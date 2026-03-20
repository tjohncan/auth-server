function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Parse ?return= parameter from URL (validated to prevent open redirect)
function getReturnUrl() {
    const params = new URLSearchParams(window.location.search);
    const url = params.get('return') || '/admin';
    // Only allow relative paths — block protocol-relative and backslash-relative URLs
    if (url.startsWith('/') && !url.startsWith('//') && !url.startsWith('/\\')) return url;
    return '/admin';
}

/* Carry authorize context to passwordless login link */
(function updatePasswordlessLink() {
    const link = document.getElementById('passwordlessLink');
    if (!link) return;
    const returnUrl = getReturnUrl();
    if (returnUrl && returnUrl.startsWith('/authorize?')) {
        const qs = returnUrl.substring('/authorize?'.length);
        link.href = '/request-passwordless-login?return_to=' + encodeURIComponent(qs);
    }
})();

/* Check if redirected here for MFA challenge (mfa_step=1) */
(async function checkMfaStep() {
    const params = new URLSearchParams(window.location.search);
    if (params.get('mfa_step') !== '1') return;

    try {
        const res = await fetch('/api/user/mfa/methods');
        if (!res.ok) return; /* No valid session - show normal login */

        const data = await res.json();
        const confirmed = (data.methods || []).filter(m => m.is_confirmed);
        if (confirmed.length === 0) return; /* No confirmed methods - show normal login */

        /* Remap fields to match what showMfaStep expects (type, not mfa_method) */
        const methods = confirmed.map(m => ({
            id: m.id,
            type: m.type,
            display_name: m.display_name
        }));

        showMfaStep(methods);
    } catch (e) {
        /* Fetch failed - fall through to normal login */
    }
})();

document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const idEl = document.getElementById('id');
    if (!idEl) return; /* MFA step has replaced the form */
    const username = idEl.value;
    const password = document.getElementById('password').value;
    const messageEl = document.getElementById('message');
    const submitBtn = e.target.querySelector('button[type="submit"]');

    submitBtn.disabled = true;

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            if (data.mfa_required && data.mfa_methods && data.mfa_methods.length > 0) {
                showMfaStep(data.mfa_methods);
            } else {
                window.location.href = getReturnUrl();
            }
        } else {
            submitBtn.disabled = false;
            messageEl.textContent = 'Error: ' + (data.error || 'Login failed');
        }
    } catch (err) {
        submitBtn.disabled = false;
        messageEl.textContent = 'Error: ' + err.message;
    }
});

function showMfaStep(methods) {
    const form = document.getElementById('loginForm');
    const messageEl = document.getElementById('message');
    messageEl.textContent = '';

    let useRecoveryCode = false;

    function renderMfaForm() {
        /* Build method options (auto-select if only one) */
        let methodSelect = '';
        if (!useRecoveryCode && methods.length > 1) {
            methodSelect = '<div class="form-field"><label for="mfaMethod">Method</label>'
                + '<select id="mfaMethod">';
            for (const m of methods) {
                methodSelect += `<option value="${escapeHtml(m.id)}">${escapeHtml(m.display_name)} (${escapeHtml(m.type)})</option>`;
            }
            methodSelect += '</select></div>';
        }

        const toggleText = useRecoveryCode ? 'Use authenticator code instead' : 'Use recovery code instead';

        let codeInput;
        if (useRecoveryCode) {
            /* Recovery code: masked input showing last 4 chars when length > 16 */
            codeInput = `
                <div class="form-field">
                    <label for="recoveryCode">Recovery Code</label>
                    <input type="text" id="recoveryCode" name="recoveryCode" placeholder="20-character recovery code"
                           maxlength="20" inputmode="text" autocomplete="off"
                           class="recovery-input" required>
                </div>
            `;
        } else {
            /* TOTP: 6 digit boxes */
            codeInput = `
                <div class="form-field">
                    <label class="text-center">Authenticator Code</label>
                    <div class="totp-container">
                        <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="0" required>
                        <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="1" required>
                        <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="2" required>
                        <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="3" required>
                        <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="4" required>
                        <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="5" required>
                    </div>
                </div>
            `;
        }

        form.innerHTML = `
            <p class="mfa-prompt text-center">Enter your ${useRecoveryCode ? 'recovery code' : 'authenticator code'} to continue.</p>
            ${methodSelect}
            ${codeInput}
            <button type="submit" class="btn-blue">Verify</button>
            <div class="help-text">
                <a href="#" id="toggleMfaMode">${toggleText}</a>
            </div>
        `;

        document.getElementById('toggleMfaMode').addEventListener('click', (e) => {
            e.preventDefault();
            useRecoveryCode = !useRecoveryCode;
            messageEl.textContent = '';
            renderMfaForm();
        });

        /* Setup TOTP digit input handlers if not using recovery code */
        if (!useRecoveryCode) {
            setupDigitInputs(document.querySelectorAll('.totp-digit'));
        } else {
            /* Setup recovery code input with custom masking */
            const recoveryInput = document.getElementById('recoveryCode');
            let realValue = '';

            const updateDisplay = (cursorPos) => {
                let maskedDisplay;
                if (realValue.length <= 16) {
                    maskedDisplay = '\u2022'.repeat(realValue.length);
                } else {
                    maskedDisplay = '\u2022'.repeat(16) + realValue.slice(16);
                }
                recoveryInput.value = maskedDisplay;
                recoveryInput.setSelectionRange(cursorPos, cursorPos);
            };

            recoveryInput.addEventListener('beforeinput', (e) => {
                e.preventDefault();
                const start = e.target.selectionStart;
                const end = e.target.selectionEnd;

                if (e.inputType === 'insertText' || e.inputType === 'insertFromPaste') {
                    const text = e.data || (e.dataTransfer && e.dataTransfer.getData('text/plain')) || '';
                    if (realValue.length + text.length - (end - start) <= 20) {
                        realValue = realValue.slice(0, start) + text + realValue.slice(end);
                        updateDisplay(start + text.length);
                    }
                } else if (e.inputType === 'deleteContentBackward') {
                    if (start === end && start > 0) {
                        realValue = realValue.slice(0, start - 1) + realValue.slice(start);
                        updateDisplay(start - 1);
                    } else if (start !== end) {
                        realValue = realValue.slice(0, start) + realValue.slice(end);
                        updateDisplay(start);
                    }
                } else if (e.inputType === 'deleteContentForward') {
                    if (start === end && start < realValue.length) {
                        realValue = realValue.slice(0, start) + realValue.slice(start + 1);
                        updateDisplay(start);
                    } else if (start !== end) {
                        realValue = realValue.slice(0, start) + realValue.slice(end);
                        updateDisplay(start);
                    }
                }
            });

            /* Store real value accessor for form submission */
            recoveryInput.getRealValue = () => realValue;

            recoveryInput.focus();
        }
    }

    renderMfaForm();

    const defaultMethodId = methods[0].id;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        /* Collect code from inputs */
        let code;
        if (useRecoveryCode) {
            const recoveryInput = document.getElementById('recoveryCode');
            code = recoveryInput.getRealValue ? recoveryInput.getRealValue() : recoveryInput.value.trim();
        } else {
            /* Collect from 6 digit boxes */
            const digitInputs = document.querySelectorAll('.totp-digit');
            code = Array.from(digitInputs).map(input => input.value).join('');
        }

        /* Validate code length */
        if (useRecoveryCode && code.length !== 20) {
            messageEl.textContent = 'Recovery code must be 20 characters.';
            return;
        }
        if (!useRecoveryCode && code.length !== 6) {
            messageEl.textContent = 'Please enter all 6 digits.';
            return;
        }

        const submitBtn = e.target.querySelector('button[type="submit"]');
        submitBtn.disabled = true;

        try {
            let res, data;
            if (useRecoveryCode) {
                res = await fetch('/api/user/mfa/recover', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ recovery_code: code })
                });
                data = await res.json();
            } else {
                const methodId = methods.length > 1
                    ? document.getElementById('mfaMethod').value
                    : defaultMethodId;
                res = await fetch('/api/user/mfa/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ method_id: methodId, code })
                });
                data = await res.json();
            }

            if (res.ok && data.valid) {
                window.location.href = getReturnUrl();
            } else {
                submitBtn.disabled = false;
                messageEl.textContent = data.error || 'Invalid code, please try again.';
            }
        } catch (err) {
            submitBtn.disabled = false;
            messageEl.textContent = 'Error: ' + err.message;
        }
    });
}

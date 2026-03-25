/* Track current MFA setup modal */
let currentMFASetupClose = null;

// ===== MFA Helpers =====

function attachMFAConfirmHandler(formId, methodId, closeModal) {
    document.getElementById(formId).addEventListener('submit', async (e) => {
        e.preventDefault();
        const submitBtn = e.target.querySelector('button[type="submit"]');
        submitBtn.disabled = true;

        const digitInputs = e.target.querySelectorAll('.totp-digit');
        const code = Array.from(digitInputs).map(input => input.value).join('');

        if (code.length !== 6) {
            submitBtn.disabled = false;
            showAlert('Please enter all 6 digits.');
            return;
        }

        try {
            const data = await apiPost('/user/mfa/totp/confirm', { method_id: methodId, code });
            closeModal();
            if (data.recovery_codes) {
                showMFARecoveryCodes(data.recovery_codes, 'MFA Enabled \u2014 Save Your Recovery Codes');
            } else {
                const profile = await loadProfile();
                if (profile) renderSecuritySection(profile);
            }
        } catch (error) {
            submitBtn.disabled = false;
            showAlert('Failed to confirm MFA: ' + error.message);
        }
    });
}

// ===== Profile =====

let cachedProfile = null;
let cachedHasVerifiedEmail = false;

async function loadProfile() {
    try {
        const response = await fetch(`${API_URL}/user/profile`, { credentials: 'include' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const profile = await response.json();
        const username = profile.username || '(not set)';
        const formattedUserId = formatUUID(profile.user_id);

        const profileContent = document.getElementById('profileContent');
        profileContent.innerHTML = `
            <p class="flex-between">
                <span><strong>Username:</strong> ${escapeHtml(username)}</span>
                <button data-action="show-change-username" class="btn-link">Change Username</button>
            </p>
            <p class="flex-center">
                <span><strong>User ID:</strong></span>
                <code class="text-sm ml-sm">${escapeHtml(formattedUserId)}</code>
                <span id="userIdCopyBtn"></span>
            </p>
        `;

        document.getElementById('userIdCopyBtn').appendChild(createCopyButton(formattedUserId));
        renderSecuritySection(profile);

        return profile;
    } catch (error) {
        console.error('Failed to load profile:', error);
        document.getElementById('profileContent').innerHTML = `
            <p class="text-error">Error loading profile: ${escapeHtml(error.message)}</p>
        `;
        return null;
    }
}

function renderSecuritySection(profile) {
    cachedProfile = profile;

    const mfaStatus = profile.has_mfa ? 'Enrolled' : 'Not enrolled';
    const mfaColor = profile.has_mfa ? '#28a745' : '#999';
    const requireStatus = profile.require_mfa ? 'Required' : 'Not required';
    const requireColor = profile.require_mfa ? '#ffc107' : '#999';

    let toggleButton = '';
    if (profile.has_mfa) {
        const toggleText = profile.require_mfa ? 'Disable MFA Requirement' : 'Enable MFA Requirement';
        const toggleColor = profile.require_mfa ? '#555f55' : '#1e7a3a';
        toggleButton = `
            <button data-action="toggle-mfa-require" class="btn-toggle">${toggleText}</button>
        `;
    }

    let passwordlessBox = '';
    if (cachedHasVerifiedEmail) {
        const plStatus = profile.allow_passwordless_login ? 'Allowed' : 'Not allowed';
        const plColor = profile.allow_passwordless_login ? '#28a745' : '#999';
        const plToggleText = profile.allow_passwordless_login ? 'Disable Passwordless Access' : 'Allow Passwordless Access';
        const plToggleColor = profile.allow_passwordless_login ? '#555f55' : '#1e7a3a';
        passwordlessBox = `
            <div class="settings-panel">
                <div><strong>Passwordless Access:</strong> <span id="plStatusText">${plStatus}</span></div>
                <button data-action="toggle-passwordless" class="btn-toggle" id="plToggleBtn">${plToggleText}</button>
            </div>
        `;
    }

    document.getElementById('securityContent').innerHTML = `
        <div class="settings-panel-spaced">
            <div class="mb-xs"><strong>Multi-Factor Authentication:</strong> <span id="mfaStatusText">${mfaStatus}</span></div>
            <div><strong>MFA Enforcement:</strong> <span id="requireStatusText">${requireStatus}</span></div>
            ${toggleButton}
        </div>
        <button data-action="show-change-password">Change Password</button>
        <button data-action="show-mfa-setup" class="ml-md">Configure MFA</button>
        ${passwordlessBox}
    `;

    document.getElementById('mfaStatusText').style.color = mfaColor;
    document.getElementById('requireStatusText').style.color = requireColor;

    /* Set dynamic colors via CSSOM (inline style attributes blocked by CSP) */
    if (profile.has_mfa) {
        const toggleBtn = document.querySelector('[data-action="toggle-mfa-require"]');
        if (toggleBtn) toggleBtn.style.background = profile.require_mfa ? '#555f55' : '#1e7a3a';
    }
    if (cachedHasVerifiedEmail) {
        const plStatusEl = document.getElementById('plStatusText');
        if (plStatusEl) plStatusEl.style.color = profile.allow_passwordless_login ? '#28a745' : '#999';
        const plToggleBtn = document.getElementById('plToggleBtn');
        if (plToggleBtn) plToggleBtn.style.background = profile.allow_passwordless_login ? '#555f55' : '#1e7a3a';
    }
}

// ===== OpenID Connect =====

async function fetchUserInfo() {
    const el = document.getElementById('userinfoResult');
    if (!oauthClient) {
        el.style.display = 'block';
        el.innerHTML = '<p class="text-error">OAuth client not initialized</p>';
        return;
    }
    el.style.display = 'block';
    el.innerHTML = '<p>Fetching...</p>';
    try {
        const response = await oauthClient.fetchWithToken(`${HOST}/userinfo`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const info = await response.json();
        const ts = info.server_time ? new Date(info.server_time * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, '') : 'N/A';
        el.innerHTML = `
            <div class="userinfo-panel">
                <div><strong>sub:</strong> <code>${escapeHtml(formatUUID(info.sub || ''))}</code></div>
                ${info.preferred_username ? `<div><strong>preferred_username:</strong> ${escapeHtml(info.preferred_username)}</div>` : ''}
                ${info.email ? `<div><strong>email:</strong> ${escapeHtml(info.email)}</div>` : ''}
                ${info.email !== undefined ? `<div><strong>email_verified:</strong> ${info.email_verified}</div>` : ''}
                <div><strong>server_time:</strong> ${escapeHtml(ts)}</div>
            </div>
        `;
    } catch (error) {
        el.innerHTML = `<p class="text-error">Error: ${escapeHtml(error.message)}</p>`;
    }
    document.getElementById('oidcHeading')?.scrollIntoView({ behavior: 'instant' });
}

// ===== Email Management =====

async function loadEmails() {
    if (!document.getElementById('emailsContent')) return;
    try {
        const response = await fetch(`${API_URL}/user/emails`, { credentials: 'include' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();
        const container = document.getElementById('emailsContent');

        if (data.emails.length === 0) {
            container.innerHTML = `
                <p class="text-muted text-italic">No email addresses configured.</p>
                <button data-action="add-email" class="btn-blue">+ Add Email Address</button>
            `;
        } else {
            let html = '';
            data.emails.forEach(email => {
                const primaryBadge = email.is_primary
                    ? '<span class="badge-primary">&#9733; Primary</span>'
                    : '';
                const verifiedBadge = email.is_verified
                    ? '<span class="badge-active-sm">&#9679; Verified</span>'
                    : '<span class="text-muted text-sm nowrap">&#9675; Unverified</span>';

                let buttons = '';
                if (!email.is_verified) {
                    buttons += `<button data-action="verify-email" data-email="${escapeHtml(email.email_address)}"
                                        class="btn-green btn-sm mr-sm">Verify</button>`;
                }
                if (email.is_primary) {
                    buttons += `<button data-action="unset-primary-email"
                                        class="btn-muted btn-sm mr-sm">Unset Primary</button>`;
                } else {
                    buttons += `<button data-action="set-primary-email" data-email="${escapeHtml(email.email_address)}"
                                        class="btn-gray btn-sm mr-sm">Set Primary</button>`;
                }
                buttons += `<button data-action="delete-email" data-email="${escapeHtml(email.email_address)}"
                                    class="btn-red btn-sm">Delete</button>`;

                html += `
                    <div class="list-item">
                        <div class="flex-between email-actions">
                            <div>
                                <strong>${escapeHtml(email.email_address)}</strong>${primaryBadge}
                                <span class="ml-md">${verifiedBadge}</span>
                            </div>
                            <div class="nowrap">
                                ${buttons}
                            </div>
                        </div>
                    </div>
                `;
            });

            html += '<button data-action="add-email" class="mt-xs">+ Add Email Address</button>';
            container.innerHTML = html;
        }

        const hadVerified = cachedHasVerifiedEmail;
        cachedHasVerifiedEmail = data.emails.some(e => e.is_verified);
        if (cachedHasVerifiedEmail !== hadVerified && cachedProfile) {
            renderSecuritySection(cachedProfile);
        }
    } catch (error) {
        console.error('Failed to load emails:', error);
        document.getElementById('emailsContent').innerHTML = `
            <p class="text-error">Error loading emails: ${escapeHtml(error.message)}</p>
        `;
    }
}

function addEmail() {
    const { modal, close } = showModal('Add Email Address', `
        <form id="addEmailForm">
            ${formField('Email Address', 'email', '', 'email', true)}
            <div class="modal-actions">
                <button type="submit" class="btn-blue btn-modal">Add</button>
                <button type="button" data-action="close-modal" class="btn-gray btn-modal">Cancel</button>
            </div>
        </form>
    `);

    document.getElementById('addEmailForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = new FormData(e.target).get('email').trim();
        if (!email) { showAlert('Email address is required'); return; }
        try {
            await apiPost('/user/emails', { email });
            close();
            loadEmails();
        } catch (error) {
            showAlert('Failed to add email: ' + error.message);
        }
    });
}

async function deleteEmail(email) {
    if (!(await showConfirm(`Delete email address: ${email}?`))) return;
    try {
        const response = await fetch(`${API_URL}/user/emails`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ email })
        });
        if (!response.ok) {
            const error = await response.json().catch(() => ({ error: 'Unknown error' }));
            throw new Error(error.error || `HTTP ${response.status}`);
        }
        loadEmails();
    } catch (error) {
        showAlert('Failed to delete email: ' + error.message);
    }
}

async function setPrimaryEmail(email) {
    try { await apiPost('/user/emails/set-primary', { email }); loadEmails(); }
    catch (error) { showAlert('Failed to set primary email: ' + error.message); }
}

async function unsetPrimaryEmail() {
    try { await apiPost('/user/emails/set-primary', { email: null }); loadEmails(); }
    catch (error) { showAlert('Failed to unset primary email: ' + error.message); }
}

async function requestEmailVerification(email) {
    const btn = document.querySelector(`[data-action="verify-email"][data-email="${CSS.escape(email)}"]`);
    if (btn) { btn.disabled = true; btn.style.opacity = '0.5'; }
    try {
        const response = await fetch(`${HOST}/email-verification-token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ email })
        });
        if (!response.ok) {
            const error = await response.json().catch(() => ({ error: 'Unknown error' }));
            throw new Error(error.error || `HTTP ${response.status}`);
        }
        showModal('Verification Email Sent', `
            <p>A verification email has been sent to <strong>${escapeHtml(email)}</strong>.</p>
            <p class="mt-md">Check your inbox and click the verification link.</p>
            <div class="mt-lg">
                <button type="button" data-action="close-modal" class="btn-gray btn-modal">Close</button>
            </div>
        `);
    } catch (error) {
        showAlert('Failed to send verification email: ' + error.message);
        if (btn) { btn.disabled = false; btn.style.opacity = ''; }
    }
}

// ===== Username & Password =====

function showChangeUsername() {
    const { modal, close } = showModal('Change Username', `
        <form id="changeUsernameForm">
            ${formField('New Username', 'new_username', '', 'text', true)}
            <div class="modal-actions">
                <button type="submit" class="btn-green btn-modal">Change Username</button>
                <button type="button" data-action="close-modal" class="btn-gray btn-modal">Cancel</button>
            </div>
        </form>
    `);

    document.getElementById('changeUsernameForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const newUsername = new FormData(e.target).get('new_username').trim();
        if (!newUsername) { showAlert('Username cannot be empty'); return; }
        close();
        changeUsername(newUsername);
    });
}

async function changeUsername(newUsername) {
    try {
        const response = await fetch(`${API_URL}/user/username`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ new_username: newUsername })
        });
        if (response.ok) { showAlert('Username changed successfully!'); loadProfile(); }
        else { const error = await response.json(); showAlert(`Failed to change username: ${error.error || 'Unknown error'}`); }
    } catch (error) {
        console.error('Failed to change username:', error);
        showAlert(`Error: ${error.message}`);
    }
}

function showChangePassword() {
    const { modal, close } = showModal('Change Password', `
        <form id="changePasswordForm">
            ${formField('Current Password', 'current_password', '', 'password', true)}
            ${formField('New Password', 'new_password', '', 'password', true)}
            ${formField('Confirm New Password', 'confirm_password', '', 'password', true)}
            <div class="modal-actions">
                <button type="submit" class="btn-green btn-modal">Change Password</button>
                <button type="button" data-action="close-modal" class="btn-gray btn-modal">Cancel</button>
            </div>
        </form>
    `);

    document.getElementById('changePasswordForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        if (formData.get('new_password') !== formData.get('confirm_password')) {
            showAlert('New passwords do not match!');
            return;
        }
        close();
        changePassword(formData.get('current_password'), formData.get('new_password'));
    });
}

async function changePassword(currentPassword, newPassword) {
    try {
        const response = await fetch(`${API_URL}/user/password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ current_password: currentPassword, new_password: newPassword })
        });
        if (response.ok) { showAlert('Password changed successfully!'); }
        else { const error = await response.json(); showAlert(`Failed to change password: ${error.error || 'Unknown error'}`); }
    } catch (error) {
        console.error('Failed to change password:', error);
        showAlert(`Error: ${error.message}`);
    }
}

// ===== MFA Management =====

async function showMFASetup() {
    const { modal, close } = showModal('Multi-Factor Authentication', '<div id="mfaContent"><p class="text-muted">Loading...</p></div>');
    currentMFASetupClose = () => { close(); currentMFASetupClose = null; };
    try {
        const data = await apiGet('/user/mfa/methods');
        renderMFAContent(data.methods);
    } catch (error) {
        document.getElementById('mfaContent').innerHTML =
            `<p class="text-error">Failed to load MFA methods: ${escapeHtml(error.message)}</p>`;
    }
}

function renderMFAContent(methods) {
    const content = document.getElementById('mfaContent');
    if (!content) return;

    let html = '';

    if (methods.length === 0) {
        html += '<p class="text-muted text-italic">No authentication methods enrolled.</p>';
    } else {
        methods.forEach(m => {
            const statusColor = m.is_confirmed ? '#28a745' : '#ffc107';
            const statusText = m.is_confirmed ? 'Active' : 'Pending confirmation';
            const buttons = m.is_confirmed
                ? `<button data-action="mfa-delete-method" data-id="${escapeHtml(m.id)}" class="btn-red btn-sm">Remove</button>`
                : `<span class="flex-row">
                       <button data-action="mfa-resume-confirm" data-id="${escapeHtml(m.id)}" class="btn-green btn-sm">Confirm</button>
                       <button data-action="mfa-delete-method" data-id="${escapeHtml(m.id)}" class="btn-red btn-sm">Remove</button>
                   </span>`;
            html += `
                <div class="list-item flex-between">
                    <div>
                        <strong>${escapeHtml(m.display_name)}</strong>
                        <span class="text-muted text-sm ml-sm">${escapeHtml(m.type)}</span>
                        <div class="text-sm mt-xs" data-status-color="${statusColor}">${statusText}</div>
                    </div>
                    ${buttons}
                </div>
            `;
        });

        const hasConfirmed = methods.some(m => m.is_confirmed);
        if (hasConfirmed) {
            html += `
                <div class="section-divider">
                    <strong>Recovery Codes</strong>
                    <p class="text-muted text-sm">Single-use backup codes for when you lose access to your authenticator.</p>
                    <button data-action="mfa-regenerate-codes" class="btn-gray btn-sm">Regenerate Recovery Codes</button>
                </div>
            `;
        }
    }

    html += `
        <div class="section-divider-flex">
            <button data-action="mfa-add-device" class="btn-blue btn-lg">+ Add Authenticator App</button>
            <button data-action="close-modal" class="btn-gray btn-lg">Close</button>
        </div>
    `;

    content.innerHTML = html;

    /* Apply dynamic colors via CSSOM */
    content.querySelectorAll('[data-status-color]').forEach(el => {
        el.style.color = el.dataset.statusColor;
    });
}

async function showMFAAddDevice() {
    if (currentMFASetupClose) { currentMFASetupClose(); currentMFASetupClose = null; }

    try { await ensureQRCodeLoaded(); }
    catch (error) { showAlert('Failed to load QR code library: ' + error.message); return; }

    const { modal, close } = showModal('Add Authenticator App', `
        <form id="mfaSetupForm">
            ${formField('Device Name', 'display_name', '', 'text', true, false, 200)}
            <p class="text-muted text-sm">A recognizable name, e.g. "Auth App" or "Work Phone".</p>
            <div class="modal-actions">
                <button type="submit" class="btn-blue btn-modal nowrap">Next</button>
                <button type="button" data-action="close-modal" class="btn-gray btn-modal">Cancel</button>
            </div>
        </form>
    `);

    document.getElementById('mfaSetupForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const displayName = new FormData(e.target).get('display_name');
        close();
        try {
            const data = await apiPost('/user/mfa/totp/setup', { display_name: displayName });
            showMFAConfirm(data.method_id, data.secret, data.qr_url);
        } catch (error) {
            showAlert('Failed to start MFA setup: ' + error.message);
        }
    });
}

function showMFAConfirm(methodId, secret, qrUrl) {
    const { modal, close } = showModal('Scan QR Code', `
        <p class="text-md mb-md">Open your authenticator app and scan the QR code below.</p>
        <div class="text-center mb-md">
            <div id="qrCodeContainer" class="qr-container"></div>
            <div class="mt-md">
                <button type="button" id="invertQRButton" class="btn-subtle btn-sm">Invert Colors</button>
            </div>
        </div>
        <details class="mb-lg">
            <summary class="details-toggle">Show manual entry secret</summary>
            <code class="secret-display">${escapeHtml(secret)}</code>
        </details>
        <form id="mfaConfirmForm">
            <label class="form-label text-center">Enter 6-digit code from app</label>
            <div class="totp-container">
                <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="0" required>
                <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="1" required>
                <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="2" required>
                <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="3" required>
                <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="4" required>
                <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="5" required>
            </div>
            <div class="modal-actions">
                <button type="submit" class="btn-green btn-modal">Confirm</button>
                <button type="button" data-action="close-modal" class="btn-gray btn-modal">Cancel</button>
            </div>
        </form>
    `);

    QRCode.render(qrUrl, document.getElementById('qrCodeContainer'), {
        size: 240, padding: 2, darkColor: '#ffffff', lightColor: '#2a2a2a', ecLevel: 'H'
    });

    document.getElementById('invertQRButton').addEventListener('click', function() {
        const svg = document.querySelector('#qrCodeContainer svg');
        const bg = svg.querySelector('rect');
        const path = svg.querySelector('path');
        const tmp = bg.getAttribute('fill');
        bg.setAttribute('fill', path.getAttribute('fill'));
        path.setAttribute('fill', tmp);
    });

    setupDigitInputs(document.querySelectorAll('#mfaConfirmForm .totp-digit'));
    attachMFAConfirmHandler('mfaConfirmForm', methodId, close);
}

function showMFAResumeConfirm(methodId) {
    const { modal, close } = showModal('Complete MFA Setup', `
        <p class="text-md mb-lg">Enter the 6-digit code from your authenticator app to finish registration.</p>
        <form id="mfaResumeConfirmForm">
            <label class="form-label text-center">Enter 6-digit code from app</label>
            <div class="totp-container">
                <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="0" required>
                <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="1" required>
                <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="2" required>
                <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="3" required>
                <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="4" required>
                <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" data-index="5" required>
            </div>
            <div class="modal-actions">
                <button type="submit" class="btn-green btn-modal">Confirm</button>
                <button type="button" data-action="close-modal" class="btn-gray btn-modal">Cancel</button>
            </div>
        </form>
    `);

    setupDigitInputs(document.querySelectorAll('#mfaResumeConfirmForm .totp-digit'));
    attachMFAConfirmHandler('mfaResumeConfirmForm', methodId, close);
}

function showMFARecoveryCodes(codes, title) {
    const codeList = codes.map(c =>
        `<div class="recovery-code">${escapeHtml(c)}</div>`
    ).join('');
    const { modal, close } = showModal(title || 'Recovery Codes', `
        <p class="text-warning mb-md">Save these codes now. Each code works once and cannot be retrieved again.</p>
        <div class="settings-panel mb-lg">
            ${codeList}
        </div>
        <div class="flex-row">
            <button type="button" id="copyCodesBtn" class="btn-blue btn-modal nowrap">Copy All</button>
            <button type="button" id="doneBtn" class="btn-green btn-modal">Done</button>
        </div>
    `);

    document.getElementById('copyCodesBtn').addEventListener('click', () => {
        navigator.clipboard.writeText(codes.join('\n')).then(() => {
            document.getElementById('copyCodesBtn').textContent = 'Copied!';
            setTimeout(() => { document.getElementById('copyCodesBtn').textContent = 'Copy All'; }, 2000);
        }).catch(() => {
            document.getElementById('copyCodesBtn').textContent = 'Failed.';
            setTimeout(() => { document.getElementById('copyCodesBtn').textContent = 'Copy All'; }, 2000);
        });
    });

    document.getElementById('doneBtn').addEventListener('click', async () => {
        close();
        const profile = await loadProfile();
        if (profile) renderSecuritySection(profile);
    });
}

async function mfaDeleteMethod(methodId) {
    let confirmMessage = 'Remove this MFA method? You will need to re-enroll to use it again.';
    try {
        const currentData = await apiGet('/user/mfa/methods');
        const confirmedMethods = currentData.methods.filter(m => m.is_confirmed);
        if (confirmedMethods.length === 1) {
            confirmMessage = 'Remove this MFA method? This is your last method, so your recovery codes will also be deleted. You will need to re-enroll to use MFA again.';
        }
    } catch (error) { console.error('Failed to check method count:', error); }

    if (!(await showConfirm(confirmMessage))) return;

    try {
        await apiDelete(`/user/mfa/methods?id=${methodId}`);
        const data = await apiGet('/user/mfa/methods');
        renderMFAContent(data.methods);
        const profile = await loadProfile();
        if (profile) renderSecuritySection(profile);
    } catch (error) {
        showAlert('Failed to remove MFA method: ' + error.message);
    }
}

async function mfaRegenerateCodes() {
    if (!(await showConfirm('Regenerate recovery codes? Your existing codes will be invalidated immediately.'))) return;
    try {
        const data = await apiPost('/user/mfa/recovery-codes/regenerate', {});
        showMFARecoveryCodes(data.recovery_codes, 'New Recovery Codes');
    } catch (error) {
        showAlert('Failed to regenerate recovery codes: ' + error.message);
    }
}

async function toggleMfaRequire() {
    try {
        const newState = !cachedProfile.require_mfa;
        const action = newState ? 'enable' : 'disable';
        if (!(await showConfirm(`Are you sure you want to ${action} MFA enforcement for yourself?`))) return;

        await apiPost('/user/mfa/require', { enabled: newState });
        await loadProfile();
    } catch (error) {
        showAlert('Failed to update MFA requirement: ' + error.message);
    }
}

async function togglePasswordless() {
    try {
        const newState = !cachedProfile.allow_passwordless_login;
        const action = newState ? 'enable' : 'disable';
        if (!(await showConfirm(`Are you sure you want to ${action} passwordless access?`))) return;

        await apiPost('/user/passwordless-login', { enabled: newState });
        await loadProfile();
    } catch (error) {
        showAlert('Failed to update passwordless access: ' + error.message);
    }
}

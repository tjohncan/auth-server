const HOST = window.location.origin;
const CALLBACK_URL = `${HOST}/callback`;
const API_URL = `${HOST}/api`;

/* OAuthClient instance (set during init) */
let oauthClient = null;

// ===== Utility Functions =====

function getClientId() {
    const params = new URLSearchParams(window.location.search);
    return params.get('client_id');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function createOAuthClient(clientId) {
    return new OAuthClient({
        authUrl: HOST,
        clientId: clientId,
        redirectUri: CALLBACK_URL,
        scope: 'openid'
    });
}

/* Normalize UUID by stripping hyphens and validating */
function normalizeUUID(uuid) {
    if (!uuid) return null;
    const stripped = uuid.replace(/-/g, '');
    if (!/^[0-9a-fA-F]{32}$/.test(stripped)) return null;
    return stripped.toLowerCase();
}

/* Format UUID with hyphens (8-4-4-4-12) */
function formatUUID(hex) {
    if (!hex || hex.length !== 32) return hex;
    return hex.slice(0,8) + '-' + hex.slice(8,12) + '-' +
           hex.slice(12,16) + '-' + hex.slice(16,20) + '-' + hex.slice(20);
}

/* Create a copy button with feedback animation */
function createCopyButton(textToCopy) {
    const btn = document.createElement('button');
    btn.textContent = 'copy';
    btn.className = 'copy-inline';

    btn.onclick = function() {
        if (btn.disabled) return;
        navigator.clipboard.writeText(textToCopy).then(() => {
            btn.textContent = '\u2713 copied!';
            btn.classList.add('copied');
            btn.disabled = true;
            setTimeout(() => {
                btn.textContent = 'copy';
                btn.classList.remove('copied');
                btn.disabled = false;
            }, 3000);
        }).catch(err => {
            console.error('Copy failed:', err);
            showAlert('Failed to copy to clipboard');
        });
    };

    return btn;
}

/* Lazy load QR code library only when needed for MFA enrollment */
function ensureQRCodeLoaded() {
    return new Promise((resolve, reject) => {
        if (window.QRCode) { resolve(); return; }
        const script = document.createElement('script');
        script.src = '/js/qrcode.js';
        script.onload = () => resolve();
        script.onerror = () => reject(new Error('Failed to load QR code library'));
        document.head.appendChild(script);
    });
}

// ===== API Helpers =====

async function apiGet(endpoint) {
    const response = await fetch(`${API_URL}${endpoint}`, { credentials: 'include' });
    if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(error.error || `HTTP ${response.status}`);
    }
    return response.json();
}

async function apiPost(endpoint, data) {
    const response = await fetch(`${API_URL}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(data)
    });
    if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(error.error || `HTTP ${response.status}`);
    }
    return response.json();
}

async function apiPut(endpoint, data) {
    const response = await fetch(`${API_URL}${endpoint}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(data)
    });
    if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(error.error || `HTTP ${response.status}`);
    }
    return response.json();
}

async function apiDelete(endpoint) {
    const response = await fetch(`${API_URL}${endpoint}`, {
        method: 'DELETE',
        credentials: 'include'
    });
    if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(error.error || `HTTP ${response.status}`);
    }
    return response.json();
}

// ===== UI Helpers =====

function showModal(title, content) {
    const modal = document.createElement('div');
    modal.className = 'modal modal-overlay';

    const box = document.createElement('div');
    box.className = 'modal-box';

    const titleHtml = title ? `<h3 class="no-margin">${escapeHtml(title)}</h3>` : '';
    box.innerHTML = `${titleHtml}${content}`;

    modal.appendChild(box);
    document.body.appendChild(modal);

    let closeCallback = null;

    const close = () => {
        if (modal.parentNode) {
            document.removeEventListener('keydown', onKeydown);
            modal.remove();
            if (closeCallback) closeCallback();
        }
    };

    modal._close = close;

    const onKeydown = (e) => {
        if (e.key === 'Escape') {
            const modals = document.querySelectorAll('.modal');
            if (modals.length && modals[modals.length - 1] === modal) {
                e.preventDefault();
                close();
            }
        }
    };
    document.addEventListener('keydown', onKeydown);

    requestAnimationFrame(() => {
        const el = box.querySelector('input:not([type="hidden"]):not([readonly]), textarea, select, button');
        if (el) el.focus();
        else { box.tabIndex = -1; box.focus(); }
    });

    return {
        modal,
        close,
        onClose: (cb) => { closeCallback = cb; }
    };
}

function showAlert(message) {
    return new Promise(resolve => {
        const { modal, close, onClose } = showModal('', `
            <p class="modal-message">${escapeHtml(message)}</p>
            <div class="modal-actions-end">
                <button class="btn-blue btn-xl">OK</button>
            </div>
        `);
        onClose(resolve);
        modal.querySelector('button').addEventListener('click', close);
    });
}

function showConfirm(message) {
    return new Promise(resolve => {
        const { modal, close, onClose } = showModal('', `
            <p class="modal-message">${escapeHtml(message)}</p>
            <div class="modal-actions-end">
                <button class="confirm-yes btn-red btn-modal">Confirm</button>
                <button class="confirm-no btn-gray btn-modal">Cancel</button>
            </div>
        `);
        let confirmed = false;
        onClose(() => resolve(confirmed));
        modal.querySelector('.confirm-yes').addEventListener('click', () => { confirmed = true; close(); });
        modal.querySelector('.confirm-no').addEventListener('click', close);
    });
}

// ===== Form Builders =====

function formField(label, name, value = '', type = 'text', required = false, readonly = false, maxlength = 0) {
    const req = required ? ' <span class="text-error">*</span>' : '';
    const ro = readonly ? ' readonly' : '';
    const rq = required ? ' required' : '';
    const ml = maxlength > 0 ? ` maxlength="${maxlength}"` : '';
    return `
        <div class="mb-md">
            <label class="form-label">${escapeHtml(label)}${req}</label>
            <input type="${type}" name="${name}" value="${escapeHtml(value)}"
                   class="form-input"${ro}${rq}${ml}>
        </div>
    `;
}

function formTextarea(label, name, value = '', required = false, maxlength = 0) {
    const req = required ? ' <span class="text-error">*</span>' : '';
    const ml = maxlength > 0 ? ` maxlength="${maxlength}"` : '';
    return `
        <div class="mb-md">
            <label class="form-label">${escapeHtml(label)}${req}</label>
            <textarea name="${name}"
                      class="form-input"${ml}>${escapeHtml(value)}</textarea>
        </div>
    `;
}

function formCheckbox(label, name, checked = false) {
    const chk = checked ? ' checked' : '';
    return `
        <div class="mb-md">
            <label class="flex-center clickable">
                <input type="checkbox" name="${name}"${chk} class="mr-sm">
                ${escapeHtml(label)}
            </label>
        </div>
    `;
}

function formSelect(label, name, options, value = '', required = false) {
    const req = required ? ' <span class="text-error">*</span>' : '';
    const opts = options.map(opt =>
        `<option value="${escapeHtml(opt.value)}" ${opt.value === value ? 'selected' : ''}>${escapeHtml(opt.label)}</option>`
    ).join('');
    return `
        <div class="mb-md">
            <label class="form-label">${escapeHtml(label)}${req}</label>
            <select name="${name}" class="form-input">${opts}</select>
        </div>
    `;
}

function formatDuration(seconds) {
    if (seconds == null || seconds < 0) return 'Unlimited';
    const units = [[86400, 'day'], [3600, 'hour'], [60, 'minute'], [1, 'second']];
    for (const [divisor, unit] of units) {
        if (seconds >= divisor && seconds % divisor === 0) {
            const count = seconds / divisor;
            return count === 1 ? `1 ${unit}` : `${count} ${unit}s`;
        }
    }
    return `${seconds} seconds`;
}

function formDuration(label, name, value, presets, required = false) {
    const req = required ? ' <span class="text-error">*</span>' : '';
    const numValue = parseInt(value, 10) || 0;
    const isPreset = presets.some(p => p.value === numValue);
    const showCustom = !isPreset && numValue > 0;

    const opts = presets.map(p =>
        `<option value="${p.value}" ${p.value === numValue ? 'selected' : ''}>${p.label || formatDuration(p.value)}</option>`
    ).join('');

    return `
        <div class="mb-md">
            <label class="form-label">${escapeHtml(label)}${req}</label>
            <div class="flex-center">
                <select data-duration-for="${name}" class="form-input flex-fill">
                    ${opts}
                    <option value="custom" ${showCustom ? 'selected' : ''}>Custom...</option>
                </select>
                <input type="number" name="${name}" value="${numValue}"${showCustom ? ' min="1"' : ''}
                       class="form-input input-narrow${showCustom ? '' : ' hidden'}">
                <span class="text-muted text-sm${showCustom ? '' : ' hidden'}" data-duration-unit="${name}">seconds</span>
            </div>
        </div>
    `;
}

// ===== Event Delegation =====

document.addEventListener('click', function(e) {
    const target = e.target.closest('[data-action]');
    if (!target) return;

    const action = target.dataset.action;

    if (target.tagName === 'A') e.preventDefault();

    switch (action) {
        case 'logout': logout(); break;
        case 'switch-tab': switchTab(target.dataset.tab); break;
        case 'show-change-username': showChangeUsername(); break;
        case 'show-change-password': showChangePassword(); break;
        case 'show-mfa-setup': showMFASetup(); break;
        case 'mfa-add-device': showMFAAddDevice(); break;
        case 'mfa-delete-method': mfaDeleteMethod(target.dataset.id); break;
        case 'mfa-resume-confirm': showMFAResumeConfirm(target.dataset.id); break;
        case 'mfa-regenerate-codes': mfaRegenerateCodes(); break;
        case 'toggle-mfa-require': toggleMfaRequire(); break;
        case 'toggle-passwordless': togglePasswordless(); break;
        case 'add-email': addEmail(); break;
        case 'delete-email': deleteEmail(target.dataset.email); break;
        case 'set-primary-email': setPrimaryEmail(target.dataset.email); break;
        case 'unset-primary-email': unsetPrimaryEmail(); break;
        case 'verify-email': requestEmailVerification(target.dataset.email); break;
        case 'select-setup': selectSetup(target.dataset.clientId); break;
        case 'navigate-org-list': navigateToOrgList(); break;
        case 'navigate-to-org': navigateToOrg(target.dataset.id); break;
        case 'navigate-to-rs': navigateToResourceServer(target.dataset.id); break;
        case 'navigate-to-client': navigateToClient(target.dataset.id); break;
        case 'edit-organization': editOrganization(target.dataset.id); break;
        case 'edit-resource-server': editResourceServer(target.dataset.id); break;
        case 'edit-client': editClient(target.dataset.id); break;
        case 'create-resource-server': createResourceServer(target.dataset.orgId); break;
        case 'create-client': createClient(target.dataset.orgId); break;
        case 'create-rs-key': createResourceServerKey(target.dataset.rsId); break;
        case 'create-client-key': createClientKey(target.dataset.clientId); break;
        case 'revoke-rs-key': revokeResourceServerKey(target.dataset.id); break;
        case 'revoke-client-key': revokeClientKey(target.dataset.id); break;
        case 'add-redirect-uri': addRedirectURI(target.dataset.clientId); break;
        case 'delete-redirect-uri': deleteRedirectURI(target.dataset.clientId, target.dataset.uri); break;
        case 'link-client-to-rs': linkClientToRS(target.dataset.clientId); break;
        case 'link-rs-to-client': linkRSToClient(target.dataset.rsId); break;
        case 'unlink-client-from-rs': unlinkClientFromRS(target.dataset.clientId, target.dataset.rsId); break;
        case 'close-modal': { const m = target.closest('.modal'); if (m && m._close) m._close(); else if (m) m.remove(); break; }
        case 'fetch-userinfo': fetchUserInfo(); break;
    }
});

document.addEventListener('change', function(e) {
    const target = e.target.closest('[data-action]');
    if (!target) return;
    switch (target.dataset.action) {
        case 'set-org-filter':
            orgMgmt.filter = target.dataset.filter;
            renderOrgManagement('adminSection');
            break;
        case 'set-rs-filter':
            orgMgmt.rsFilter = target.dataset.filter;
            renderOrgManagement('adminSection');
            break;
        case 'set-client-filter':
            orgMgmt.clientFilter = target.dataset.filter;
            renderOrgManagement('adminSection');
            break;
    }
});

// ===== Picker =====

async function showPicker() {
    const pickerContent = document.getElementById('pickerContent');
    pickerContent.innerHTML = '<p>Loading...</p>';

    try {
        const response = await fetch(
            `/api/user/management-setups?callback_url=${encodeURIComponent(CALLBACK_URL)}&api_url=${encodeURIComponent(API_URL)}`,
            { credentials: 'include' }
        );

        if (response.status === 401) {
            window.location.replace('/login?return=' + encodeURIComponent('/admin'));
            return;
        }

        if (!response.ok) {
            document.getElementById('pickerOverlay').style.display = 'block';
            pickerContent.innerHTML = `<p>Error: HTTP ${response.status}</p>`;
            return;
        }

        const data = await response.json();

        if (!data.setups || data.setups.length === 0) {
            document.getElementById('pickerOverlay').style.display = 'block';
            pickerContent.innerHTML = '<p>No management setups found. Contact your administrator.</p>';
            return;
        }

        if (data.setups.length === 1) {
            selectSetup(data.setups[0].client_id);
            return;
        }

        document.getElementById('pickerOverlay').style.display = 'block';
        document.getElementById('dashboard').style.display = 'none';
        let html = '<h2>Select Management Client</h2>';
        html += '<p>Choose which management UI client to use for API access:</p>';
        html += '<ul class="plain-list">';

        data.setups.forEach(setup => {
            html += `
                <li class="picker-item">
                    <strong>${escapeHtml(setup.org_display_name)}</strong> <small>(${escapeHtml(setup.org_code_name)})</small><br>
                    <small>Client: ${escapeHtml(setup.client_display_name)}</small><br>
                    <button data-action="select-setup" data-client-id="${escapeHtml(setup.client_id)}" class="mt-md">Connect</button>
                </li>
            `;
        });

        html += '</ul>';
        html += '<p class="section-heading text-center"><a href="/">← Home</a></p>';
        pickerContent.innerHTML = html;

    } catch (err) {
        pickerContent.innerHTML = '<p>Error: ' + escapeHtml(err.message) + '</p>';
    }
}

function selectSetup(clientId) {
    window.location.replace(`/admin?client_id=${clientId}`);
}

// ===== Tab Management =====

let activeTab = 'profile';
let isOrgAdmin = false;

function switchTab(tab) {
    activeTab = tab;
    const profileSection = document.getElementById('profileSection');
    const adminSection = document.getElementById('adminSection');
    const profileHeading = document.getElementById('profileHeading');
    const adminHeading = document.getElementById('adminHeading');
    const tabProfile = document.getElementById('tabProfile');
    const tabAdmin = document.getElementById('tabAdmin');

    if (tab === 'profile') {
        profileSection.style.display = 'block';
        adminSection.style.display = 'none';
        profileHeading.style.display = isOrgAdmin ? 'none' : 'block';
        tabProfile.classList.add('active');
        tabAdmin.classList.remove('active');
    } else {
        profileSection.style.display = 'none';
        adminSection.style.display = 'block';
        adminHeading.style.display = 'none';
        tabAdmin.classList.add('active');
        tabProfile.classList.remove('active');
    }
}

// ===== Dashboard & Initialization =====

async function logout() {
    try {
        await fetch(`${HOST}/logout`, { method: 'POST', credentials: 'include' });
    } catch (error) {
        console.error('Logout error:', error);
    }

    const keysToRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key.startsWith('tokens_') || key.startsWith('pkce_')) {
            keysToRemove.push(key);
        }
    }
    keysToRemove.forEach(key => localStorage.removeItem(key));

    window.location.href = '/login';
}

async function showDashboard(clientId) {
    document.getElementById('pickerOverlay').style.display = 'none';
    const normalizedId = normalizeUUID(clientId);
    document.getElementById('clientInfo').textContent = normalizedId ? formatUUID(normalizedId) : clientId;

    const profile = await loadProfile();
    if (profile) {
        document.getElementById('userInfo').textContent = formatUUID(profile.user_id);
    }
    /* EMAIL_LOAD_START */ await loadEmails(); /* EMAIL_LOAD_END */
    await loadOrganizations();

    document.getElementById('dashboard').style.display = 'block';
}

async function init() {
    const clientId = getClientId();

    if (!clientId) {
        await showPicker();
        return;
    }

    const client = createOAuthClient(clientId);
    oauthClient = client;

    try {
        await client.startAutoRefresh();
    } catch (e) {
        await client.authorize();
        return;
    }

    if (client.tokensExpired()) {
        await client.authorize();
        return;
    }

    await showDashboard(clientId);
}

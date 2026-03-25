// ===== Organization Management =====

// Parse an optional integer form field (empty -> null, "0" -> 0, "-1" -> -1)
function optInt(formData, name) {
    const v = formData.get(name);
    if (v === '' || v === null) return null;
    const n = parseInt(v, 10);
    return isNaN(n) ? null : n;
}

// Navigation state
const orgMgmt = {
    view: 'org-list',
    orgId: null,
    rsId: null,
    clientId: null,
    filter: 'active',
    rsFilter: 'active',
    clientFilter: 'active',
};

/* Duration presets for seconds fields */
const DURATION_PRESETS = {
    access_token: [
        { value: 300, label: '5 minutes' },
        { value: 900, label: '15 minutes' },
        { value: 1800, label: '30 minutes' },
        { value: 3600, label: '1 hour' },
        { value: 7200, label: '2 hours' },
    ],
    refresh_token: [
        { value: 86400, label: '1 day' },
        { value: 604800, label: '7 days' },
        { value: 2592000, label: '30 days' },
        { value: 7776000, label: '90 days' },
    ],
    session: [
        { value: -1, label: 'Unlimited' },
        { value: 3600, label: '1 hour' },
        { value: 28800, label: '8 hours' },
        { value: 86400, label: '1 day' },
        { value: 604800, label: '7 days' },
        { value: 2592000, label: '30 days' },
    ],
    rotation: [
        { value: -1, label: 'Unlimited' },
        { value: 2592000, label: '30 days' },
        { value: 7776000, label: '90 days' },
        { value: 15552000, label: '180 days' },
        { value: 31536000, label: '1 year' },
    ],
};

/* Delegated handler for duration preset selects */
document.addEventListener('change', (e) => {
    const select = e.target.closest('[data-duration-for]');
    if (!select) return;
    const name = select.dataset.durationFor;
    const wrapper = select.closest('div');
    const input = wrapper.querySelector(`input[name="${name}"]`);
    const unit = wrapper.querySelector(`[data-duration-unit="${name}"]`);
    if (!input) return;
    if (select.value === 'custom') {
        input.classList.remove('hidden');
        input.setAttribute('min', '1');
        if (unit) unit.classList.remove('hidden');
        input.value = '';
        input.focus();
    } else {
        input.value = select.value;
        input.classList.add('hidden');
        input.removeAttribute('min');
        if (unit) unit.classList.add('hidden');
    }
});

// Navigation
function navigateToOrgList() {
    orgMgmt.view = 'org-list';
    orgMgmt.orgId = null;
    orgMgmt.rsId = null;
    orgMgmt.clientId = null;
    renderOrgManagement();
}

function navigateToOrg(orgId) {
    orgMgmt.view = 'org-detail';
    orgMgmt.orgId = orgId;
    orgMgmt.rsId = null;
    orgMgmt.clientId = null;
    renderOrgManagement();
}

function navigateToResourceServer(rsId) {
    orgMgmt.view = 'rs-detail';
    orgMgmt.rsId = rsId;
    orgMgmt.clientId = null;
    renderOrgManagement();
}

function navigateToClient(clientId) {
    orgMgmt.view = 'client-detail';
    orgMgmt.clientId = clientId;
    orgMgmt.rsId = null;
    renderOrgManagement();
}

// Main load function
async function loadOrganizations() {
    try {
        const data = await apiGet('/admin/organizations?limit=1');
        if (data.organizations.length > 0) {
            isOrgAdmin = true;
            document.getElementById('tabBar').style.display = 'block';
            document.getElementById('profileHeading').style.display = 'none';
            await renderOrgManagement();
            switchTab('profile');
        }
    } catch (error) {
        console.error('Failed to check org admin status:', error);
    }
}

// ===== Rendering =====

async function renderOrgManagement(scrollTarget) {
    const content = document.getElementById('orgsContent');
    const homeLink = document.getElementById('homeLink');
    const upLink = document.getElementById('upLink');

    homeLink.classList.add('hidden');
    upLink.classList.add('hidden');

    try {
        if (orgMgmt.view === 'org-list') {
            await renderOrgList(content);
        } else if (orgMgmt.view === 'org-detail') {
            await renderOrgDetail(content);
        } else if (orgMgmt.view === 'rs-detail') {
            await renderResourceServerDetail(content);
        } else if (orgMgmt.view === 'client-detail') {
            await renderClientDetail(content);
        }

        if (scrollTarget) {
            document.getElementById(scrollTarget)?.scrollIntoView({ behavior: 'instant' });
        }
    } catch (error) {
        console.error('Render error:', error);
        content.innerHTML = `
            <p class="text-error">Error: ${escapeHtml(error.message)}</p>
            <button data-action="navigate-org-list" class="btn-blue">Refresh</button>
        `;
    }

    if (orgMgmt.view === 'org-detail') {
        upLink.innerHTML = '<a href="#" data-action="navigate-org-list" class="link-nav">\u2B11 Up One Level</a>';
        upLink.classList.remove('hidden');
        homeLink.style.marginTop = '10px';
    } else if (orgMgmt.view === 'rs-detail' || orgMgmt.view === 'client-detail') {
        upLink.innerHTML = `<a href="#" data-action="navigate-to-org" data-id="${orgMgmt.orgId}" class="link-nav">\u2B11 Up One Level</a>`;
        upLink.classList.remove('hidden');
        homeLink.style.marginTop = '10px';
    } else {
        homeLink.style.marginTop = '40px';
    }

    homeLink.classList.remove('hidden');
}

async function renderOrgList(container) {
    const isActiveParam = orgMgmt.filter === 'all' ? '' :
                          orgMgmt.filter === 'active' ? '&is_active=true' : '&is_active=false';
    const data = await apiGet(`/admin/organizations?limit=100${isActiveParam}`);

    let html = `
        <div class="mb-lg nowrap">
            <label class="mr-md">
                <input type="radio" name="orgFilter" value="active" ${orgMgmt.filter === 'active' ? 'checked' : ''} data-action="set-org-filter" data-filter="active">
                Active Only
            </label>
            <label class="mr-md">
                <input type="radio" name="orgFilter" value="inactive" ${orgMgmt.filter === 'inactive' ? 'checked' : ''} data-action="set-org-filter" data-filter="inactive">
                Inactive Only
            </label>
            <label>
                <input type="radio" name="orgFilter" value="all" ${orgMgmt.filter === 'all' ? 'checked' : ''} data-action="set-org-filter" data-filter="all">
                All
            </label>
        </div>
    `;

    if (data.organizations.length === 0) {
        html += '<p>No organizations found.</p>';
    } else {
        data.organizations.forEach(org => {
            const statusBadge = org.is_active
                ? '<span class="badge-active">\u25CF Active</span>'
                : '<span class="badge-inactive">\u25CF Inactive</span>';

            html += `
                <div class="org-card">
                    <div class="flex-between-top">
                        <div class="no-shrink flex-fill">
                            <h4 class="mb-xs">${escapeHtml(org.display_name)}</h4>
                            <div class="text-muted text-sm">
                                ${escapeHtml(org.code_name)} <span class="ml-md">${statusBadge}</span>
                            </div>
                            ${org.note ? `<div class="text-sm mt-sm">${escapeHtml(org.note)}</div>` : ''}
                        </div>
                        <div class="ml-md">
                            <button data-action="navigate-to-org" data-id="${org.id}" class="btn-gray">Details</button>
                        </div>
                    </div>
                </div>
            `;
        });
    }

    container.innerHTML = html;
}

async function renderOrgDetail(container) {
    let html = '<div class="breadcrumb">';
    html += '<a href="#" data-action="navigate-org-list" class="link-nav">\u2190 Organizations</a>';
    html += '</div>';

    const org = await apiGet(`/admin/organizations?id=${orgMgmt.orgId}`);

    const statusBadge = org.is_active
        ? '<span class="badge-active">\u25CF Active</span>'
        : '<span class="badge-inactive">\u25CF Inactive</span>';

    html += `
        <div class="detail-card">
            <div class="flex-between-top mb-md">
                <h3 class="no-shrink no-margin">${escapeHtml(org.display_name)}</h3>
                <button data-action="edit-organization" data-id="${org.id}" class="btn-green">Edit</button>
            </div>
            <div class="detail-meta">
                <div><strong>Code Name:</strong> ${escapeHtml(org.code_name)}</div>
                <div><strong>Status:</strong> ${statusBadge}</div>
                <div class="flex-center">
                    <strong>Organization ID:</strong>
                    <code class="text-sm">${escapeHtml(formatUUID(org.id))}</code>
                    <span class="copy-btn-placeholder" data-copy-text="${escapeHtml(formatUUID(org.id))}"></span>
                </div>
                ${org.note ? `<div class="pre-line"><strong>Note:</strong> ${escapeHtml(org.note)}</div>` : ''}
            </div>
        </div>
    `;

    // Resource Servers section
    html += '<h3 class="section-heading">Resource Servers</h3>';
    const rsActiveParam = orgMgmt.rsFilter === 'all' ? '' :
                          orgMgmt.rsFilter === 'active' ? '&is_active=true' : '&is_active=false';
    const rsData = await apiGet(`/admin/resource-servers?organization_id=${orgMgmt.orgId}&limit=100${rsActiveParam}`);

    html += `
        <div class="flex-between mb-md">
            <button data-action="create-resource-server" data-org-id="${orgMgmt.orgId}" class="btn-blue mr-md">+ Create Resource Server</button>
            <div class="text-sm nowrap">
                <label class="mr-md"><input type="radio" name="rsFilter" value="active" ${orgMgmt.rsFilter === 'active' ? 'checked' : ''} data-action="set-rs-filter" data-filter="active"> Active</label>
                <label class="mr-md"><input type="radio" name="rsFilter" value="inactive" ${orgMgmt.rsFilter === 'inactive' ? 'checked' : ''} data-action="set-rs-filter" data-filter="inactive"> Inactive</label>
                <label><input type="radio" name="rsFilter" value="all" ${orgMgmt.rsFilter === 'all' ? 'checked' : ''} data-action="set-rs-filter" data-filter="all"> All</label>
            </div>
        </div>`;

    if (rsData.resource_servers.length === 0) {
        html += '<p class="text-muted">No resource servers configured.</p>';
    } else {
        rsData.resource_servers.forEach(rs => {
            const statusBadge = rs.is_active
                ? '<span class="badge-active">\u25CF Active</span>'
                : '<span class="badge-inactive">\u25CF Inactive</span>';
            html += `
                <div class="list-item">
                    <div class="flex-between flex-wrap-actions">
                        <div>
                            <strong>${escapeHtml(rs.display_name)}</strong>
                            <span class="text-muted text-sm ml-md">${escapeHtml(rs.code_name)}</span>
                            <span class="ml-md">${statusBadge}</span>
                        </div>
                        <button data-action="navigate-to-rs" data-id="${rs.id}" class="btn-gray btn-sm">Details</button>
                    </div>
                </div>
            `;
        });
    }

    // Clients section
    html += '<h3 class="section-heading">Clients</h3>';
    const clientActiveParam = orgMgmt.clientFilter === 'all' ? '' :
                              orgMgmt.clientFilter === 'active' ? '&is_active=true' : '&is_active=false';
    const clientData = await apiGet(`/admin/clients?organization_id=${orgMgmt.orgId}&limit=100${clientActiveParam}`);

    html += `
        <div class="flex-between mb-md">
            <button data-action="create-client" data-org-id="${orgMgmt.orgId}" class="btn-blue">+ Create Client</button>
            <div class="text-sm nowrap">
                <label class="mr-md"><input type="radio" name="clientFilter" value="active" ${orgMgmt.clientFilter === 'active' ? 'checked' : ''} data-action="set-client-filter" data-filter="active"> Active</label>
                <label class="mr-md"><input type="radio" name="clientFilter" value="inactive" ${orgMgmt.clientFilter === 'inactive' ? 'checked' : ''} data-action="set-client-filter" data-filter="inactive"> Inactive</label>
                <label><input type="radio" name="clientFilter" value="all" ${orgMgmt.clientFilter === 'all' ? 'checked' : ''} data-action="set-client-filter" data-filter="all"> All</label>
            </div>
        </div>`;

    if (clientData.clients.length === 0) {
        html += '<p class="text-muted">No clients configured.</p>';
    } else {
        clientData.clients.forEach(client => {
            const statusBadge = client.is_active
                ? '<span class="badge-active">\u25CF Active</span>'
                : '<span class="badge-inactive">\u25CF Inactive</span>';
            html += `
                <div class="list-item">
                    <div class="flex-between flex-wrap-actions">
                        <div>
                            <strong>${escapeHtml(client.display_name)}</strong>
                            <span class="text-muted text-sm ml-md">${escapeHtml(client.code_name)}</span>
                            <span class="ml-md">${statusBadge}</span>
                        </div>
                        <button data-action="navigate-to-client" data-id="${client.id}" class="btn-gray btn-sm">Details</button>
                    </div>
                </div>
            `;
        });
    }

    container.innerHTML = html;
    container.querySelectorAll('.copy-btn-placeholder').forEach(placeholder => {
        placeholder.appendChild(createCopyButton(placeholder.getAttribute('data-copy-text')));
    });
}

async function renderResourceServerDetail(container) {
    const rs = await apiGet(`/admin/resource-servers?id=${orgMgmt.rsId}`);
    const org = await apiGet(`/admin/organizations?id=${orgMgmt.orgId}`);

    let html = '<div class="breadcrumb">';
    html += '<a href="#" data-action="navigate-org-list" class="link-nav">Organizations</a> / ';
    html += `<a href="#" data-action="navigate-to-org" data-id="${org.id}" class="link-nav">${escapeHtml(org.display_name)}</a> / `;
    html += '<span>Resource Server</span></div>';

    const statusBadge = rs.is_active ? '<span class="badge-active">\u25CF Active</span>' : '<span class="badge-inactive">\u25CF Inactive</span>';

    html += `
        <div class="detail-card">
            <div class="flex-between-top mb-md">
                <h3 class="no-shrink no-margin">${escapeHtml(rs.display_name)}</h3>
                <button data-action="edit-resource-server" data-id="${rs.id}" class="btn-green">Edit</button>
            </div>
            <div class="detail-meta">
                <div><strong>Code Name:</strong> ${escapeHtml(rs.code_name)}</div>
                <div><strong>Address:</strong> ${escapeHtml(rs.address)}</div>
                <div><strong>Status:</strong> ${statusBadge}</div>
                <div><strong>User Provisioning:</strong> ${rs.allow_user_provisioning ? 'Yes' : 'No'}</div>
                <div class="flex-center">
                    <strong>Resource Server ID:</strong>
                    <code class="text-sm">${escapeHtml(formatUUID(rs.id))}</code>
                    <span class="copy-btn-placeholder" data-copy-text="${escapeHtml(formatUUID(rs.id))}"></span>
                </div>
                ${rs.note ? `<div class="pre-line"><strong>Note:</strong> ${escapeHtml(rs.note)}</div>` : ''}
            </div>
        </div>
    `;

    // Keys
    html += '<h3 class="section-heading">Resource Server Keys</h3>';
    const rsKeysData = await apiGet(`/admin/resource-server-keys?resource_server_id=${orgMgmt.rsId}&limit=100&is_active=1`);
    html += `<button data-action="create-rs-key" data-rs-id="${orgMgmt.rsId}" class="btn-blue mb-md">+ Generate Key</button>`;

    if (rsKeysData.keys.length === 0) {
        html += '<p class="text-muted">No keys configured.</p>';
    } else {
        rsKeysData.keys.forEach(key => {
            const activeBadge = key.is_active ? '<span class="badge-active-sm">\u25CF Active</span>' : '<span class="badge-inactive-sm">\u25CF Revoked</span>';
            const formattedKeyId = formatUUID(key.key_id);
            html += `
                <div class="list-item">
                    <div class="flex-between">
                        <div class="flex-center">
                            <code class="text-sm">${escapeHtml(formattedKeyId)}</code>
                            <span class="copy-btn-placeholder" data-copy-text="${escapeHtml(formattedKeyId)}"></span>
                            ${activeBadge}
                            <div class="text-muted text-sm mt-xs">Generated: ${key.generated_at.slice(0, 19).replace('T', ' ')}</div>
                            ${key.note ? `<div class="text-muted text-sm">${escapeHtml(key.note)}</div>` : ''}
                        </div>
                        ${key.is_active ? `<button data-action="revoke-rs-key" data-id="${key.id}" class="btn-red btn-xs ml-sm">Revoke</button>` : ''}
                    </div>
                </div>
            `;
        });
    }

    // Linked Clients
    html += '<h3 class="section-heading">Linked Clients</h3>';
    const linkData = await apiGet(`/admin/resource-server-clients?resource_server_id=${orgMgmt.rsId}&limit=100`);
    html += `<button data-action="link-rs-to-client" data-rs-id="${orgMgmt.rsId}" class="btn-blue mb-md">+ Link Client</button>`;

    if (linkData.links.length === 0) {
        html += '<p class="text-muted">No clients linked to this resource server.</p>';
    } else {
        linkData.links.forEach(link => {
            html += `
                <div class="list-item flex-between flex-wrap-actions">
                    <div>
                        <strong>${escapeHtml(link.client_display_name)}</strong>
                        <span class="text-muted text-sm ml-md">${escapeHtml(link.client_code_name)}</span>
                    </div>
                    <div class="nowrap">
                        <button data-action="navigate-to-client" data-id="${link.client_id}" class="btn-gray btn-sm mr-sm">View Client</button>
                        <button data-action="unlink-client-from-rs" data-client-id="${link.client_id}" data-rs-id="${orgMgmt.rsId}" class="btn-red btn-sm">Unlink</button>
                    </div>
                </div>
            `;
        });
    }

    container.innerHTML = html;
    container.querySelectorAll('.copy-btn-placeholder').forEach(placeholder => {
        placeholder.appendChild(createCopyButton(placeholder.getAttribute('data-copy-text')));
    });
}

async function renderClientDetail(container) {
    const client = await apiGet(`/admin/clients?id=${orgMgmt.clientId}`);
    const org = await apiGet(`/admin/organizations?id=${orgMgmt.orgId}`);

    let html = '<div class="breadcrumb">';
    html += '<a href="#" data-action="navigate-org-list" class="link-nav">Organizations</a> / ';
    html += `<a href="#" data-action="navigate-to-org" data-id="${org.id}" class="link-nav">${escapeHtml(org.display_name)}</a> / `;
    html += '<span>Client</span></div>';

    const statusBadge = client.is_active ? '<span class="badge-active">\u25CF Active</span>' : '<span class="badge-inactive">\u25CF Inactive</span>';

    html += `
        <div class="detail-card">
            <div class="flex-between-top mb-md">
                <h3 class="no-shrink no-margin">${escapeHtml(client.display_name)}</h3>
                <button data-action="edit-client" data-id="${client.id}" class="btn-green">Edit</button>
            </div>
            <div class="detail-meta">
                <div><strong>Code Name:</strong> ${escapeHtml(client.code_name)}</div>
                <div><strong>Type:</strong> ${escapeHtml(client.client_type)}</div>
                <div><strong>Grant Type:</strong> ${escapeHtml(client.grant_type)}</div>
                <div><strong>Status:</strong> ${statusBadge}</div>
                <div class="flex-center">
                    <strong>Client ID:</strong>
                    <code class="text-sm">${escapeHtml(formatUUID(client.id))}</code>
                    <span class="copy-btn-placeholder" data-copy-text="${escapeHtml(formatUUID(client.id))}"></span>
                </div>
                <div><strong>Access Token TTL:</strong> ${formatDuration(client.access_token_ttl_seconds)}</div>
                ${client.grant_type === 'authorization_code' ? `
                    ${client.issue_refresh_tokens ? `<div><strong>Refresh Token TTL:</strong> ${formatDuration(client.refresh_token_ttl_seconds)}</div>` : ''}
                    <div><strong>Maximum Session Duration:</strong> ${formatDuration(client.maximum_session_seconds)}</div>
                    <div><strong>Refresh Tokens:</strong> ${client.issue_refresh_tokens ? 'Yes' : 'No'}</div>
                    <div><strong>Require MFA:</strong> ${client.require_mfa ? 'Yes' : 'No'}</div>
                ` : `
                    <div><strong>Maximum Key Age:</strong> ${formatDuration(client.secret_rotation_seconds)}</div>
                `}
                ${client.note ? `<div class="pre-line"><strong>Note:</strong> ${escapeHtml(client.note)}</div>` : ''}
            </div>
        </div>
    `;

    // Client Keys (confidential only)
    if (client.client_type === 'confidential') {
        html += '<h3 class="section-heading">Client Keys</h3>';
        const clientKeysData = await apiGet(`/admin/client-keys?client_id=${orgMgmt.clientId}&limit=100&is_active=1`);
        html += `<button data-action="create-client-key" data-client-id="${orgMgmt.clientId}" class="btn-blue mb-md">+ Generate Key</button>`;

        if (clientKeysData.keys.length === 0) {
            html += '<p class="text-muted">No keys configured.</p>';
        } else {
            clientKeysData.keys.forEach(key => {
                const activeBadge = key.is_active ? '<span class="badge-active-sm">\u25CF Active</span>' : '<span class="badge-inactive-sm">\u25CF Revoked</span>';
                const formattedKeyId = formatUUID(key.key_id);
                html += `
                    <div class="list-item">
                        <div class="flex-between">
                            <div class="flex-center">
                                <code class="text-sm">${escapeHtml(formattedKeyId)}</code>
                                <span class="copy-btn-placeholder" data-copy-text="${escapeHtml(formattedKeyId)}"></span>
                                ${activeBadge}
                                <div class="text-muted text-sm mt-xs">Generated: ${key.generated_at.slice(0, 19).replace('T', ' ')}</div>
                                ${key.note ? `<div class="text-muted text-sm">${escapeHtml(key.note)}</div>` : ''}
                            </div>
                            ${key.is_active ? `<button data-action="revoke-client-key" data-id="${key.id}" class="btn-red btn-xs ml-sm">Revoke</button>` : ''}
                        </div>
                    </div>
                `;
            });
        }
    }

    // Redirect URIs (authorization_code only)
    if (client.grant_type === 'authorization_code') {
        html += '<h3 class="section-heading">Redirect URIs</h3>';
        const uriData = await apiGet(`/admin/client-redirect-uris?client_id=${orgMgmt.clientId}&limit=100`);
        html += `<button data-action="add-redirect-uri" data-client-id="${orgMgmt.clientId}" class="btn-blue mb-md">+ Add Redirect URI</button>`;

        if (uriData.redirect_uris.length === 0) {
            html += '<p class="text-muted">No redirect URIs configured.</p>';
        } else {
            uriData.redirect_uris.forEach(uri => {
                html += `
                    <div class="list-item flex-between flex-wrap-actions">
                        <div>
                            <code>${escapeHtml(uri.redirect_uri)}</code>
                            ${uri.note ? `<div class="text-muted text-sm mt-xs">${escapeHtml(uri.note)}</div>` : ''}
                        </div>
                        <button data-action="delete-redirect-uri" data-client-id="${orgMgmt.clientId}" data-uri="${encodeURIComponent(uri.redirect_uri)}" class="btn-red btn-sm">Delete</button>
                    </div>
                `;
            });
        }
    }

    // Linked Resource Servers
    html += '<h3 class="section-heading">Linked Resource Servers</h3>';
    const linkData = await apiGet(`/admin/client-resource-servers?client_id=${orgMgmt.clientId}&limit=100`);
    html += `<button data-action="link-client-to-rs" data-client-id="${orgMgmt.clientId}" class="btn-blue mb-md">+ Link Resource Server</button>`;

    if (linkData.links.length === 0) {
        html += '<p class="text-muted">No resource servers linked.</p>';
    } else {
        linkData.links.forEach(link => {
            html += `
                <div class="list-item flex-between flex-wrap-actions">
                    <div>
                        <strong>${escapeHtml(link.resource_server_display_name)}</strong>
                        <span class="text-muted text-sm ml-md">${escapeHtml(link.resource_server_code_name)}</span>
                    </div>
                    <div class="nowrap">
                        <button data-action="navigate-to-rs" data-id="${link.resource_server_id}" class="btn-gray btn-sm mr-sm">View RS</button>
                        <button data-action="unlink-client-from-rs" data-client-id="${orgMgmt.clientId}" data-rs-id="${link.resource_server_id}" class="btn-red btn-sm">Unlink</button>
                    </div>
                </div>
            `;
        });
    }

    container.innerHTML = html;
    container.querySelectorAll('.copy-btn-placeholder').forEach(placeholder => {
        placeholder.appendChild(createCopyButton(placeholder.getAttribute('data-copy-text')));
    });
}

// ===== CRUD Operations =====

async function editOrganization(orgId) {
    const org = await apiGet(`/admin/organizations?id=${orgId}`);
    const { modal, close } = showModal('Edit Organization', `
        <form id="editOrgForm">
            ${formField('Display Name', 'display_name', org.display_name, 'text', true, false, 200)}
            ${formTextarea('Note', 'note', org.note || '', false, 2000)}
            ${formCheckbox('Active', 'is_active', org.is_active)}
            <div class="modal-actions">
                <button type="submit" class="btn-green btn-modal">Save</button>
                <button type="button" data-action="close-modal" class="btn-gray btn-modal">Cancel</button>
            </div>
        </form>
    `);
    document.getElementById('editOrgForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        try {
            await apiPut(`/admin/organizations?id=${orgId}`, {
                display_name: formData.get('display_name'),
                note: formData.get('note'),
                is_active: formData.get('is_active') === 'on'
            });
            close(); renderOrgManagement();
        } catch (error) { showAlert('Error: ' + error.message); }
    });
}

async function createResourceServer(orgId) {
    const { modal, close } = showModal('Create Resource Server', `
        <form id="createRSForm">
            ${formField('Code Name', 'code_name', '', 'text', true, false, 100)}
            ${formField('Display Name', 'display_name', '', 'text', true, false, 200)}
            ${formField('Address', 'address', '', 'text', true, false, 2000)}
            ${formTextarea('Note', 'note', '', false, 2000)}
            <div class="modal-actions">
                <button type="submit" class="btn-blue btn-modal">Create</button>
                <button type="button" data-action="close-modal" class="btn-gray btn-modal">Cancel</button>
            </div>
        </form>
    `);
    document.getElementById('createRSForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        try {
            await apiPost('/admin/resource-servers', {
                organization_id: orgId, code_name: formData.get('code_name'),
                display_name: formData.get('display_name'), address: formData.get('address'),
                note: formData.get('note') || null
            });
            close(); renderOrgManagement();
        } catch (error) { showAlert('Error: ' + error.message); }
    });
}

async function editResourceServer(rsId) {
    const rs = await apiGet(`/admin/resource-servers?id=${rsId}`);
    const { modal, close } = showModal('Edit Resource Server', `
        <form id="editRSForm">
            ${formField('Display Name', 'display_name', rs.display_name, 'text', true, false, 200)}
            ${formField('Address', 'address', rs.address, 'text', true, false, 2000)}
            ${formTextarea('Note', 'note', rs.note || '', false, 2000)}
            ${formCheckbox('Active', 'is_active', rs.is_active)}
            ${formCheckbox('Allow User Provisioning', 'allow_user_provisioning', rs.allow_user_provisioning)}
            <div class="modal-actions">
                <button type="submit" class="btn-green btn-modal">Save</button>
                <button type="button" data-action="close-modal" class="btn-gray btn-modal">Cancel</button>
            </div>
        </form>
    `);
    document.getElementById('editRSForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        try {
            await apiPut(`/admin/resource-servers?id=${rsId}`, {
                display_name: formData.get('display_name'), address: formData.get('address'),
                note: formData.get('note'), is_active: formData.get('is_active') === 'on',
                allow_user_provisioning: formData.get('allow_user_provisioning') === 'on'
            });
            close(); renderOrgManagement();
        } catch (error) { showAlert('Error: ' + error.message); }
    });
}

async function createClient(orgId) {
    const { modal, close } = showModal('Create Client', `
        <form id="createClientForm">
            ${formField('Code Name', 'code_name', '', 'text', true, false, 100)}
            ${formField('Display Name', 'display_name', '', 'text', true, false, 200)}
            ${formSelect('Client Type', 'client_config', [
                { value: 'public', label: 'Public Client (Authorization Code Flow)' },
                { value: 'confidential', label: 'Confidential Client (Client Credentials Flow)' }
            ], 'public', true)}
            ${formDuration('Access Token TTL', 'access_token_ttl_seconds', 3600, DURATION_PRESETS.access_token, true)}
            <div id="authCodeFields">
                ${formCheckbox('Issue Refresh Tokens', 'issue_refresh_tokens', true)}
                ${formDuration('Refresh Token TTL', 'refresh_token_ttl_seconds', 2592000, DURATION_PRESETS.refresh_token)}
                ${formDuration('Maximum Session Duration', 'maximum_session_seconds', 604800, DURATION_PRESETS.session)}
                ${formCheckbox('Require MFA', 'require_mfa', false)}
            </div>
            <div id="confidentialFields" class="hidden">
                ${formDuration('Maximum Key Age (Secret Rotation)', 'secret_rotation_seconds', -1, DURATION_PRESETS.rotation)}
            </div>
            ${formTextarea('Note', 'note', '', false, 2000)}
            <div class="modal-actions">
                <button type="submit" class="btn-blue btn-modal">Create</button>
                <button type="button" data-action="close-modal" class="btn-gray btn-modal">Cancel</button>
            </div>
        </form>
    `);

    const form = document.getElementById('createClientForm');
    const clientConfig = form.querySelector('[name="client_config"]');
    const authCodeFields = document.getElementById('authCodeFields');
    const confidentialFields = document.getElementById('confidentialFields');

    function toggleFields() {
        const isPublic = clientConfig.value === 'public';
        authCodeFields.style.display = isPublic ? 'block' : 'none';
        confidentialFields.style.display = isPublic ? 'none' : 'block';
        confidentialFields.querySelectorAll('input, select').forEach(el => el.disabled = isPublic);
        authCodeFields.querySelectorAll('input, select').forEach(el => el.disabled = !isPublic);
    }
    clientConfig.addEventListener('change', toggleFields);
    toggleFields();

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        try {
            const clientConfig = formData.get('client_config');
            const grant_type = clientConfig === 'public' ? 'authorization_code' : 'client_credentials';
            const createData = {
                organization_id: orgId, code_name: formData.get('code_name'),
                display_name: formData.get('display_name'), client_type: clientConfig,
                grant_type: grant_type, access_token_ttl_seconds: parseInt(formData.get('access_token_ttl_seconds')),
                note: formData.get('note') || null
            };
            if (grant_type === 'authorization_code') {
                createData.issue_refresh_tokens = formData.get('issue_refresh_tokens') === 'on';
                createData.refresh_token_ttl_seconds = optInt(formData, 'refresh_token_ttl_seconds');
                createData.maximum_session_seconds = optInt(formData, 'maximum_session_seconds');
                createData.require_mfa = formData.get('require_mfa') === 'on';
            } else {
                createData.secret_rotation_seconds = optInt(formData, 'secret_rotation_seconds');
            }
            await apiPost('/admin/clients', createData);
            close(); renderOrgManagement();
        } catch (error) { showAlert('Error: ' + error.message); }
    });
}

async function editClient(clientId) {
    const client = await apiGet(`/admin/clients?id=${clientId}`);
    const { modal, close } = showModal('Edit Client', `
        <form id="editClientForm">
            ${formField('Display Name', 'display_name', client.display_name, 'text', true, false, 200)}
            ${formDuration('Access Token TTL', 'access_token_ttl_seconds', client.access_token_ttl_seconds, DURATION_PRESETS.access_token, true)}
            ${client.grant_type === 'authorization_code' ? `
                ${formCheckbox('Issue Refresh Tokens', 'issue_refresh_tokens', client.issue_refresh_tokens)}
                ${formDuration('Refresh Token TTL', 'refresh_token_ttl_seconds', client.refresh_token_ttl_seconds, DURATION_PRESETS.refresh_token)}
                ${formDuration('Maximum Session Duration', 'maximum_session_seconds', client.maximum_session_seconds, DURATION_PRESETS.session)}
                ${formCheckbox('Require MFA', 'require_mfa', client.require_mfa)}
            ` : `
                ${formDuration('Maximum Key Age (Secret Rotation)', 'secret_rotation_seconds', client.secret_rotation_seconds, DURATION_PRESETS.rotation)}
            `}
            ${formTextarea('Note', 'note', client.note || '', false, 2000)}
            ${formCheckbox('Active', 'is_active', client.is_active)}
            <div class="modal-actions">
                <button type="submit" class="btn-green btn-modal">Save</button>
                <button type="button" data-action="close-modal" class="btn-gray btn-modal">Cancel</button>
            </div>
        </form>
    `);
    document.getElementById('editClientForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        try {
            const updateData = {
                display_name: formData.get('display_name'),
                access_token_ttl_seconds: parseInt(formData.get('access_token_ttl_seconds')),
                note: formData.get('note'), is_active: formData.get('is_active') === 'on'
            };
            if (client.grant_type === 'authorization_code') {
                updateData.issue_refresh_tokens = formData.get('issue_refresh_tokens') === 'on';
                updateData.refresh_token_ttl_seconds = optInt(formData, 'refresh_token_ttl_seconds');
                updateData.maximum_session_seconds = optInt(formData, 'maximum_session_seconds');
                updateData.require_mfa = formData.get('require_mfa') === 'on';
            } else {
                updateData.secret_rotation_seconds = optInt(formData, 'secret_rotation_seconds');
            }
            await apiPut(`/admin/clients?id=${clientId}`, updateData);
            close(); renderOrgManagement();
        } catch (error) { showAlert('Error: ' + error.message); }
    });
}

async function addRedirectURI(clientId) {
    const { modal, close } = showModal('Add Redirect URI', `
        <form id="addURIForm">
            <div class="form-group">
                <label>Redirect URI <span class="text-error">*</span></label>
                <div class="flex-row">
                    <select name="uri_scheme" class="form-input input-narrow">
                        <option value="https://">https://</option>
                        <option value="http://">http://</option>
                    </select>
                    <input type="text" name="uri_path" placeholder="localhost:3000/callback" required maxlength="2000" class="form-input flex-fill">
                </div>
                <small class="form-hint">Select the scheme and enter the path.</small>
            </div>
            ${formTextarea('Note', 'note', '', false, 2000)}
            <div class="modal-actions">
                <button type="submit" class="btn-blue btn-modal">Add</button>
                <button type="button" data-action="close-modal" class="btn-gray btn-modal">Cancel</button>
            </div>
        </form>
    `);
    document.getElementById('addURIForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        try {
            await apiPost('/admin/client-redirect-uris', {
                client_id: clientId,
                redirect_uri: formData.get('uri_scheme') + formData.get('uri_path'),
                note: formData.get('note') || null
            });
            close(); renderOrgManagement();
        } catch (error) { showAlert('Error: ' + error.message); }
    });
}

async function deleteRedirectURI(clientId, redirectUri) {
    const decodedUri = decodeURIComponent(redirectUri);
    if (!(await showConfirm(`Delete redirect URI: ${decodedUri}?`))) return;
    try {
        await apiDelete(`/admin/client-redirect-uris?client_id=${clientId}&redirect_uri=${encodeURIComponent(decodedUri)}`);
        renderOrgManagement();
    } catch (error) { showAlert('Error: ' + error.message); }
}

async function linkClientToRS(clientId) {
    const rsData = await apiGet(`/admin/resource-servers?organization_id=${orgMgmt.orgId}&limit=100`);
    const currentLinks = await apiGet(`/admin/client-resource-servers?client_id=${clientId}&limit=100`);
    const linkedIds = new Set(currentLinks.links.map(l => l.resource_server_id));
    const availableRS = rsData.resource_servers.filter(rs => !linkedIds.has(rs.id) && rs.is_active);
    if (availableRS.length === 0) { showAlert('No available resource servers to link.'); return; }
    const options = availableRS.map(rs => ({ value: rs.id, label: `${rs.display_name} (${rs.code_name})` }));
    const { modal, close } = showModal('Link Resource Server', `
        <form id="linkRSForm">
            ${formSelect('Resource Server', 'id', options, '', true)}
            <div class="modal-actions">
                <button type="submit" class="btn-blue btn-modal">Link</button>
                <button type="button" data-action="close-modal" class="btn-gray btn-modal">Cancel</button>
            </div>
        </form>
    `);
    document.getElementById('linkRSForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        try {
            await apiPost('/admin/client-resource-servers', { client_id: clientId, resource_server_id: new FormData(e.target).get('id') });
            close(); renderOrgManagement();
        } catch (error) { showAlert('Error: ' + error.message); }
    });
}

async function linkRSToClient(rsId) {
    const clientData = await apiGet(`/admin/clients?organization_id=${orgMgmt.orgId}&limit=100`);
    const currentLinks = await apiGet(`/admin/resource-server-clients?resource_server_id=${rsId}&limit=100`);
    const linkedIds = new Set(currentLinks.links.map(l => l.client_id));
    const availableClients = clientData.clients.filter(c => !linkedIds.has(c.id) && c.is_active);
    if (availableClients.length === 0) { showAlert('No available clients to link.'); return; }
    const options = availableClients.map(c => ({ value: c.id, label: `${c.display_name} (${c.code_name})` }));
    const { modal, close } = showModal('Link Client', `
        <form id="linkClientForm">
            ${formSelect('Client', 'id', options, '', true)}
            <div class="modal-actions">
                <button type="submit" class="btn-blue btn-modal">Link</button>
                <button type="button" data-action="close-modal" class="btn-gray btn-modal">Cancel</button>
            </div>
        </form>
    `);
    document.getElementById('linkClientForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        try {
            await apiPost('/admin/client-resource-servers', { client_id: new FormData(e.target).get('id'), resource_server_id: rsId });
            close(); renderOrgManagement();
        } catch (error) { showAlert('Error: ' + error.message); }
    });
}

async function unlinkClientFromRS(clientId, rsId) {
    if (!(await showConfirm('Unlink this client and resource server?'))) return;
    try {
        await apiDelete(`/admin/client-resource-servers?client_id=${clientId}&resource_server_id=${rsId}`);
        renderOrgManagement();
    } catch (error) { showAlert('Error: ' + error.message); }
}

// ===== Key Management =====

async function createResourceServerKey(resourceServerId) {
    const { modal, close } = showModal('Create Resource Server Key', `
        <form id="createKeyForm">
            <div class="form-group">
                <label class="flex-center"><input type="radio" name="secret_mode" value="generate" checked> Generate secure secret</label>
                <label class="flex-center mt-sm"><input type="radio" name="secret_mode" value="custom"> Provide your own secret</label>
            </div>
            <div id="customSecretField" class="hidden mt-md">
                ${formField('Secret', 'secret', '', 'password')}
                <small class="form-hint">Leave empty to generate a random secret</small>
            </div>
            <div class="mt-md">${formTextarea('Note', 'note', '', false, 2000)}</div>
            <div class="modal-actions">
                <button type="submit" class="btn-blue btn-modal">Create Key</button>
                <button type="button" data-action="close-modal" class="btn-gray btn-modal">Cancel</button>
            </div>
        </form>
    `);
    const form = document.getElementById('createKeyForm');
    form.querySelectorAll('input[name="secret_mode"]').forEach(radio => {
        radio.addEventListener('change', () => { document.getElementById('customSecretField').style.display = radio.value === 'custom' ? 'block' : 'none'; });
    });
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        try {
            const payload = { resource_server_id: resourceServerId, note: formData.get('note') || null };
            if (formData.get('secret_mode') === 'custom') {
                const s = formData.get('secret');
                if (s && s.trim()) payload.secret = s;
            }
            const response = await apiPost('/admin/resource-server-keys', payload);
            close();
            if (response.secret) showSecretModal(response.key_id, response.secret, resourceServerId, 'resource_server_key');
            else renderOrgManagement();
        } catch (error) { showAlert('Error: ' + error.message); }
    });
}

async function revokeResourceServerKey(keyId) {
    if (!(await showConfirm('Are you sure you want to revoke this key? This action cannot be undone.'))) return;
    try { await apiDelete(`/admin/resource-server-keys?id=${keyId}`); renderOrgManagement(); }
    catch (error) { showAlert('Error: ' + error.message); }
}

async function createClientKey(clientId) {
    const { modal, close } = showModal('Create Client Key', `
        <form id="createClientKeyForm">
            <div class="form-group">
                <label class="flex-center"><input type="radio" name="secret_mode" value="generate" checked> Generate secure secret</label>
                <label class="flex-center mt-sm"><input type="radio" name="secret_mode" value="custom"> Provide your own secret</label>
            </div>
            <div id="customSecretFieldClient" class="hidden mt-md">
                ${formField('Secret', 'secret', '', 'password')}
                <small class="form-hint">Leave empty to generate a random secret</small>
            </div>
            <div class="mt-md">${formTextarea('Note', 'note', '', false, 2000)}</div>
            <div class="modal-actions">
                <button type="submit" class="btn-blue btn-modal">Create Key</button>
                <button type="button" data-action="close-modal" class="btn-gray btn-modal">Cancel</button>
            </div>
        </form>
    `);
    const form = document.getElementById('createClientKeyForm');
    form.querySelectorAll('input[name="secret_mode"]').forEach(radio => {
        radio.addEventListener('change', () => { document.getElementById('customSecretFieldClient').style.display = radio.value === 'custom' ? 'block' : 'none'; });
    });
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        try {
            const payload = { client_id: clientId, note: formData.get('note') || null };
            if (formData.get('secret_mode') === 'custom') {
                const s = formData.get('secret');
                if (s && s.trim()) payload.secret = s;
            }
            const response = await apiPost('/admin/client-keys', payload);
            close();
            if (response.secret) showSecretModal(response.key_id, response.secret, clientId, 'client_key');
            else renderOrgManagement();
        } catch (error) { showAlert('Error: ' + error.message); }
    });
}

async function revokeClientKey(keyId) {
    if (!(await showConfirm('Are you sure you want to revoke this key? This action cannot be undone.'))) return;
    try { await apiDelete(`/admin/client-keys?id=${keyId}`); renderOrgManagement(); }
    catch (error) { showAlert('Error: ' + error.message); }
}

function showSecretModal(keyId, secret, entityId, keyType) {
    const formattedKeyId = formatUUID(keyId);
    const formattedEntityId = formatUUID(entityId);

    const { modal, close, onClose } = showModal('Save Your Secret', `
        <div class="warning-box">
            <strong>Warning:</strong> This secret will only be shown once and cannot be retrieved later!
        </div>
        <div class="form-group mb-md">
            <label class="form-label-bold">Key ID</label>
            <div class="flex-row">
                <input type="text" id="keyIdValue" value="${escapeHtml(formattedKeyId)}" readonly class="key-display">
                <button data-action="copy-key-id" class="btn-gray">Copy</button>
            </div>
        </div>
        <div class="form-group mb-md">
            <label class="form-label-bold">Secret</label>
            <div class="flex-row">
                <input type="text" id="secretValue" value="${escapeHtml(secret)}" readonly class="key-display">
                <button data-action="copy-secret" class="btn-green">Copy</button>
            </div>
        </div>
        <div class="modal-actions">
            <button data-action="download-json" class="btn-teal btn-modal">Download as JSON</button>
            <button data-action="close-secret-modal" class="btn-blue btn-modal">I've Saved My Secret</button>
        </div>
    `);

    modal.querySelector('[data-action="copy-key-id"]').onclick = function(e) {
        e.stopPropagation();
        const btn = e.target;
        const orig = btn.textContent;
        navigator.clipboard.writeText(formattedKeyId).then(() => {
            btn.textContent = '\u2713 Copied!';
            setTimeout(() => { btn.textContent = orig; }, 2000);
        }).catch(() => {
            btn.textContent = 'Failed.';
            setTimeout(() => { btn.textContent = orig; }, 2000);
        });
    };

    modal.querySelector('[data-action="copy-secret"]').onclick = function(e) {
        e.stopPropagation();
        const btn = e.target;
        const orig = btn.textContent;
        navigator.clipboard.writeText(secret).then(() => {
            btn.textContent = '\u2713 Copied!';
            setTimeout(() => { btn.textContent = orig; }, 2000);
        }).catch(() => {
            btn.textContent = 'Failed.';
            setTimeout(() => { btn.textContent = orig; }, 2000);
        });
    };

    modal.querySelector('[data-action="download-json"]').onclick = function(e) {
        e.stopPropagation();
        const timestamp = new Date().toISOString().replace('T', ' ').slice(0, -1);
        const data = { key_id: formattedKeyId, secret: secret, type: keyType, generated_at: timestamp };
        if (keyType === 'resource_server_key') data.resource_server_id = formattedEntityId;
        else if (keyType === 'client_key') data.client_id = formattedEntityId;

        const json = JSON.stringify(data, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${keyType.replace('_', '-')}-${keyId.substring(0, 8)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    onClose(renderOrgManagement);

    modal.querySelector('[data-action="close-secret-modal"]').onclick = function(e) {
        e.stopPropagation();
        close();
    };
}

// ===== Start =====
init();

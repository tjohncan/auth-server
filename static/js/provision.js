'use strict';

/* Shared auth fields */
function requireAuth() {
    return requireFields([
        ['rs-id', 'Resource Server ID'],
        ['rs-key-id', 'Resource Server Key ID'],
        ['rs-secret', 'Resource Server Secret']
    ]);
}

function authFields() {
    return {
        resource_server_id: val('rs-id'),
        resource_server_key_id: val('rs-key-id'),
        resource_server_secret: val('rs-secret')
    };
}

/* API call — JSON body */
async function apiJson(method, url, body) {
    var res = await fetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    var text = await res.text();
    var json = null;
    try { json = JSON.parse(text); } catch (e) {}
    return { status: res.status, json: json, text: text };
}

/* Display result */
function showResult(panelId, method, url, body, status, responseText, json) {
    var container = $(panelId + '-result');

    var displayBody = JSON.parse(JSON.stringify(body));
    displayBody.resource_server_secret = '****';

    var reqDisplay = method + ' ' + url + '\nContent-Type: application/json\n\n' + JSON.stringify(displayBody, null, 2);

    var resBody = json ? JSON.stringify(json, null, 2) : responseText;
    var statusClass = status < 400 ? 'status-ok' : 'status-err';

    var html = '<div class="result-block">' +
        '<div class="result-label">Request</div>' +
        '<pre>' + esc(reqDisplay) + '</pre>' +
        '</div>' +
        '<div class="result-block">' +
        '<div class="result-label">Response <span class="' + statusClass + '">' + status + '</span></div>' +
        '<pre>' + esc(resBody) + '</pre>' +
        '</div>';

    var copies = [];
    if (json) {
        if (json.user_id) copies.push(['Copy User ID', json.user_id]);
        if (json.invitation && json.invitation.url) copies.push(['Copy Invitation URL', json.invitation.url]);
    }
    if (copies.length) {
        html += '<div class="copy-section">';
        for (var i = 0; i < copies.length; i++) {
            var key = panelId + '-' + i;
            copyStore[key] = copies[i][1];
            html += '<button class="copy-btn" data-action="copy" data-key="' + key + '">' + copies[i][0] + '</button>';
        }
        html += '</div>';
    }

    container.innerHTML = html;
    container.style.display = 'block';
}

/* Panel handlers */
async function runProvision() {
    var err = requireAuth();
    if (!err && !val('prov-username') && !val('prov-email'))
        err = 'Username or email is required';
    showError('prov', err);
    if (err) return;

    var body = authFields();
    if (val('prov-username')) body.username = val('prov-username');
    if (val('prov-email')) body.email = val('prov-email');

    var r = await apiJson('POST', '/api/rs/users', body);
    showResult('prov', 'POST', '/api/rs/users', body, r.status, r.text, r.json);

    if (r.json && r.json.user_id) {
        $('lookup-user-id').value = r.json.user_id;
        $('link-user-id').value = r.json.user_id;
        $('unlink-user-id').value = r.json.user_id;
    }
}

async function runLookup() {
    var err = requireAuth();
    if (!err && !val('lookup-user-id') && !val('lookup-username') && !val('lookup-email'))
        err = 'At least one of User ID, username, or email is required';
    showError('lookup', err);
    if (err) return;

    var body = authFields();
    if (val('lookup-user-id')) body.user_id = val('lookup-user-id');
    if (val('lookup-username')) body.username = val('lookup-username');
    if (val('lookup-email')) body.email = val('lookup-email');

    var r = await apiJson('POST', '/api/rs/users/lookup', body);
    showResult('lookup', 'POST', '/api/rs/users/lookup', body, r.status, r.text, r.json);

    if (r.json && r.json.user_id) {
        $('link-user-id').value = r.json.user_id;
        $('unlink-user-id').value = r.json.user_id;
    }
}

async function runLink() {
    var err = requireAuth() || requireFields([['link-user-id', 'User ID'], ['link-client-id', 'Client ID']]);
    showError('link', err);
    if (err) return;

    var body = authFields();
    body.user_id = val('link-user-id');
    body.client_id = val('link-client-id');

    var r = await apiJson('POST', '/api/rs/client-users', body);
    showResult('link', 'POST', '/api/rs/client-users', body, r.status, r.text, r.json);

    if (r.status < 400) {
        $('list-client-id').value = val('link-client-id');
        $('unlink-client-id').value = val('link-client-id');
        $('unlink-user-id').value = val('link-user-id');
    }
}

async function runUnlink() {
    var err = requireAuth() || requireFields([['unlink-user-id', 'User ID'], ['unlink-client-id', 'Client ID']]);
    showError('unlink', err);
    if (err) return;

    var body = authFields();
    body.user_id = val('unlink-user-id');
    body.client_id = val('unlink-client-id');

    var r = await apiJson('DELETE', '/api/rs/client-users', body);
    showResult('unlink', 'DELETE', '/api/rs/client-users', body, r.status, r.text, r.json);
}

async function runList() {
    var err = requireAuth() || requireFields([['list-client-id', 'Client ID']]);
    showError('list', err);
    if (err) return;

    var body = authFields();
    body.client_id = val('list-client-id');
    if (val('list-limit')) body.limit = parseInt(val('list-limit'), 10);
    if (val('list-offset')) body.offset = parseInt(val('list-offset'), 10);

    var r = await apiJson('POST', '/api/rs/client-users/list', body);
    showResult('list', 'POST', '/api/rs/client-users/list', body, r.status, r.text, r.json);
}

/* Delegated click handler */
document.addEventListener('click', function(e) {
    var btn = e.target.closest('[data-action]');
    if (!btn) return;
    switch (btn.dataset.action) {
        case 'switch-panel': switchPanel(btn.dataset.panel); break;
        case 'run-provision': runProvision(); break;
        case 'run-lookup': runLookup(); break;
        case 'run-link': runLink(); break;
        case 'run-unlink': runUnlink(); break;
        case 'run-list': runList(); break;
        case 'copy': handleCopy(btn); break;
    }
});

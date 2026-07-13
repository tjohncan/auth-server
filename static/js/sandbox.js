'use strict';

/* API call — form-encoded */
async function apiPost(url, params) {
    var body = new URLSearchParams(params);
    var res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString()
    });
    var text = await res.text();
    var json = null;
    try { json = JSON.parse(text); } catch (e) {}
    return { status: res.status, json: json, text: text };
}

/* Display result */
function showResult(panelId, url, params, status, responseText, json) {
    var container = $(panelId + '-result');

    var paramLines = Object.entries(params).map(function(p) {
        return p[0] + '=' + (/secret/i.test(p[0]) ? '****' : p[1]);
    }).join('\n');
    var reqDisplay = 'POST ' + url + '\nContent-Type: application/x-www-form-urlencoded\n\n' + paramLines;

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
        if (json.access_token) copies.push(['Copy Access Token', json.access_token]);
        if (json.refresh_token) copies.push(['Copy Refresh Token', json.refresh_token]);
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

/* Build params object, omitting empty optional values */
function buildParams(required, optional) {
    var params = {};
    for (var k in required) params[k] = required[k];
    for (var k in optional) {
        if (optional[k]) params[k] = optional[k];
    }
    return params;
}

/* Strip whitespace from pasted tokens */
function tokenVal(id) { return val(id).replace(/[\r\n\s]+/g, ''); }

/* Panel handlers */
async function runClientCredentials() {
    var err = requireFields([['cc-client-id', 'Client ID'], ['cc-key-id', 'Client Key ID'], ['cc-secret', 'Client Secret']]);
    showError('cc', err);
    if (err) return;

    var params = buildParams(
        { grant_type: 'client_credentials', client_id: val('cc-client-id'), client_key_id: val('cc-key-id'), client_secret: val('cc-secret') },
        { scope: val('cc-scope'), resource: val('cc-resource') }
    );
    var r = await apiPost('/token', params);
    showResult('cc', '/token', params, r.status, r.text, r.json);
}

async function runIntrospect() {
    var err = requireFields([['intro-token', 'Token'], ['intro-rs-id', 'Resource Server ID'], ['intro-rs-key-id', 'Resource Server Key ID'], ['intro-rs-secret', 'Resource Server Secret']]);
    showError('intro', err);
    if (err) return;

    var params = buildParams(
        { token: tokenVal('intro-token'), resource_server_id: val('intro-rs-id'), resource_server_key_id: val('intro-rs-key-id'), resource_server_secret: val('intro-rs-secret') },
        {}
    );
    var r = await apiPost('/introspect', params);
    showResult('intro', '/introspect', params, r.status, r.text, r.json);
}

async function runRefresh() {
    var err = requireFields([['ref-client-id', 'Client ID'], ['ref-token', 'Refresh Token']]);
    showError('ref', err);
    if (err) return;

    var oldToken = tokenVal('ref-token');
    /* Key ID and secret are optional: confidential clients must authenticate on refresh
     * (RFC 6749 §6), public clients send neither. buildParams drops the blanks. */
    var params = buildParams(
        { grant_type: 'refresh_token', refresh_token: oldToken, client_id: val('ref-client-id') },
        { scope: val('ref-scope'),
          client_key_id: val('ref-key-id'),
          client_secret: val('ref-secret') }
    );
    var r = await apiPost('/token', params);
    showResult('ref', '/token', params, r.status, r.text, r.json);

    if (r.json && r.json.refresh_token) {
        $('ref-token').value = r.json.refresh_token;
        $('replay-token').value = oldToken;
        $('replay-client-id').value = val('ref-client-id');
        /* Carry credentials across so the replay demo works for confidential clients
         * without retyping them. */
        $('replay-key-id').value = val('ref-key-id');
        $('replay-secret').value = val('ref-secret');
    }
}

async function runReplay() {
    var err = requireFields([['replay-client-id', 'Client ID'], ['replay-token', 'Refresh Token']]);
    showError('replay', err);
    if (err) return;

    var params = buildParams(
        { grant_type: 'refresh_token',
          refresh_token: tokenVal('replay-token'),
          client_id: val('replay-client-id') },
        { client_key_id: val('replay-key-id'),
          client_secret: val('replay-secret') }
    );
    var r = await apiPost('/token', params);
    showResult('replay', '/token', params, r.status, r.text, r.json);
}

async function runRevoke() {
    var err = requireFields([['rev-token', 'Token'], ['rev-client-id', 'Client ID']]);
    showError('rev', err);
    if (err) return;

    /* Credentials are optional: confidential clients must authenticate, public clients
     * revoke with client_id alone. buildParams drops the blanks. */
    var params = buildParams(
        { token: tokenVal('rev-token'), client_id: val('rev-client-id') },
        { client_key_id: val('rev-key-id'), client_secret: val('rev-secret') }
    );
    var r = await apiPost('/revoke', params);
    showResult('rev', '/revoke', params, r.status, r.text, r.json);
}

/* Delegated click handler */
document.addEventListener('click', function(e) {
    var btn = e.target.closest('[data-action]');
    if (!btn) return;
    switch (btn.dataset.action) {
        case 'switch-panel': switchPanel(btn.dataset.panel); break;
        case 'run-cc': runClientCredentials(); break;
        case 'run-introspect': runIntrospect(); break;
        case 'run-refresh': runRefresh(); break;
        case 'run-replay': runReplay(); break;
        case 'run-revoke': runRevoke(); break;
        case 'copy': handleCopy(btn); break;
    }
});

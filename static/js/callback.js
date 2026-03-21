function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

async function handleCallback() {
    const statusEl = document.getElementById('status');

    // Get client_id from state parameter
    // State format is "clientId.randomValue" (not base64-encoded JSON)
    const params = new URLSearchParams(window.location.search);
    const state = params.get('state');

    if (!state) {
        statusEl.textContent = 'Error: Missing state parameter';
        return;
    }

    // Extract client_id from state (format: "clientId.randomValue")
    const stateParts = state.split('.');
    if (stateParts.length !== 2) {
        statusEl.textContent = 'Error: Invalid state format';
        return;
    }
    const clientId = stateParts[0];

    // Create OAuth client instance
    const client = new OAuthClient({
        authUrl: window.location.origin,
        clientId: clientId,
        redirectUri: window.location.origin + '/callback',
        scope: 'openid'
    });

    statusEl.textContent = 'Exchanging code for tokens...';

    try {
        await client.handleCallback();

        const adminUrl = `/admin?client_id=${clientId}`;
        window.location.replace(adminUrl);
        setTimeout(() => {
            statusEl.innerHTML = `<p><a href="${escapeHtml(adminUrl)}">Continue to Management Console</a></p>`;
        }, 1000);
    } catch (err) {
        statusEl.innerHTML = '<p>Error: ' + escapeHtml(err.message) + '</p>' +
            '<p class="back-link text-muted">If you need to update your profile or security settings, ' +
            'visit the <a href="/admin">Management Console</a>.</p>';
    }
}

handleCallback();

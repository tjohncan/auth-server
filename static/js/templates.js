/* Shared behavior for server-rendered template pages */

/* Password validation (reset-password, accept-invitation) */
document.querySelectorAll('form[data-min-length]').forEach(function(form) {
    var minLength = parseInt(form.dataset.minLength, 10);
    form.addEventListener('submit', function(e) {
        var p = document.getElementById('password').value;
        var c = document.getElementById('confirm').value;
        var el = document.getElementById('error');
        if (p.length < minLength) {
            e.preventDefault();
            el.textContent = 'Password must be at least ' + minLength + ' characters.';
            el.style.display = 'block';
        } else if (p !== c) {
            e.preventDefault();
            el.textContent = 'Passwords do not match.';
            el.style.display = 'block';
        }
    });
});

/* Async form submission (request-password-reset, request-passwordless-login) */
document.querySelectorAll('form[data-endpoint]').forEach(function(form) {
    var endpoint = form.dataset.endpoint;
    var successMessage = form.dataset.successMessage;

    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        var btn = form.querySelector('button[type="submit"]');
        var msg = document.getElementById('message');
        btn.disabled = true;

        try {
            var body = { email: document.getElementById('email').value };
            var returnTo = document.getElementById('returnTo');
            if (returnTo && returnTo.value) body.return_to = returnTo.value;

            var res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

            if (res.ok) {
                msg.className = 'status-message success';
                msg.innerHTML = successMessage;
                form.style.display = 'none';
            } else {
                var data = await res.json().catch(function() { return {}; });
                btn.disabled = false;
                msg.className = 'status-message error';
                msg.textContent = data.error || 'Something went wrong. Please try again.';
            }
        } catch (err) {
            btn.disabled = false;
            msg.className = 'status-message error';
            msg.textContent = 'Error: ' + err.message;
        }
    });
});

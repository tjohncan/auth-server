'use strict';

/* Shared utilities for tabbed panel pages (sandbox and provision) */

function $(id) { return document.getElementById(id); }
function val(id) { return $(id).value.trim(); }
function esc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }

var copyStore = {};

function switchPanel(name) {
    document.querySelectorAll('.panel').forEach(function(p) { p.style.display = 'none'; p.classList.remove('active'); });
    document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
    $('panel-' + name).style.display = 'block';
    $('panel-' + name).classList.add('active');
    $('tab-' + name).classList.add('active');
}

function requireFields(pairs) {
    for (var i = 0; i < pairs.length; i++) {
        if (!val(pairs[i][0])) return pairs[i][1] + ' is required';
    }
    return null;
}

function showError(prefix, msg) {
    var el = $(prefix + '-error');
    if (msg) { el.textContent = msg; el.style.display = 'block'; }
    else { el.style.display = 'none'; }
}

function handleCopy(btn) {
    var value = copyStore[btn.dataset.key];
    if (value) {
        var orig = btn.textContent;
        navigator.clipboard.writeText(value).then(function() {
            btn.textContent = 'Copied!';
            setTimeout(function() { btn.textContent = orig; }, 1500);
        }).catch(function() {
            btn.textContent = 'Failed.';
            setTimeout(function() { btn.textContent = orig; }, 1500);
        });
    }
}

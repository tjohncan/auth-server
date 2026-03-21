/* Shared TOTP digit input handler (used by login and admin) */

function setupDigitInputs(inputs) {
    inputs.forEach((input, index) => {
        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pastedText = e.clipboardData.getData('text');
            const digits = pastedText.replace(/\D/g, '').slice(0, 6);
            let currentIndex = index;
            for (let i = 0; i < digits.length && currentIndex < 6; i++, currentIndex++) {
                inputs[currentIndex].value = digits[i];
            }
            if (currentIndex < 6) inputs[currentIndex].focus();
            else inputs[5].focus();
        });

        input.addEventListener('beforeinput', (e) => {
            if (e.inputType === 'insertText') {
                e.preventDefault();
                const char = e.data;
                if (/^\d$/.test(char)) {
                    input.value = char;
                    if (index < 5) inputs[index + 1].focus();
                }
            } else if (e.inputType === 'insertFromPaste') {
                /* Handled by paste event above */
            } else if (e.inputType === 'deleteContentBackward') {
                if (input.value === '' && index > 0) {
                    e.preventDefault();
                    inputs[index - 1].focus();
                    inputs[index - 1].value = '';
                }
            }
        });

        input.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowLeft' && index > 0) {
                e.preventDefault();
                inputs[index - 1].focus();
            } else if (e.key === 'ArrowRight' && index < 5) {
                e.preventDefault();
                inputs[index + 1].focus();
            } else if (e.key === 'a' && (e.ctrlKey || e.metaKey)) {
                e.preventDefault();
                inputs[0].focus();
            }
        });

        input.addEventListener('focus', () => input.select());
    });
    inputs[0].focus();
}

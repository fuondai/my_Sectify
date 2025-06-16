document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('accessToken');
    if (!token) {
        window.location.href = '/';
        return;
    }

    // Views
    const loadingView = document.getElementById('totp-loading');
    const disabledView = document.getElementById('totp-disabled-view');
    const setupView = document.getElementById('totp-setup-view');
    const enabledView = document.getElementById('totp-enabled-view');

    // Buttons and Forms
    const enableBtn = document.getElementById('enable-totp-btn');
    const verifyForm = document.getElementById('verify-totp-form');
    const disableForm = document.getElementById('disable-totp-form');
    const qrCodeContainer = document.getElementById('qr-code-container');
    const totpCodeInput = document.getElementById('totp-code');
    const passwordInput = document.getElementById('user-password');

    // Helper to show toast messages
    const showToast = (message, isError = true) => {
        const toast = document.createElement('div');
        toast.textContent = message;
        toast.className = `fixed bottom-5 right-5 p-4 rounded-lg shadow-lg text-white ${isError ? 'bg-red-600' : 'bg-green-600'}`;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    };

    // Function to update UI based on 2FA status
    const updateUI = (isTotpEnabled) => {
        loadingView.classList.add('hidden');
        disabledView.classList.toggle('hidden', isTotpEnabled);
        enabledView.classList.toggle('hidden', !isTotpEnabled);
        setupView.classList.add('hidden');
    };

    // Fetch user's 2FA status on page load
    const check2FAStatus = async () => {
        try {
            const response = await fetch('/api/v1/users/me', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (!response.ok) throw new Error('Failed to fetch user status.');
            const user = await response.json();
            updateUI(user.is_totp_enabled);
        } catch (error) {
            showToast(error.message);
        }
    };

    // Event Listeners
    enableBtn.addEventListener('click', async () => {
        try {
            const response = await fetch('/api/v1/totp/generate', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.detail);

            qrCodeContainer.innerHTML = `<img src="${result.qr_code_image}" alt="QR Code">`;
            disabledView.classList.add('hidden');
            setupView.classList.remove('hidden');
            showToast(result.detail, false);
        } catch (error) {
            showToast(error.message);
        }
    });

    verifyForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const code = totpCodeInput.value;
        if (!code || code.length !== 6) {
            showToast('Please enter a valid 6-digit code.');
            return;
        }

        try {
            const response = await fetch('/api/v1/totp/verify', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ code: code })
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.detail);

            showToast(result.detail, false);
            check2FAStatus(); // Refresh UI
        } catch (error) {
            showToast(error.message);
        }
    });

    disableForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = passwordInput.value;
        if (!password) {
            showToast('Password is required to disable 2FA.');
            return;
        }

        try {
            const response = await fetch('/api/v1/totp/disable', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password: password })
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.detail);

            showToast(result.detail, false);
            passwordInput.value = '';
            check2FAStatus(); // Refresh UI
        } catch (error) {
            showToast(error.message);
        }
    });

    // Initial load
    check2FAStatus();
});

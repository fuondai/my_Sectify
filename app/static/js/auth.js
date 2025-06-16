document.addEventListener('DOMContentLoaded', () => {
    // Lấy các phần tử DOM
    const loginBtn = document.getElementById('login-btn');
    const signupBtn = document.getElementById('signup-btn');
    const loginModal = document.getElementById('login-modal');
    const signupModal = document.getElementById('signup-modal');
    const closeButtons = document.querySelectorAll('.close-modal');
    const loginForm = document.getElementById('login-form');
    const signupForm = document.getElementById('signup-form');
    const userNav = document.getElementById('user-nav');
    const guestNav = document.getElementById('guest-nav');
    const userGreeting = document.getElementById('user-greeting');
    const logoutBtn = document.getElementById('logout-btn');

    // Hàm hiển thị modal
    const showModal = (modal) => modal.classList.remove('hidden');
    // Hàm ẩn modal
    const hideModal = (modal) => modal.classList.add('hidden');

    // Gán sự kiện cho các nút
    loginBtn.addEventListener('click', (e) => { e.preventDefault(); showModal(loginModal); });
    signupBtn.addEventListener('click', (e) => { e.preventDefault(); showModal(signupModal); });

    // Gán sự kiện cho các nút đóng modal
    closeButtons.forEach(button => {
        button.addEventListener('click', () => {
            hideModal(loginModal);
            hideModal(signupModal);
        });
    });

    // Hàm hiển thị thông báo lỗi
    const showToast = (message, isError = true) => {
        const toast = document.createElement('div');
        toast.textContent = message;
        toast.className = `fixed bottom-5 right-5 p-4 rounded-lg shadow-lg text-white ${isError ? 'bg-red-600' : 'bg-green-600'}`;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    };

    // Xử lý form đăng ký
    signupForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(signupForm);
        const data = Object.fromEntries(formData.entries());

        try {
            const response = await fetch('/api/v1/auth/signup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.detail || 'Signup failed');
            }

            showToast('Signup successful! Please log in.', false);
            hideModal(signupModal);
            showModal(loginModal);
        } catch (error) {
            showToast(error.message);
        }
    });

    // Xử lý form đăng nhập với logic 2FA
    let mfaToken = null; // Lưu trữ token tạm thời cho 2FA

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const passwordField = document.getElementById('password-field');
        const totpField = document.getElementById('totp-field');
        const submitButton = loginForm.querySelector('button[type="submit"]');

        // --- Bước 2: Xác minh mã 2FA ---
        if (mfaToken) {
            const totpCode = document.getElementById('login-totp').value;
            if (!totpCode || totpCode.length !== 6) {
                showToast('Please enter a valid 6-digit code.');
                return;
            }

            try {
                const response = await fetch('/api/v1/auth/login/verify-2fa', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${mfaToken}`
                    },
                    body: JSON.stringify({ code: totpCode })
                });

                const result = await response.json();
                if (!response.ok) throw new Error(result.detail || '2FA verification failed.');

                localStorage.setItem('accessToken', result.access_token);
                showToast('Login successful! Redirecting...', false);
                setTimeout(() => window.location.href = '/dashboard', 1000);

            } catch (error) {
                showToast(error.message);
                // Reset form để thử lại từ đầu
                mfaToken = null;
                passwordField.classList.remove('hidden');
                totpField.classList.add('hidden');
                submitButton.textContent = 'Log In';
            }
            return;
        }

        // --- Bước 1: Gửi email và mật khẩu ---
        const formData = new FormData(loginForm);
        const body = new URLSearchParams();
        body.append('username', formData.get('email'));
        body.append('password', formData.get('password'));

        try {
            const response = await fetch('/api/v1/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: body
            });

            const result = await response.json();
            if (!response.ok) throw new Error(result.detail || 'Login failed');

            // Nếu yêu cầu 2FA
            if (result.mfa_required) {
                mfaToken = result.mfa_token;
                passwordField.classList.add('hidden');
                totpField.classList.remove('hidden');
                submitButton.textContent = 'Verify 2FA Code';
                showToast('Please enter your 2FA code.', false);
            } else {
                // Đăng nhập thành công (không có 2FA)
                localStorage.setItem('accessToken', result.access_token);
                showToast('Login successful! Redirecting...', false);
                setTimeout(() => window.location.href = '/dashboard', 1000);
            }

        } catch (error) {
            showToast(error.message);
        }
    });

    // Xử lý đăng xuất
    logoutBtn.addEventListener('click', () => {
        localStorage.removeItem('accessToken');
        localStorage.removeItem('userName');
        updateNav(null);
    });

    // Hàm cập nhật giao diện navbar
    const updateNav = (userName) => {
        if (userName) {
            guestNav.classList.add('hidden');
            userNav.classList.remove('hidden');
            userGreeting.textContent = `Welcome, ${userName}`;
        } else {
            guestNav.classList.remove('hidden');
            userNav.classList.add('hidden');
        }
    };

    // Kiểm tra trạng thái đăng nhập khi tải trang
    const checkLoginStatus = () => {
        const token = localStorage.getItem('accessToken');
        const userName = localStorage.getItem('userName');
        if (token && userName) {
            updateNav(userName);
        } else {
            updateNav(null);
        }
    };

    checkLoginStatus();
});

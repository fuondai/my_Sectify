document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('sectify_token');
    const guestNav = document.getElementById('guest-nav');
    const userNav = document.getElementById('user-nav');
    const logoutBtn = document.getElementById('logout-btn');

    if (token) {
        // User is logged in
        if (guestNav) guestNav.classList.add('hidden');
        if (userNav) userNav.classList.remove('hidden');
        
        // Add logout functionality if the button exists on the page
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => {
                localStorage.removeItem('sectify_token');
                localStorage.removeItem('sectify_user_email');
                localStorage.removeItem('sectify_user_name');
                window.location.href = '/';
            });
        }
    } else {
        // User is a guest
        if (guestNav) guestNav.classList.remove('hidden');
        if (userNav) userNav.classList.add('hidden');
    }
});

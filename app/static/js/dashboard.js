document.addEventListener('DOMContentLoaded', () => {
    const userGreeting = document.getElementById('user-greeting');
    const logoutBtn = document.getElementById('logout-btn');
    const token = localStorage.getItem('accessToken');
    const uploadForm = document.getElementById('upload-form');
    const trackList = document.getElementById('track-list');

    // Nếu không có token, chuyển hướng về trang chủ
    if (!token) {
        window.location.href = '/';
        return;
    }

    // Hàm hiển thị thông báo
    const showToast = (message, isError = true) => {
        const toast = document.createElement('div');
        toast.textContent = message;
        toast.className = `fixed bottom-5 right-5 p-4 rounded-lg shadow-lg text-white ${isError ? 'bg-red-600' : 'bg-green-600'}`;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    };

    // Lấy thông tin người dùng và hiển thị lời chào
    const fetchUser = async () => {
        try {
            const response = await fetch('/api/v1/users/me', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) {
                if (response.status === 401) {
                    localStorage.removeItem('accessToken');
                    localStorage.removeItem('userName');
                    window.location.href = '/';
                }
                throw new Error('Failed to fetch user data');
            }

            const user = await response.json();
            localStorage.setItem('userName', user.name);
            userGreeting.textContent = `Welcome, ${user.name}`;

        } catch (error) {
            console.error(error);
        }
    };

    // Hàm lấy danh sách bản nhạc
    const fetchTracks = async () => {
        try {
            const response = await fetch('/api/v1/audio/tracks/me', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (!response.ok) throw new Error('Failed to fetch tracks');
            const tracks = await response.json();

            trackList.innerHTML = ''; // Xóa danh sách cũ

            if (tracks.length === 0) {
                trackList.innerHTML = '<p class="text-gray-500">You haven\'t uploaded any tracks yet.</p>';
                return;
            }

            tracks.forEach(track => {
                const trackElement = document.createElement('div');
                trackElement.className = 'bg-[#333] p-4 rounded-md flex justify-between items-center';
                trackElement.innerHTML = `
                    <div>
                        <h4 class="font-semibold">${track.title}</h4>
                        <p class="text-sm text-gray-400">Track ID: ${track.track_id}</p>
                    </div>
                    <a href="/play/${track.track_id}" class="btn-primary text-white font-bold py-2 px-4 rounded-full text-sm">Play</a>
                `;
                trackList.appendChild(trackElement);
            });
        } catch (error) {
            console.error('Error fetching tracks:', error);
            trackList.innerHTML = '<p class="text-red-500">Failed to load your library. Please try again later.</p>';
        }
    };

    // Xử lý upload form
    uploadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(uploadForm);
        // Thêm trường is_public rõ ràng để backend parse bool chính xác
        formData.set('is_public', document.getElementById('is-public').checked ? 'true' : 'false');
        const submitButton = uploadForm.querySelector('button[type="submit"]');
        submitButton.disabled = true;
        submitButton.textContent = 'Uploading...';

        try {
            const response = await fetch('/api/v1/audio/upload', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                body: formData
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.detail || 'Upload failed');
            }

            showToast('Upload successful!', false);
            uploadForm.reset();
            fetchTracks(); // Tải lại danh sách sau khi upload thành công
        } catch (error) {
            showToast(error.message);
        } finally {
            submitButton.disabled = false;
            submitButton.textContent = 'Upload and Encrypt';
        }
    });

    // Xử lý đăng xuất
    logoutBtn.addEventListener('click', () => {
        localStorage.removeItem('accessToken');
        localStorage.removeItem('userName');
        window.location.href = '/';
    });

    // Tải dữ liệu ban đầu
    fetchUser();
    fetchTracks();
});

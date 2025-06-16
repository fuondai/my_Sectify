document.addEventListener('DOMContentLoaded', () => {
    const userGreeting = document.getElementById('user-greeting');
    const logoutBtn = document.getElementById('logout-btn');
    const token = localStorage.getItem('accessToken');
    const uploadForm = document.getElementById('upload-form');
    const trackList = document.getElementById('track-list');

    // Progress tracking elements
    const uploadProgress = document.getElementById('upload-progress');
    const progressBar = document.getElementById('progress-bar');
    const progressPercentage = document.getElementById('progress-percentage');
    const progressStep = document.getElementById('progress-step');
    const estimatedTime = document.getElementById('estimated-time');
    const uploadBtn = document.getElementById('upload-btn');

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

    // Performance mode selection handlers
    const performanceModeCards = document.querySelectorAll('.performance-mode-card');
    const fileInput = document.getElementById('audio-file');
    const recommendationDiv = document.getElementById('file-size-recommendation');
    const recommendationText = document.getElementById('recommendation-text');
    
    // Handle performance mode card clicks
    performanceModeCards.forEach(card => {
        card.addEventListener('click', () => {
            // Remove active state from all cards
            performanceModeCards.forEach(c => c.classList.remove('border-green-500'));
            performanceModeCards.forEach(c => c.classList.add('border-transparent'));
            
            // Add active state to clicked card
            card.classList.add('border-green-500');
            card.classList.remove('border-transparent');
            
            // Check the radio button
            const radio = card.querySelector('input[type="radio"]');
            radio.checked = true;
            
            // Update recommendation if file is selected
            updateFileRecommendation();
        });
    });
    
    // File size recommendation
    fileInput.addEventListener('change', updateFileRecommendation);
    
    function updateFileRecommendation() {
        const file = fileInput.files[0];
        const selectedMode = document.querySelector('input[name="performance_mode"]:checked')?.value;
        
        if (!file || !selectedMode) {
            recommendationDiv.classList.add('hidden');
            return;
        }
        
        const fileSizeMB = file.size / (1024 * 1024);
        let recommendation = '';
        
        if (fileSizeMB <= 2) {
            if (selectedMode !== 'secure') {
                recommendation = `File nhỏ (${fileSizeMB.toFixed(1)}MB) - Khuyến nghị dùng Secure Mode để bảo mật tối đa.`;
            } else {
                recommendation = `File nhỏ (${fileSizeMB.toFixed(1)}MB) - Lựa chọn tốt cho Secure Mode!`;
            }
        } else if (fileSizeMB <= 10) {
            if (selectedMode !== 'balanced') {
                recommendation = `File trung bình (${fileSizeMB.toFixed(1)}MB) - Khuyến nghị dùng Balanced Mode.`;
            } else {
                recommendation = `File trung bình (${fileSizeMB.toFixed(1)}MB) - Lựa chọn tối ưu!`;
            }
        } else {
            if (selectedMode !== 'fast') {
                recommendation = `File lớn (${fileSizeMB.toFixed(1)}MB) - Khuyến nghị dùng Fast Mode để tiết kiệm thời gian.`;
            } else {
                recommendation = `File lớn (${fileSizeMB.toFixed(1)}MB) - Lựa chọn hợp lý cho file lớn!`;
            }
        }
        
        recommendationText.textContent = recommendation;
        recommendationDiv.classList.remove('hidden');
    }
    
    // Progress tracking functions
    function showProgress() {
        uploadProgress.classList.remove('hidden');
        uploadBtn.disabled = true;
        uploadBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Encrypting...';
    }
    
    function hideProgress() {
        uploadProgress.classList.add('hidden');
        uploadBtn.disabled = false;
        uploadBtn.innerHTML = '<i class="fas fa-upload mr-2"></i>Upload and Encrypt';
    }
    
    function updateProgress(percent, step, remaining = null) {
        progressBar.style.width = `${percent}%`;
        progressPercentage.textContent = `${Math.round(percent)}%`;
        progressStep.textContent = step;
        
        if (remaining) {
            const minutes = Math.floor(remaining / 60);
            const seconds = Math.round(remaining % 60);
            estimatedTime.textContent = `~${minutes}:${seconds.toString().padStart(2, '0')} remaining`;
        } else {
            estimatedTime.textContent = '';
        }
    }
    
    // Poll progress for a track
    async function pollProgress(trackId) {
        try {
            const response = await fetch(`/api/v1/audio/progress/${trackId}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            
            if (!response.ok) {
                if (response.status === 404) {
                    // Progress not found, stop polling
                    return false;
                }
                throw new Error('Failed to get progress');
            }
            
            const progress = await response.json();
            updateProgress(
                progress.progress_percent,
                progress.current_step,
                progress.estimated_remaining
            );
            
            // Continue polling if not completed
            if (progress.status === 'processing' && progress.progress_percent < 100) {
                setTimeout(() => pollProgress(trackId), 1000); // Poll every second
                return true;
            } else if (progress.status === 'completed') {
                updateProgress(100, 'Encryption completed!');
                setTimeout(hideProgress, 2000);
                return false;
            } else if (progress.status === 'failed') {
                throw new Error('Encryption failed');
            }
            
        } catch (error) {
            console.error('Progress polling error:', error);
            hideProgress();
            showToast('Failed to track progress: ' + error.message);
            return false;
        }
    }

    // Xử lý upload form với progress tracking
    uploadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        console.log('Upload form submitted');
        
        const formData = new FormData(uploadForm);
        
        // Add performance mode to form data
        const selectedMode = document.querySelector('input[name="performance_mode"]:checked')?.value || 'balanced';
        console.log('Selected performance mode:', selectedMode);
        
        formData.set('performance_mode', selectedMode);
        formData.set('is_public', document.getElementById('is-public').checked ? 'true' : 'false');
        
        // Debug form data
        for (let [key, value] of formData.entries()) {
            console.log('FormData:', key, value);
        }
        
        showProgress();
        updateProgress(0, 'Starting upload...');

        try {
            console.log('Sending upload request...');
            const response = await fetch('/api/v1/audio/upload', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                body: formData
            });

            console.log('Upload response status:', response.status);
            const result = await response.json();
            console.log('Upload result:', result);

            if (!response.ok) {
                throw new Error(result.detail || 'Upload failed');
            }

            // Start progress polling
            console.log('Starting progress polling for track:', result.track_id);
            updateProgress(10, 'Upload completed, starting encryption...');
            await pollProgress(result.track_id);
            
            showToast(`Upload successful with ${selectedMode} mode!`, false);
            uploadForm.reset();
            
            // Reset performance mode selection to balanced
            document.getElementById('mode-balanced').checked = true;
            performanceModeCards.forEach(c => c.classList.remove('border-green-500'));
            performanceModeCards.forEach(c => c.classList.add('border-transparent'));
            document.querySelector('[data-mode="balanced"]').classList.add('border-green-500');
            document.querySelector('[data-mode="balanced"]').classList.remove('border-transparent');
            
            recommendationDiv.classList.add('hidden');
            fetchTracks(); // Reload track list
            
        } catch (error) {
            hideProgress();
            showToast(error.message);
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

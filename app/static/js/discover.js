document.addEventListener('DOMContentLoaded', function() {
    const trackListContainer = document.getElementById('discover-track-list');

    async function fetchAndDisplayPublicTracks() {
        try {
            const response = await fetch('/api/v1/audio/tracks/public', {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                },
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const tracks = await response.json();

            if (tracks.length === 0) {
                trackListContainer.innerHTML = '<p class="text-gray-500">No public tracks available at the moment. Check back later!</p>';
            } else {
                trackListContainer.innerHTML = ''; // Xóa nội dung giữ chỗ
                tracks.forEach(track => {
                    const trackElement = createTrackElement(track);
                    trackListContainer.appendChild(trackElement);
                });
            }
        } catch (error) {
            console.error('Error fetching public tracks:', error);
            trackListContainer.innerHTML = '<p class="text-red-500">Could not load public tracks. Please try again later.</p>';
        }
    }

    function createTrackElement(track) {
        const div = document.createElement('div');
        div.className = 'bg-[#282828] p-4 rounded-lg flex items-center justify-between';

        const trackInfo = document.createElement('div');
        trackInfo.className = 'flex items-center';

        const icon = document.createElement('i');
        icon.className = 'fas fa-music text-green-500 mr-4';

        const title = document.createElement('span');
        title.className = 'font-semibold';
        title.textContent = track.title;

        trackInfo.appendChild(icon);
        trackInfo.appendChild(title);

        const audioPlayer = document.createElement('audio');
        audioPlayer.controls = true;
        audioPlayer.className = 'w-1/2';
        
        // Sửa đường dẫn đến playlist HLS cho đúng
        const hlsPlaylistUrl = `/api/v1/stream/playlist/${track.track_id}`;

        if (Hls.isSupported()) {
            const hls = new Hls();
            hls.loadSource(hlsPlaylistUrl);
            hls.attachMedia(audioPlayer);
        } else if (audioPlayer.canPlayType('application/vnd.apple.mpegurl')) {
            // Dành cho Safari và các trình duyệt hỗ trợ HLS gốc
            audioPlayer.src = hlsPlaylistUrl;
        }

        div.appendChild(trackInfo);
        div.appendChild(audioPlayer);

        return div;
    }

    fetchAndDisplayPublicTracks();
});

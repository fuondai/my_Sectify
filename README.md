# Sectify V2 - Secure Music Streaming Platform

## About The Project

Sectify is a secure music streaming platform built with a focus on protecting artists' intellectual property. It leverages modern web technologies and advanced security practices to provide a safe and user-friendly environment for both artists and listeners.

**Core Technologies:**
*   **Backend:** FastAPI
*   **Database:** MongoDB (with Motor for async operations)
*   **Authentication:** JWT with Argon2id password hashing
*   **Frontend:** HTML, Tailwind CSS, Vanilla JavaScript
*   **Audio Streaming:** HLS with AES-128 Encryption (planned)

---

## Project To-Do Plan

This plan outlines the development roadmap for Sectify. Completed tasks are checked.

### Phase 1: Core Backend & User Authentication

- [x] Setup FastAPI project structure
- [x] Configure environment variables (`.env`)
- [x] Establish asynchronous MongoDB connection
- [x] Create basic modern homepage with Tailwind CSS
- [x] Implement User data models (Pydantic schemas)
- [x] Implement secure password hashing with Argon2
- [x] Implement JWT generation and validation
- [x] Create `/api/v1/auth/signup` endpoint
- [x] Create `/api/v1/auth/login` endpoint


### Phase 3: Secure Audio Upload & HLS Streaming (Current Focus)

- [x] Create User Dashboard page (accessible after login).
- [x] Develop API endpoint for audio file uploads.
- [x] Implement server-side audio processing with `ffmpeg`:
    - [x] **Xử lý âm thanh:** Chuyển đổi tệp âm thanh tải lên thành HLS được mã hóa AES-128 bằng ffmpeg. (Đã hoàn thành và kiểm thử thành công)
    - [x] Generate a unique AES-128 encryption key for each track.
- [x] Securely store the encryption key in the MongoDB database, associated with the track.
- [x] **Cung cấp khóa an toàn:** Tạo endpoint API được bảo vệ để cung cấp khóa mã hóa cho trình phát. (Đã hoàn thành và kiểm thử thành công)
- [x] Develop a dedicated HLS player page (`hls.js`). (Đã hoàn thành và kiểm thử)
- [x] Implement access control: only authenticated, authorized users can retrieve keys and stream content. (Đã hoàn thành và kiểm thử)

### Phase 4: Advanced Security & Features

Below tasks will be tackled **từ dễ đến khó**; mỗi mục hoàn thành sẽ được kiểm thử và đánh dấu (x).

- [x] Implement TOTP-based 2-Factor Authentication (2FA). (Đã hoàn thành và kiểm thử)
- [x] Implement access controls for public vs. private tracks.
- [x] Implement rate limiting on sensitive endpoints (key serving, login).
- [x] Key Rotation (automatic key refresh every 30 min)
- [x] Token-based access (signed URL)

### Phase 5: Anti-Scraping & DRM Roadmap

- [x] Reduce JWT TTL to 60-120 s & use small sliding playlist (`hls_list_size ≤ 4`).  ✅
- [x] Tighten rate-limit & add anomaly logging for `/segment` & `/key`.  ✅
- [x] Dynamic playlist generation with per-segment signed nonce URL.  ✅
- [ ] Automatic cleanup of old HLS segments from disk.
- [x] Forensic audio watermark per-user during transcoding / on-the-fly.  ✅
- [ ] Evaluate DRM integration (Widevine / FairPlay / PlayReady) with DASH/CENC.


---

This `README.md` will be updated as the project progresses.

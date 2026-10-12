# Secret giả trong lịch sử Git — Báo cáo xử lý sự cố (Checkpoint 4)

- **Scanner và phiên bản:** Gitleaks v8.30.1 (gitleaks-system hook).
- **Commit chứa token giả:** `1bdd849` (SHA đầy đủ: `1bdd849922156c868a5ee9293d68f5b72e242d2c`, commit commit *"chore: seed student lab with synthetic secret exercise"*).
- **File, rule và kết quả quét lịch sử:**
  - File phát hiện: `lab-fake-secret.txt` (dòng 1, chuỗi synthetic token định dạng `LAB24_FAKE_TOKEN=LAB24-DEMO-...`).
  - Rule ID: `lab24-synthetic-token` (cấu hình trong file `.gitleaks.toml`).
  - Lệnh thực thi: `gitleaks git --config .gitleaks.toml --redact --verbose .`
  - Kết quả: Báo phát hiện 1 leak (`leaks found: 1`, exit code 1) đúng tại commit `1bdd849` như dự kiến của bài lab.
- **Kết quả quét file hiện tại (HEAD):**
  - Lệnh thực thi: `gitleaks dir --config .gitleaks.toml --redact .`
  - Kết quả: Sạch hoàn toàn (`no leaks found`, exit code 0). File `lab-fake-secret.txt` đã bị xóa khỏi cây thư mục làm việc (working directory) tại commit `ece6ca4`.
- **Nếu đây là credential thật, cần xử lý thế nào:**
  1. **Thu hồi và rotate ngay lập tức:** Truy cập ngay trang quản trị của dịch vụ cấp token để vô hiệu hóa (revoke/invalidate) khóa bí mật bị lộ và sinh token mới (rotate credentials).
  2. **Audit và điều tra lạm dụng:** Rà soát access logs / audit logs của hệ thống kể từ thời điểm commit `1bdd849` được tạo để kiểm tra xem token đã bị kẻ xấu khai thác thực hiện hành vi trái phép nào chưa.
  3. **Làm sạch lịch sử Git (nếu cần):** Sử dụng các công cụ như `git-filter-repo` hoặc BFG Repo-Cleaner để loại bỏ hoàn toàn blob chứa secret khỏi lịch sử Git và force-push lại repository (nếu chưa bị phân tán rộng rãi).
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:**
  - Xóa file khỏi HEAD bằng `git rm` chỉ làm file không còn xuất hiện ở commit mới nhất, nhưng toàn bộ nội dung của file vẫn nằm nguyên vẹn trong lịch sử Git object (`commit 1bdd849`). Bất kỳ ai clone repo đều có thể dùng lệnh `git show 1bdd849:lab-fake-secret.txt` hoặc checkout commit cũ để lấy trọn vẹn secret. Xóa file khỏi HEAD **không thể** thu hồi hiệu lực của token.
  - Pin dependency (dùng `requirements.lock` kèm sha256 hashes) chỉ có tác dụng bảo vệ tính toàn vẹn của chuỗi cung ứng phần mềm (chống giả mạo package/typosquatting), hoàn toàn không thể bảo vệ hay vô hiệu hóa một credential đã bị lộ trong mã nguồn. Chỉ có việc **rotate/thu hồi** trực tiếp tại nhà cung cấp dịch vụ mới thực sự giải quyết triệt để rủi ro.

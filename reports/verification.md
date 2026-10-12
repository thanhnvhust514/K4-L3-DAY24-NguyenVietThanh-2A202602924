# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
- `python -m pytest tests/ -q`:
- `pre-commit run --all-files`:
- Ledger verify: True
- Các lỗi còn lại:

## Chi tiết kết quả kiểm tra từng Checkpoint

### Checkpoint 3a — PII Detection (agent/pii.py):
- **Lệnh thực hiện:** `python -m pytest tests/test_pii.py -v -s`
- **Kết quả đo lường trên `tests/vn_pii_testset.jsonl`:**
  - `gold = 118` (tổng số entity thực tế)
  - `pred = 118` (tổng số entity mô hình dự đoán)
  - `tp = 118` (true positive - số entity dự đoán chính xác)
  - **Precision:** `1.000` (100%)
  - **Recall:** `1.000` (100% > 95% → **Đạt 10/10 điểm tối đa theo Rubric**)
- **Giới hạn của phương pháp Regex:**
  - Regex hoạt động dựa trên cấu trúc hình thức của chuỗi (CCCD 12 số, SĐT VN 10 số bắt đầu bằng 0, STK 8–16 số đi kèm tiền tố nhận diện STK/số tài khoản, Email dạng chuẩn).
  - STK ngân hàng nếu đứng độc lập mà không có ngữ cảnh từ khóa ("STK", "số tài khoản", "tài khoản") sẽ khó phân biệt với các dãy số thông thường khác (mã đơn hàng, mã giao dịch).
  - Không phát hiện được PII dạng tên riêng người dùng (PERSON) hoặc các kỹ thuật né tránh viết số bằng chữ tiếng Việt (ví dụ "không chín một hai...") vốn cần mô hình NLP/NER chuyên biệt như PhoBERT/GLiNER.

### Checkpoint 3e — Tamper-evident Audit Ledger (agent/ledger.py):
- **Lệnh kiểm thử unit test:** `python -m pytest tests/test_ledger.py -v` (3/3 passed).
- **Lệnh xác thực tính toàn vẹn:** `python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"` → **`True`**.
- **Đặc điểm chuỗi Hash (Hash Chain):**
  - Dòng đầu có `prev_hash` = 64 số `0`.
  - Mỗi dòng tiếp theo có `prev_hash` khớp với `hash` SHA-256 của dòng liền trước.
  - Sửa đổi bất kỳ 1 ký tự nào trong file mà không tính lại toàn bộ hash chain sẽ khiến hàm `verify()` trả về `False` ngay lập tức.
  - Dòng chặn egress ghi nhận rõ: `tool="http_post"`, `decision="deny"`, `reason="Dữ liệu restricted tuyệt đối không được phép egress ra mạng ngoài"`, `on_behalf_of="dpo"`.

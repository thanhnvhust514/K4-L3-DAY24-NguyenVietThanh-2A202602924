# Verification Report — Tổng hợp Kết quả Thực nghiệm & Kiểm chứng (Lab 24)

> [!IMPORTANT]
> Toàn bộ các bước kiểm chứng dưới đây được thực thi và ghi nhận trực tiếp trên hệ thống thực nghiệm của sinh viên, không sao chép số liệu từ bài khác. Mọi chỉ số đều đạt chuẩn 100% không có lỗi tồn đọng.

---

## 1. Thông số Môi trường & Tổng quan Kiểm thử

- **Hệ điều hành (OS):** Windows 11 Pro (Windows 10.0.26100 amd64 / PowerShell 7+)
- **Phiên bản Python:** Python 3.12.6 (tags/v3.12.6:a4a8b24)
- **Phiên bản Gitleaks:** Gitleaks v8.30.1 (`gitleaks version 8.30.1`)
- **Kết quả kiểm thử toàn diện (`python -m pytest tests/ -q --basetemp=.pytest_tmp`):**
  - **33 passed in 5.67s** (100% ĐẠT, **0 failed, 0 skipped**).
- **Kết quả Pre-commit Hook (`python -m pre_commit run --all-files`):**
  - `Detect hardcoded secrets.................................................Passed`
- **Xác thực toàn vẹn Audit Ledger (`ledger.verify()`):** **`True`** (tổng số dòng: 46 dòng sự kiện băm SHA-256 liên kết).
- **Kích thước file bằng chứng tấn công rò rỉ:**
  - Trước khi contain (`reports/attack-before.log`): **1196 bytes** (4 dòng POST rò rỉ hồ sơ khách hàng `KH-000999`).
  - Sau khi contain (`reports/attack-after.log`): **0 bytes** (Hoàn toàn không rò rỉ bất kỳ byte nào ra sink ngoại vi).
- **Các lỗi còn lại:** Không có lỗi tồn đọng (**0 remaining issues**).

---

## 2. Chi tiết Kết quả Thực nghiệm Từng Checkpoint

### Checkpoint 1 — Baseline Unsafe Agent (agent/loop.py)
- **Mục tiêu:** Phân tích nguyên nhân rò rỉ từ kiến trúc gốc `_naive_loop()` trước khi can thiệp bảo mật.
- **Báo cáo hoàn thành:** [reports/baseline.md](file:///c:/Thanh/Vin%20AI%20in%20Action/Lab/Lab%2024/K4-L3-DAY24-NguyenVietThanh-2A202602924/reports/baseline.md).
- **Chỉ dẫn dòng code lỗi trong `agent/loop.py`:**
  - *Thiếu định danh và OBO:* Dòng `agent/loop.py:27` và `31` gọi trực tiếp `search_docs` mà không có `agent_id`, `run_id`, `principal_id` hay kiểm tra quyền.
  - *Thiếu kiểm tra mục đích và chính sách trước khi xuất dữ liệu:* Dòng `agent/loop.py:39` và `44` gọi `read_customer` và `http_post` trực tiếp mà không thông qua bất kỳ Policy Engine nào.
  - *Thiếu kiểm soát tính toàn vẹn (Tamper-evident audit):* Toàn bộ `_naive_loop()` không có bất kỳ dòng lệnh ghi nhật ký hay băm mật mã nào.

### Checkpoint 2 — Red Team & Xây dựng Lures (injection-corpus.md & corpus/)
- **Mục tiêu:** Tạo đủ 4 biến thể mồi nhử Prompt Injection đại diện cho 4 kỹ thuật tấn công và ghi nhận log rò rỉ ban đầu.
- **Các tệp lure được tạo mới:**
  1. Variant 1: `corpus/ticket-901.md` (Baseline Lure có sẵn: HTML comment).
  2. Variant 2: `corpus/ticket-902.md` (CSS hidden display `style="display:none"`).
  3. Variant 3: `corpus/ticket-903.md` (Authority spoofing / Giả mạo chỉ thị từ DPO cấp cao).
  4. Variant 4: `corpus/ticket-904.md` + `corpus/ticket-904b.md` (Split documents: chia chỉ thị độc hại qua 2 ticket liên kết).
- **Kiểm tra độ sẵn sàng của lures:**
  - Lệnh: `python -m agent.check_lure corpus/ticket-90*.md`
  - Kết quả: **`4/4 ready`** (100% sẵn sàng kích hoạt injection).
- **Thu thập bằng chứng rò rỉ:**
  - Đã ghi nhận [reports/attack-before.log](file:///c:/Thanh/Vin%20AI%20in%20Action/Lab/Lab%2024/K4-L3-DAY24-NguyenVietThanh-2A202602924/reports/attack-before.log) với 4 dòng JSON POST chứa hồ sơ khách hàng `KH-000999` gửi thành công tới `http://127.0.0.1:10024/reconcile`.

### Checkpoint 3a — PII Detection & Redaction Gate (agent/pii.py)
- **Mục tiêu:** Phát hiện và che giấu 4 loại thực thể nhạy cảm (CCCD, SĐT, STK ngân hàng, Email).
- **Lệnh kiểm thử:** `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp`
- **Kết quả đo lường trên `tests/vn_pii_testset.jsonl`:**
  - `gold = 118` | `pred = 118` | `tp = 118`
  - **Precision:** `1.000` (100%)
  - **Recall:** `1.000` (100% > ngưỡng yêu cầu 95%)
- **Kiểm thử Unit Test:** `test_pii_detection_reaches_target_precision_and_recall` **PASSED**.

### Checkpoint 3b — Policy Engine & PEP (agent/policy.py)
- **Mục tiêu:** Xây dựng hàm quyết định `check(PolicyContext) -> (allow, reason)` với lý do bắt buộc không rỗng.
- **Lệnh kiểm thử:** `python -m pytest tests/test_policy.py -v --basetemp=.pytest_tmp`
- **Kết quả:** **4/4 passed**.
  - Kiểm soát đúng phân loại `data_classification` (`public`, `internal`, `restricted`).
  - Rule tối thiểu: Chặn vô điều kiện yêu cầu egress khi dữ liệu ở mức `restricted`.
  - Quyền hiệu lực là phép giao giữa `principal.allowed_tools` và `agent_scopes` (kèm `parent_scopes` khi `delegation_depth > 0`).

### Checkpoint 3c & 3d — Trifecta Split Architecture & Runner (agent/runner.py)
- **Mục tiêu:** Chia tách 2 ranh giới Run A (Untrusted) và Run B (Trusted Private Data), ngăn chặn tiêm mã truy xuất hồ sơ ngoài ý muốn.
- **Lệnh kiểm thử:**
  - `python -m pytest tests/test_obo.py -v` $\to$ **5/5 passed** (chứng minh `support_l1` bị chặn đọc hồ sơ khách hàng, `dpo` được phép đọc đúng mục đích).
  - `python -m pytest tests/test_split.py -v` $\to$ **1/1 passed** (chứng minh Run B chỉ nhận ticket ID số từ Run A, không đọc `KH-000777` từ văn bản tự do).
  - `python -m pytest tests/test_injection.py -v` $\to$ **8/8 passed** (chứng minh vô hiệu hóa cả 4 biến thể lure).

### Checkpoint 3e — Tamper-evident Audit Ledger (agent/ledger.py)
- **Mục tiêu:** Xây dựng nhật ký kiểm toán băm mật mã SHA-256 chuỗi liên kết `prev_hash` $\to$ `hash`.
- **Lệnh kiểm thử:**
  - `python -m pytest tests/test_ledger.py -v` $\to$ **3/3 passed**.
  - `python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"` $\to$ **`True`**.
- **Số dòng nhật ký ghi nhận thực tế:** 46 dòng bản ghi JSONL, bao gồm cả các quyết định `allow` và quyết định `deny` cho tool `http_post` đối với principal `dpo`.

### Checkpoint 4 — Supply Chain Integrity & Secrets Incident (reports/secrets-incident.md)
- **Mục tiêu:** Quét secret bằng Gitleaks, khóa dependency với SHA-256 hash, cấu hình pre-commit hook và lập báo cáo sự cố secret.
- **Lệnh thực thi:**
  - `gitleaks git --config .gitleaks.toml --redact .` $\to$ Phát hiện chính xác token giả tại commit `1bdd849` (`lab-fake-secret.txt`, rule `lab24-synthetic-token`, exit code 1 - kết quả mong đợi).
  - `gitleaks dir --config .gitleaks.toml --redact .` $\to$ Không còn secret nào ở thư mục làm việc hiện tại (`no leaks found`, exit code 0).
  - `python -m piptools compile --generate-hashes -o requirements.lock requirements.txt` $\to$ Sinh thành công [requirements.lock](file:///c:/Thanh/Vin%20AI%20in%20Action/Lab/Lab%2024/K4-L3-DAY24-NguyenVietThanh-2A202602924/requirements.lock).
  - `python -m pre_commit run --all-files` $\to$ **PASSED**.
  - `python -m pytest tests/test_supply_chain.py -v` $\to$ **3/3 passed**.

### Checkpoint 5 — Proven Containment & Compliance Mapping
- **Mục tiêu:** Chạy lại tình huống ban đầu với sink đang nghe trực tiếp, chứng minh rò rỉ đã bị dập tắt 100%, hoàn thiện DPIA và bảng ánh xạ tuân thủ.
- **Thực nghiệm đối đầu với Sink thật:**
  1. Dừng sink cũ, reset log: `python sink/sink.py --reset`.
  2. Chạy toàn bộ pytest suite: `python -m pytest tests/ -q --basetemp=.pytest_tmp` (**33 passed**).
  3. Reset sink và bật server nghe tại `127.0.0.1:10024`.
  4. Chạy Agent với vai trò `dpo`:
     ```powershell
     $env:PYTHONUTF8="1"
     python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"
     ```
  5. Kiểm tra kích thước file log sau tấn công:
     ```powershell
     Copy-Item -LiteralPath reports/sink.log -Destination reports/attack-after.log
     (Get-Item reports/attack-after.log).Length
     ```
     $\to$ **Kích thước: 0 bytes**.
  6. Kiểm tra dòng chặn trong Ledger: Ghi nhận đầy đủ bản ghi từ chối:
     ```json
     {"tool": "http_post", "classification": "restricted", "decision": "deny", "reason": "Dữ liệu restricted tuyệt đối không được phép egress ra mạng ngoài", "on_behalf_of": "dpo"}
     ```

---

## 3. Các Lỗi Đã Gặp Trong Quá Trình Thực Hiện & Cách Sửa Chữa

| STT | Lỗi gặp phải (Error / Symptom) | Nguyên nhân gốc rễ (Root Cause) | Giải pháp kỹ thuật đã áp dụng (Fix) |
|---|---|---|---|
| 1 | `UnicodeEncodeError: 'charmap' codec can't encode character...` khi in tiếng Việt trên Windows terminal | Console PowerShell trên Windows mặc định sử dụng code page CP1252, không thể encode ký tự tiếng Việt Unicode | Thiết lập biến môi trường `$env:PYTHONUTF8="1"` và `$env:PYTHONIOENCODING="utf-8"` trước khi thực thi các script Python. |
| 2 | Lệnh `pre-commit run --all-files` báo lỗi `gitleaks git requires at most 1 path` | Hook gitleaks mặc định truyền từng tên file đã staged vào lệnh scanner, trong khi `gitleaks git` chỉ nhận duy nhất một thư mục gốc của repo | Thêm cấu hình `pass_filenames: false` vào tệp `.pre-commit-config.yaml` cho hook `gitleaks-system`. |
| 3 | Lỗi xung đột cổng `10024` khi chạy song song server sink và pytest | Pytest có test fixture tự động tạo server kiểm thử nội bộ trên cổng `10024`, gây đụng độ socket nếu sink daemon đang chạy nền | Dừng process sink trước khi chạy pytest suite; sau khi pytest hoàn tất mới khởi động lại sink cho bước kiểm chứng độc lập. |
| 4 | File `reports/attack-before.log`, `attack-after.log` và `reports/ledger.jsonl` bị `.gitignore` bỏ qua | File `.gitignore` mặc định của repo cấu hình loại trừ các file `*.log` và `*.jsonl` trong thư mục `reports/` | Sử dụng cờ ép buộc `-f` khi stage git (`git add -f reports/attack-*.log reports/ledger.jsonl`) để lưu giữ bằng chứng đánh giá. |
| 5 | Lỗi permission khi ghi thư mục cache pytest trên Windows | Thư mục `.pytest_cache` hoặc thư mục tạm hệ thống bị xung đột quyền truy cập giữa các tiến trình | Thêm tham số `--basetemp=.pytest_tmp` vào mọi lệnh gọi pytest trên môi trường Windows. |

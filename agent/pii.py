"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
BANK_RE = re.compile(r"(?i)\b(?:stk|s[oố]\s*t[aà]i\s*kho[aả]n|t[aà]i\s*kho[aả]n|s[oố]\s*tk|tk)\s*[:.]?\s*(\d{8,16})\b")
CCCD_RE = re.compile(r"\b\d{12}\b")
PHONE_RE = re.compile(r"(?:\b0|\+84)(?:[-.\s]?\d){9}\b")


def detect(text: str) -> list[dict]:
    results = []
    occupied = set()

    # 1. EMAIL
    for m in EMAIL_RE.finditer(text):
        s, e = m.start(), m.end()
        results.append({"type": "EMAIL", "start": s, "end": e})
        occupied.update(range(s, e))

    # 2. VN_BANK_ACCOUNT (8-16 chữ số đi kèm STK / số tài khoản)
    for m in BANK_RE.finditer(text):
        s, e = m.start(1), m.end(1)
        if not any(i in occupied for i in range(s, e)):
            results.append({"type": "VN_BANK_ACCOUNT", "start": s, "end": e})
            occupied.update(range(s, e))

    # 3. VN_CCCD (12 chữ số liên tiếp)
    for m in CCCD_RE.finditer(text):
        s, e = m.start(), m.end()
        if not any(i in occupied for i in range(s, e)):
            results.append({"type": "VN_CCCD", "start": s, "end": e})
            occupied.update(range(s, e))

    # 4. VN_PHONE (0 + 9 chữ số)
    for m in PHONE_RE.finditer(text):
        s, e = m.start(), m.end()
        if not any(i in occupied for i in range(s, e)):
            results.append({"type": "VN_PHONE", "start": s, "end": e})
            occupied.update(range(s, e))

    results.sort(key=lambda x: x["start"])
    return results


def redact(text: str) -> str:
    entities = detect(text)
    # Thay từ cuối về đầu để không làm lệch offset các entity phía trước
    for entity in sorted(entities, key=lambda x: x["start"], reverse=True):
        replacement = f"[REDACTED_{entity['type']}]"
        text = text[:entity["start"]] + replacement + text[entity["end"]:]
    return text

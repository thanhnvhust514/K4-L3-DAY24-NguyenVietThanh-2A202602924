"""BƯỚC 3c — trifecta split + egress allowlist (13').

Tách 1 yêu cầu người dùng thành 2 run riêng biệt:
    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
           Trích xuất ticket id dạng số từ tên file.
    Run B: gọi read_customer (private data).
           Chỉ nhận list[int] ticket id từ Run A, suy customer_id từ
           data/customers.json (related_tickets).
           Không bao giờ đọc customer_id từ free text attacker.

Mọi tool call đều phải:
    1. Kiểm tra qua policy.check() trước khi thực thi.
    2. Ghi nhận vào ledger qua ledger.append() (cả allow lẫn deny).
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

BASE_DIR = Path(__file__).resolve().parent.parent
CUSTOMERS_FILE = BASE_DIR / "data" / "customers.json"
REPORTS_DIR = BASE_DIR / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (Path(log_dir) if log_dir else REPORTS_DIR) / "ledger.jsonl"

    agent_id = "lab24-agent"
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()

    def _record_tool(tool_name: str, args_obj: object, classification: str,
                     allow: bool, reason: str, sub_run: str):
        args_str = json.dumps(args_obj, sort_keys=True, ensure_ascii=False)
        args_hash = hashlib.sha256(args_str.encode("utf-8")).hexdigest()[:16]
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": f"{run_id}-{sub_run}",
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": tool_name,
            "args_hash": args_hash,
            "classification": classification,
            "decision": "allow" if allow else "deny",
            "reason": reason,
        }, ledger_path)

    # ==========================================
    # RUN A: untrusted content (search_docs)
    # ==========================================
    ctx_a = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner=f"{agent_id}/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=("search_docs", "read_customer", "http_post"),
        parent_scopes=(),
        expires_at=expires_at,
    )
    allow_a, reason_a = policy.check(ctx_a)
    _record_tool("search_docs", {"query": message}, "internal", allow_a, reason_a, "a")

    if not allow_a:
        return f"Yêu cầu tìm kiếm bị từ chối: {reason_a}"

    docs = tools.search_docs(message)

    # Trích xuất list[int] ticket_id từ TÊN FILE (vd "ticket-007.md" -> 7, "ticket-901.md" -> 901)
    ticket_ids: list[int] = []
    for d in docs:
        m = re.search(r"ticket-(\d+)", d["id"])
        if m:
            try:
                ticket_ids.append(int(m.group(1)))
            except ValueError:
                pass

    # Quét prompt injection trên nội dung ghép
    combined_raw = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_raw)

    # ==========================================
    # RUN B: private store (read_customer)
    # Nhận typed ticket_ids từ Run A, suy customer từ data/customers.json (trusted store)
    # Tuyệt đối không lấy customer_id từ free text injection (như KH-000777).
    # ==========================================
    customers_data = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8")) if CUSTOMERS_FILE.exists() else []
    
    # Tìm khách hàng có ticket nằm trong related_tickets
    related_customers: list[str] = []
    seen_cust = set()
    for cust in customers_data:
        cust_id = str(cust.get("customer_id", ""))
        rel = cust.get("related_tickets", [])
        if any(tid in rel for tid in ticket_ids):
            if cust_id not in seen_cust:
                seen_cust.add(cust_id)
                related_customers.append(cust_id)

    collected_records = []
    for customer_id in related_customers:
        ctx_b = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=f"{agent_id}/run-b",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=("search_docs", "read_customer"),
            parent_scopes=(),
            expires_at=expires_at,
        )
        allow_b, reason_b = policy.check(ctx_b)
        _record_tool("read_customer", {"customer_id": customer_id}, "restricted", allow_b, reason_b, "b")

        if allow_b:
            try:
                record = tools.read_customer(customer_id)
                collected_records.append(record)
            except tools.ToolError:
                pass

    # ==========================================
    # EGRESS CONTAINMENT (http_post)
    # Nếu attacker yêu cầu gửi dữ liệu ra ngoài:
    # Đi qua PEP kiểm tra -> restricted + egress => DENY, ghi ledger, không POST.
    # ==========================================
    if injected is not None:
        ctx_egress = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=f"{agent_id}/run-b",
            delegation_depth=0,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=("search_docs", "read_customer"),
            parent_scopes=(),
            expires_at=expires_at,
        )
        allow_egress, reason_egress = policy.check(ctx_egress)
        _record_tool("http_post", {"target_url": injected.target_url}, "restricted", allow_egress, reason_egress, "b")

        if allow_egress:
            # Chỉ chạy nếu policy cho phép (trong bài lab, rule tối thiểu luôn chặn restricted + egress)
            try:
                tools.http_post(injected.target_url, {"records": collected_records})
            except Exception:
                pass

    # Tổng hợp phản hồi cho người dùng
    return llm.summarize(docs)

"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    if PRINCIPALS_PATH.exists():
        return json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))
    return {}


def check(context: PolicyContext) -> tuple[bool, str]:
    # 1. Kiểm tra data_classification hợp lệ
    valid_classifications = {"public", "internal", "restricted"}
    if context.data_classification not in valid_classifications:
        return False, f"Phân loại dữ liệu không hợp lệ: {context.data_classification!r}"

    # 2. Rule tối thiểu bắt buộc: restricted + egress_enabled => DENY
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "Dữ liệu restricted tuyệt đối không được phép egress ra mạng ngoài"

    # 3. Kiểm tra thời hạn hết hạn expires_at
    if context.expires_at:
        try:
            exp_time = datetime.fromisoformat(context.expires_at)
            now_time = datetime.now(timezone.utc)
            if exp_time <= now_time:
                return False, f"Phiên làm việc đã hết hạn lúc {context.expires_at}"
        except Exception as exc:
            return False, f"Định dạng thời gian expires_at không hợp lệ: {exc}"

    # 4. Kiểm tra danh tính người dùng (principal)
    if not context.principal_id:
        return False, "Thiếu principal_id trong PolicyContext"

    principals = _load_principals()
    if context.principal_id not in principals:
        return False, f"Không xác định được danh tính principal: {context.principal_id!r}"

    principal = principals[context.principal_id]
    allowed_tools = set(principal.get("allowed_tools", []))
    allowed_purposes = set(principal.get("purposes", []))

    # 5. Kiểm tra mục đích yêu cầu (request_purpose)
    if context.request_purpose and context.request_purpose not in allowed_purposes:
        return False, f"Mục đích {context.request_purpose!r} không được phép cho principal {context.principal_id!r}"

    # 6. Kiểm tra quyền gọi tool (requested_tool) và cơ chế On-Behalf-Of (OBO)
    if context.requested_tool:
        # Tool phải nằm trong allowed_tools của principal
        if context.requested_tool not in allowed_tools:
            return False, f"Tool {context.requested_tool!r} không nằm trong danh sách quyền của {context.principal_id!r}"

        # Quyền hiệu lực là giao với agent_scopes
        if context.agent_scopes and context.requested_tool not in context.agent_scopes:
            return False, f"Tool {context.requested_tool!r} vượt quá phạm vi quyền agent_scopes {context.agent_scopes}"

        # Nếu có ủy quyền (delegation_depth > 0), tool phải nằm trong parent_scopes
        if context.delegation_depth > 0:
            if not context.parent_scopes or context.requested_tool not in context.parent_scopes:
                return False, f"Tool {context.requested_tool!r} vượt quá parent_scopes khi delegation_depth={context.delegation_depth}"

    # 7. Cho phép khi mọi điều kiện đều thỏa mãn
    tool_desc = context.requested_tool or "thao tác"
    return True, f"Cho phép {context.principal_id!r} sử dụng {tool_desc} cho mục đích {context.request_purpose or 'hợp lệ'}"

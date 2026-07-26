"""
before_tool.py — خطاف ما قبل تنفيذ الأداة

يتولّى هذا الخطاف:
  1. التحقق من صحة المدخلات (ToolValidationError عند الفشل)
  2. تعقيم المعاملات (حذف الحقول الحساسة)
  3. إنشاء trace_id فريد وحفظه في threading.local()
  4. تسجيل بداية التنفيذ في logs/tool_trace.jsonl بصيغة JSON
  5. تسجيل بدء التوقيت بدقة <= 1ms عبر perf_counter_ns

الواجهة:
    before_tool(tool_name: str, params: dict) -> dict | None

    - إرجاع dict معدَّل => استخدامه بدلاً من params الأصلي
    - إرجاع None    => المتابعة بدون تعديل
    - رمي ToolValidationError => رفض تنفيذ الأداة

Google-style Docstrings مُستخدَمة في كل الدوال.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# المسارات
# ─────────────────────────────────────────────────────────────────────────────
_BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LOGS_DIR   = os.path.join(_BASE_DIR, "logs")
_TRACE_FILE = os.path.join(_LOGS_DIR, "tool_trace.jsonl")

os.makedirs(_LOGS_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# المُسجِّل (structlog إن وُجد، وإلا logging القياسي)
# ─────────────────────────────────────────────────────────────────────────────
try:
    import structlog
    _log = structlog.get_logger("before_tool")
    _USE_STRUCTLOG = True
except ImportError:
    _log = logging.getLogger("before_tool")   # type: ignore[assignment]
    _USE_STRUCTLOG = False

# ─────────────────────────────────────────────────────────────────────────────
# الحقول الحساسة — تُحذف من السجلات (case-insensitive)
# ─────────────────────────────────────────────────────────────────────────────
_SENSITIVE_KEYS: frozenset[str] = frozenset({
    "password", "passwd", "token", "secret", "api_key",
    "authorization", "auth", "private_key", "credentials",
    "access_token", "refresh_token", "client_secret",
})

# ─────────────────────────────────────────────────────────────────────────────
# threading.local لحفظ trace_id + start_ns بين before_tool و after_tool
# ─────────────────────────────────────────────────────────────────────────────
_local: threading.local = threading.local()

# قفل كتابة ملف السجل (thread-safe)
_file_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
# استثناء مخصص
# ─────────────────────────────────────────────────────────────────────────────
class ToolValidationError(Exception):
    """يُرمى عند فشل التحقق من صحة مدخلات الأداة.

    Attributes:
        message: وصف الخطأ.
    """


# ─────────────────────────────────────────────────────────────────────────────
# دوال مساعدة
# ─────────────────────────────────────────────────────────────────────────────

def _sanitize(params: dict[str, Any]) -> dict[str, Any]:
    """يُعيد نسخةً نظيفةً من params بدون قيم الحقول الحساسة.

    يعمل بشكل تكراري على القواميس المتداخلة.

    Args:
        params: معاملات الأداة كما وردت.

    Returns:
        نسخة منقّاة — الحقول الحساسة تُستبدل بـ ``"***REDACTED***"``.
    """
    cleaned: dict[str, Any] = {}
    for key, value in params.items():
        if key.lower() in _SENSITIVE_KEYS:
            cleaned[key] = "***REDACTED***"
        elif isinstance(value, dict):
            cleaned[key] = _sanitize(value)
        else:
            cleaned[key] = value
    return cleaned


def _write_jsonl(record: dict[str, Any]) -> None:
    """يكتب سطر JSON واحداً إلى tool_trace.jsonl بشكل thread-safe.

    Args:
        record: القاموس المراد تسجيله.
    """
    try:
        line = json.dumps(record, ensure_ascii=False, default=str)
        with _file_lock:
            with open(_TRACE_FILE, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
    except Exception as exc:                              # noqa: BLE001
        logging.getLogger("before_tool").warning(
            "فشل كتابة tool_trace.jsonl: %s", exc
        )


def _log_info(msg: str, **kw: Any) -> None:
    """يُسجِّل رسالة info بغض النظر عن نوع المُسجِّل المتاح.

    Args:
        msg: نص الرسالة.
        **kw: بيانات إضافية (تُضاف فقط مع structlog).
    """
    if _USE_STRUCTLOG:
        _log.info(msg, **kw)
    else:
        _log.info("%s | %s", msg, kw)  # type: ignore[union-attr]


# ─────────────────────────────────────────────────────────────────────────────
# الخطاف الرئيسي
# ─────────────────────────────────────────────────────────────────────────────

def before_tool(tool_name: str, params: dict | None) -> dict | None:
    """خطاف ما قبل تنفيذ الأداة.

    يُنفَّذ تلقائياً قبل كل استدعاء لأي أداة في النظام.

    الوظائف:
      - التحقق من صحة ``tool_name`` و``params``.
      - إنشاء ``trace_id`` فريد وحفظه في ``threading.local()``.
      - تسجيل وقت البداية بدقة نانو‌ثانية (``perf_counter_ns``).
      - تعقيم ``params`` وحذف الحقول الحساسة.
      - كتابة سجل JSON إلى ``logs/tool_trace.jsonl``.

    Args:
        tool_name: اسم الأداة المراد تنفيذها. يجب أن يكون str غير فارغ.
        params:    معاملات الأداة. يجب أن تكون ``dict`` أو ``None``.

    Returns:
        ``dict`` المعاملات المعقَّمة إذا كانت params غير فارغة،
        أو ``None`` للمتابعة بدون تعديل.

    Raises:
        ToolValidationError: إذا كان ``tool_name`` فارغاً أو من نوع خاطئ،
            أو إذا كانت ``params`` من نوع غير ``dict`` أو ``None``.
    """
    try:
        # ── 1. التحقق من الصحة ───────────────────────────────────────────────
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ToolValidationError(
                f"tool_name يجب أن يكون str غير فارغ — استُقبل: "
                f"{type(tool_name).__name__!r} = {tool_name!r}"
            )

        if params is not None and not isinstance(params, dict):
            raise ToolValidationError(
                f"params يجب أن يكون dict أو None — استُقبل: "
                f"{type(params).__name__!r}"
            )

        # ── 2. إنشاء trace_id وتسجيل التوقيت ────────────────────────────────
        trace_id: str     = str(uuid.uuid4())
        start_ns: int     = time.perf_counter_ns()      # دقة < 1ms
        thread_id: int    = threading.get_ident()

        # حفظ trace_id + start_ns في threading.local() للاستخدام في after_tool
        _local.trace_id  = trace_id
        _local.start_ns  = start_ns
        _local.tool_name = tool_name

        # ── 3. تعقيم المعاملات ───────────────────────────────────────────────
        safe_params: dict[str, Any] = _sanitize(params) if params else {}

        # ── 4. تسجيل في structlog / logging ──────────────────────────────────
        _log_info(
            "tool_start",
            trace_id=trace_id,
            tool_name=tool_name,
            thread_id=thread_id,
            params=safe_params,
        )

        # ── 5. كتابة tool_trace.jsonl ─────────────────────────────────────────
        _write_jsonl({
            "event":      "tool_start",
            "trace_id":   trace_id,
            "tool_name":  tool_name,
            "params":     safe_params,
            "start_ns":   start_ns,
            "thread_id":  thread_id,
        })

        # نُعيد المعاملات المعقّمة — أو None إذا كانت فارغة
        return safe_params if safe_params else None

    except ToolValidationError:
        # نرمي أخطاء التحقق صراحةً كي يعالجها النظام
        raise

    except Exception as exc:                              # noqa: BLE001
        # أي خطأ غير متوقع يُسجَّل ولا يُوقف تنفيذ الأداة
        logging.getLogger("before_tool").error(
            "خطأ غير متوقع في before_tool: %s", exc, exc_info=True
        )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# تصدير العناصر العامة
# ─────────────────────────────────────────────────────────────────────────────
__all__ = ["before_tool", "ToolValidationError", "_local"]

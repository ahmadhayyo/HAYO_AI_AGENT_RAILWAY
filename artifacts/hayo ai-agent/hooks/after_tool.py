"""
after_tool.py — خطاف ما بعد تنفيذ الأداة

يتولّى هذا الخطاف:
  1. استرداد trace_id + start_ns من threading.local() (كتبه before_tool)
  2. حساب الزمن المستغرق بدقة ms
  3. نشر المقاييس إلى prometheus_client (Counter + Histogram)
  4. كشف Coroutine / Future والإشارة إليهما في السجل
  5. التحقق من حجم المخرج (> 10 MB => تحذير + قص)
  6. كتابة سجل النتيجة في logs/tool_trace.jsonl

الواجهة:
    after_tool(tool_name: str, result: Any, params: dict) -> Any

    - إرجاع Any   => نتيجة معدَّلة ترسل بدلاً من result
    - إرجاع None  => المتابعة بدون تعديل

Google-style Docstrings مُستخدَمة في كل الدوال.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import sys
import threading
import time
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# المسارات
# ─────────────────────────────────────────────────────────────────────────────
_BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LOGS_DIR   = os.path.join(_BASE_DIR, "logs")
_TRACE_FILE = os.path.join(_LOGS_DIR, "tool_trace.jsonl")

os.makedirs(_LOGS_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# المُسجِّل
# ─────────────────────────────────────────────────────────────────────────────
try:
    import structlog
    _log = structlog.get_logger("after_tool")
    _USE_STRUCTLOG = True
except ImportError:
    _log = logging.getLogger("after_tool")    # type: ignore[assignment]
    _USE_STRUCTLOG = False

# ─────────────────────────────────────────────────────────────────────────────
# prometheus_client — اختياري
# ─────────────────────────────────────────────────────────────────────────────
_PROM_OK = False
try:
    from prometheus_client import Counter, Histogram

    _TOOL_CALLS = Counter(
        "hayo_tool_calls_total",
        "إجمالي استدعاءات الأدوات",
        ["tool_name", "success"],
    )
    _TOOL_DURATION = Histogram(
        "hayo_tool_duration_ms",
        "زمن تنفيذ الأداة بالميلي‌ثانية",
        ["tool_name"],
        buckets=[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000],
    )
    _PROM_OK = True
except Exception:                                         # noqa: BLE001
    pass

# ─────────────────────────────────────────────────────────────────────────────
# ثوابت
# ─────────────────────────────────────────────────────────────────────────────
_MAX_OUTPUT_BYTES  = 10 * 1024 * 1024   # 10 MB
_OUTPUT_PREVIEW_CH = 200                # أول N حرف في output_preview

# قفل كتابة الملف
_file_lock = threading.Lock()

# نفس threading.local التي يكتب فيها before_tool
from hooks.before_tool import _local                     # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# دوال مساعدة
# ─────────────────────────────────────────────────────────────────────────────

def _result_size_bytes(result: Any) -> int:
    """يُقدِّر حجم المخرج بالبايت.

    Args:
        result: مخرج الأداة بأي نوع.

    Returns:
        الحجم التقريبي بالبايت.
    """
    try:
        return sys.getsizeof(result)
    except Exception:                                     # noqa: BLE001
        return 0


def _safe_preview(result: Any, max_chars: int = _OUTPUT_PREVIEW_CH) -> str:
    """يُنشئ معاينةً نصيةً آمنة للمخرج.

    Args:
        result:    المخرج المراد معاينته.
        max_chars: الحد الأقصى لعدد الأحرف.

    Returns:
        نص مقصور على ``max_chars`` حرف.
    """
    try:
        text = str(result)
        return text[:max_chars] + ("…" if len(text) > max_chars else "")
    except Exception:                                     # noqa: BLE001
        return "<non-representable>"


def _classify_result(result: Any) -> str:
    """يُصنِّف نوع المخرج (coroutine / future / sync).

    Args:
        result: مخرج الأداة.

    Returns:
        سلسلة نصية: ``"coroutine"`` | ``"future"`` | ``"sync"``.
    """
    if inspect.iscoroutine(result):
        return "coroutine"
    if asyncio.isfuture(result) or inspect.isawaitable(result):
        return "future"
    return "sync"


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
        logging.getLogger("after_tool").warning(
            "فشل كتابة tool_trace.jsonl: %s", exc
        )


def _log_info(msg: str, **kw: Any) -> None:
    if _USE_STRUCTLOG:
        _log.info(msg, **kw)
    else:
        _log.info("%s | %s", msg, kw)  # type: ignore[union-attr]


def _log_warning(msg: str, **kw: Any) -> None:
    if _USE_STRUCTLOG:
        _log.warning(msg, **kw)
    else:
        _log.warning("%s | %s", msg, kw)  # type: ignore[union-attr]


# ─────────────────────────────────────────────────────────────────────────────
# الخطاف الرئيسي
# ─────────────────────────────────────────────────────────────────────────────

def after_tool(tool_name: str, result: Any, params: dict | None) -> Any:
    """خطاف ما بعد تنفيذ الأداة.

    يُنفَّذ تلقائياً بعد اكتمال أي أداة في النظام.

    الوظائف:
      - استرداد ``trace_id`` و``start_ns`` من ``threading.local()``.
      - حساب ``duration_ms`` بدقة ميلي‌ثانية.
      - نشر Counter + Histogram إلى Prometheus (إن توفّر).
      - كشف الـ coroutine / future وتسجيلهما.
      - التحقق من حجم المخرج (> 10 MB => تحذير + قص).
      - كتابة سجل JSON في ``logs/tool_trace.jsonl``.

    Args:
        tool_name: اسم الأداة التي اكتملت.
        result:    مخرج الأداة (أي نوع).
        params:    المعاملات الأصلية التي استُدعيت بها الأداة.

    Returns:
        المخرج المقصوص إذا تجاوز 10 MB، وإلا ``None`` (متابعة بدون تعديل).
    """
    try:
        end_ns: int = time.perf_counter_ns()

        # ── 1. استرداد trace بيانات من threading.local() ─────────────────────
        trace_id: str  = getattr(_local, "trace_id",  "unknown")
        start_ns: int  = getattr(_local, "start_ns",  end_ns)
        thread_id: int = threading.get_ident()

        duration_ms: float = (end_ns - start_ns) / 1_000_000   # ns → ms

        # ── 2. تصنيف المخرج ──────────────────────────────────────────────────
        result_kind: str = _classify_result(result)
        is_async: bool   = result_kind in ("coroutine", "future")

        # ── 3. التحقق من حجم المخرج ──────────────────────────────────────────
        size_bytes: int  = _result_size_bytes(result)
        truncated: bool  = False
        final_result     = result

        if size_bytes > _MAX_OUTPUT_BYTES:
            _log_warning(
                "tool_output_oversized",
                trace_id=trace_id,
                tool_name=tool_name,
                size_mb=round(size_bytes / 1_048_576, 2),
                limit_mb=10,
            )
            # قص المخرج إذا كان نصاً
            if isinstance(result, str):
                final_result = result[:_MAX_OUTPUT_BYTES] + "\n…[OUTPUT TRUNCATED]"
            truncated = True

        # ── 4. نشر مقاييس Prometheus ─────────────────────────────────────────
        if _PROM_OK:
            try:
                _TOOL_CALLS.labels(
                    tool_name=tool_name, success="true"
                ).inc()
                _TOOL_DURATION.labels(tool_name=tool_name).observe(duration_ms)
            except Exception:                             # noqa: BLE001
                pass

        # ── 5. تسجيل في structlog / logging ──────────────────────────────────
        output_preview = _safe_preview(final_result)
        _log_info(
            "tool_end",
            trace_id=trace_id,
            tool_name=tool_name,
            duration_ms=round(duration_ms, 3),
            success=True,
            is_async=is_async,
            result_kind=result_kind,
            truncated=truncated,
            output_preview=output_preview,
        )

        # ── 6. كتابة tool_trace.jsonl ─────────────────────────────────────────
        _write_jsonl({
            "event":          "tool_end",
            "trace_id":       trace_id,
            "tool_name":      tool_name,
            "duration_ms":    round(duration_ms, 3),
            "success":        True,
            "is_async":       is_async,
            "result_kind":    result_kind,
            "size_bytes":     size_bytes,
            "truncated":      truncated,
            "output_preview": output_preview,
            "thread_id":      thread_id,
        })

        return final_result if truncated else None

    except Exception as exc:                              # noqa: BLE001
        logging.getLogger("after_tool").error(
            "خطأ غير متوقع في after_tool: %s", exc, exc_info=True
        )
        return None


__all__ = ["after_tool"]

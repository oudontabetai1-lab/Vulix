"""Browser operation bindings and pure persisted non-network causality checks."""
from contextlib import contextmanager, nullcontext
import uuid

from .probe_ledger import sha256_hex, body_length


def logger_for(browser):
    logger = getattr(browser, "request_logger", None)
    return logger if callable(getattr(logger, "browser_event", None)) else None


def page_context(browser):
    # Object keys are retained, so Python cannot recycle identity while callbacks remain.
    page = getattr(browser, "page", None)
    identities = getattr(browser, "_evidence_pages", None)
    if identities is None:
        identities = browser._evidence_pages = {}
    if page not in identities:
        identities[page] = uuid.uuid4().hex
    return dict(page_id=identities[page], frame_id=identities[page],
                generation=identities[page])


def emit(browser, kind, **kwargs):
    logger = logger_for(browser)
    if logger is None:
        return None
    try:
        return logger.browser_event(kind, context=kwargs.pop("context", page_context(browser)), **kwargs)
    except Exception as exc:
        logger.probe_ledger.manifest.note_gap("browser_event_error:" + type(exc).__name__)
        return None


def snapshot(browser, page, parent):
    if browser is None:
        return None
    html = getattr(page, "html", None)
    sid = emit(browser, "snapshot", parent_id=parent, input_hash=sha256_hex(html),
               input_length=body_length(html), complete=isinstance(html, str) and bool(html)
               and getattr(browser, "_evidence_refresh_ok", True))
    browser._evidence_snapshot = sid or ""
    return sid


@contextmanager
def operation(browser, check, *, role="attack", ip=None, parent=None):
    """Bind the concrete page before any await; delayed callbacks keep this object."""
    logger = logger_for(browser)
    if logger is None:
        yield None
        return
    context = page_context(browser)
    context["snapshot_id"] = getattr(browser, "_evidence_snapshot", "")
    oid = emit(browser, "operation", check=check, role=role, context=context,
               parent_id=parent if parent is not None else context["snapshot_id"])
    context["operation_id"] = oid or ""
    context.update(check=check, role=role, dialogs={}, page=browser.page,
                   frame=getattr(browser.page, "main_frame", None))
    prior = getattr(browser, "_evidence_operation", None)
    browser._evidence_operation = context
    scope = logger.probe_scope(ip, check, role=role, parent_id=oid or "") if ip else nullcontext()
    try:
        with scope:
            yield context
    except BaseException as exc:
        outcome = "timeout" if type(exc).__name__ in {"TimeoutError", "CancelledError"} else "verification_error"
        decision(browser, context, outcome=outcome)
        raise
    finally:
        browser._evidence_operation = prior


def decision(browser, context, *, matched=False, complete=False, outcome=None, rule="", material="",
             inputs=(), required_inputs=0, request_attempt_id=""):
    if context is None:
        return None
    observed = emit(browser, "observation", context=context, check=context["check"], role=context["role"],
                    parent_id=context["operation_id"], input_hash=sha256_hex(material),
                    input_length=body_length(material), complete=complete, inputs=inputs, required_inputs=required_inputs,
                    request_attempt_id=request_attempt_id)
    did = emit(browser, "decision", context=context, check=context["check"], role=context["role"],
                parent_id=observed, outcome=outcome or ("matched" if matched else "no_match")
                if complete else outcome or "unexecutable", rule=rule, complete=complete, request_attempt_id=request_attempt_id)
    browser._evidence_last_decision = did or ""
    return did


def accepted_decisions(events):
    """Separate from C1: a page analysis never invents a delivered HTTP request."""
    valid = set()
    result = {}
    good = {"matched", "no_match"}
    delivered = set()
    for row in events.values():
        request_id = row.get("request_attempt_id")
        request = events.get(request_id, {})
        if (row.get("record_kind") == "observation" and request.get("record_kind") == "request"
                and row.get("parent_id") == request_id and (row.get("request") or {}).get("sent") is True
                and (row.get("response") or {}).get("body_hash")
                and all(row.get(k) == request.get(k) for k in ("scan_id", "check", "role", "completion_unit", "injection_key"))
                and all((row.get("request") or {}).get(k) == (request.get("request") or {}).get(k)
                        for k in ("method", "url", "transport", "body_hash", "body_length"))):
            delivered.add(request_id)
    for aid, row in sorted(events.items(), key=lambda item: int(item[0].rpartition(":")[2])):
        if row.get("record_kind") != "browser":
            continue
        b = row.get("browser") or {}
        kind = b.get("kind")
        parent = events.get(row.get("parent_id"), {})
        pb = parent.get("browser") or {}
        same_page = b.get("page_id") and b.get("page_id") == pb.get("page_id")
        prior = parent.get("attempt_id") in valid
        ready = b.get("complete") is True
        if kind == "page_source":
            ok = ready and bool(b.get("input_hash")) and b.get("input_length", 0) > 0
        elif kind == "flow":
            ok = prior and same_page and pb.get("kind") in {"page_source", "flow_end"}
        elif kind == "flow_action":
            flow = events.get(b.get("flow_id"), {})
            fb = flow.get("browser") or {}
            ok = (prior and same_page and b.get("total") == fb.get("total") and b.get("total", 0) > 0
                  and ((pb.get("kind") == "flow" and b.get("index") == 1
                        and b.get("flow_id") == parent.get("attempt_id"))
                       or (pb.get("kind") == "flow_step" and pb.get("flow_id") == b.get("flow_id")
                           and b.get("index") == pb.get("index", 0) + 1)))
        elif kind == "flow_step":
            ok = (prior and same_page and row.get("outcome") in good and ready
                  and pb.get("kind") == "flow_action"
                  and all(b.get(k) == pb.get(k) for k in ("flow_id", "index", "total")))
        elif kind == "flow_end":
            ok = (prior and same_page and ready and row.get("outcome") in good
                  and pb.get("kind") == "flow_step" and pb.get("flow_id") == b.get("flow_id")
                  and pb.get("index") == pb.get("total"))
        elif kind == "snapshot":
            ok = prior and same_page and ready and pb.get("kind") in {"page_source", "flow_end"} and b.get("input_length", 0) > 0 and bool(b.get("input_hash"))
        elif kind == "operation":
            # Verification additionally requires the exact matched attack decision.
            snap = events.get(b.get("snapshot_id"), {})
            ok = (ready is False and snap.get("attempt_id") in valid
                  and (snap.get("browser") or {}).get("kind") == "snapshot"
                  and (snap.get("browser") or {}).get("page_id") == b.get("page_id")
                  and prior and same_page and (pb.get("kind") == "snapshot" if row.get("role") == "attack"
                       else pb.get("kind") == "decision" and parent.get("outcome") == "matched"
                       and parent.get("check") == row.get("check")))
        elif kind in {"observation", "decision"}:
            op = events.get(b.get("operation_id"), {})
            ob = op.get("browser") or {}
            ok = (prior and same_page and ready and op.get("attempt_id") in valid
                  and all(row.get(k) == op.get(k) for k in ("check", "role", "completion_unit"))
                  and all(b.get(k) == ob.get(k) for k in ("page_id", "frame_id", "generation", "snapshot_id"))
                  and (pb.get("kind") == "operation" and row.get("parent_id") == b.get("operation_id")
                       if kind == "observation" else pb.get("kind") == "observation"
                       and pb.get("operation_id") == b.get("operation_id") and row.get("outcome") in good))
        else:
            ok = False
        if ok and kind == "observation" and row.get("check") == "dom_xss":
            request = events.get(row.get("request_attempt_id"), {})
            ok = (request.get("record_kind") == "request"
                  and request.get("parent_id") == b.get("operation_id")
                  and all(request.get(k) == row.get(k) for k in ("check", "role", "completion_unit"))
                  and row.get("request_attempt_id") in delivered)
        if ok and kind == "observation" and row.get("check") == "js_static":
            inputs = b.get("inputs", [])
            snap = events.get(b.get("snapshot_id"), {}).get("browser") or {}
            ok = (len(inputs) == b.get("required_inputs") and bool(inputs)
                  and inputs[0].get("body_hash") == snap.get("input_hash")
                  and all(i.get("captured") is True and i.get("body_length", 0) > 0
                          and i.get("body_hash") and i.get("source_id") for i in inputs))
        if ok:
            valid.add(aid)
        if kind == "decision":
            result.setdefault(row.get("completion_unit"), []).append(row if ok else None)
    # Any failed or malformed operation poisons the unit even if another payload matched.
    for row in events.values():
        b = row.get("browser") or {}
        if row.get("record_kind") == "browser" and b.get("kind") == "operation":
            if not any(r and (r.get("browser") or {}).get("operation_id") == row["attempt_id"]
                       for r in result.get(row.get("completion_unit"), ())):
                result.setdefault(row.get("completion_unit"), []).append(None)
    return {unit: [] if None in rows else rows for unit, rows in result.items()}


@contextmanager
def network_scope(browser, parent, *, check, role):
    """Capture only concrete main-frame requests; no request is created by this scope."""
    logger = logger_for(browser)
    capture = getattr(browser, "network", None)
    if logger is None or capture is None:
        yield []
        return
    with logger.probe_scope(None, check, role=role, parent_id=parent or "") as context:
        previous = tuple(getattr(capture, k, None) for k in ("probe_context", "pending_probe_context", "probe_frame"))
        capture.probe_context = capture.pending_probe_context = context
        capture.probe_frame = getattr(browser.page, "main_frame", None)
        try:
            yield context["requests"]
        finally:
            capture.probe_context, capture.pending_probe_context, capture.probe_frame = previous

"""Safe, read-only crawl graph snapshot projection module.

Produces a deterministic, redacted graph snapshot (nodes, edges, and per-node references
to existing findings, actions, and inputs) from scan data with explicit completeness guarantees.
"""
from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qsl, urlsplit

from wscan.request_logger import redact_text, redact_url
from wscan.url_normalize import normalize_url_for_key
from wscan.url_scope import is_sensitive_query_key

SCHEMA_VERSION: str = "1.0.0"
KNOWN_NODE_KINDS: frozenset[str] = frozenset({"page", "form", "param"})


def normalize_node_kind(kind: str) -> str:
    """Normalize node kind, preserving any unrecognized or unknown kind as 'unknown'."""
    k = str(kind or "").strip().lower()
    return k if k in KNOWN_NODE_KINDS else "unknown"


def generate_node_id(kind: str, url: str, identifier: str = "") -> str:
    """Derive a deterministic, stable ID for a crawl graph node from normalized URL, kind, and identifier.

    Reuses url_normalize.normalize_url_for_key to ensure stability across equivalent URLs,
    and applies redact_url so sensitive credentials/tokens do not influence or leak into the hash.
    Unknown kinds are preserved under the 'unknown' namespace.
    """
    effective_kind = normalize_node_kind(kind)
    safe_url = redact_url(url) if url else ""
    norm_url = normalize_url_for_key(safe_url) if safe_url else ""
    safe_identifier = redact_text(identifier) if identifier else ""
    seed = f"{effective_kind}:{norm_url}:{safe_identifier}".strip(":")
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
    return f"{effective_kind}_{digest}"


def _build_finding_reference(f: Mapping[str, Any]) -> dict[str, Any]:
    """Create a safe, read-only reference to an existing finding."""
    f_url = str(f.get("url") or "")
    f_field = str(f.get("field_name") or "")
    f_check = str(f.get("check_type") or "")
    f_sev = str(f.get("severity") or "")
    f_id = str(f.get("id") or f.get("finding_id") or "")
    if not f_id:
        f_id = f"{f_check}_{f_field}" if f_field else f_check
    return {
        "id": f_id,
        "check_type": f_check,
        "severity": f_sev,
        "verified": bool(f.get("verified", False)),
        "field_name": f_field,
        "evidence_type": str(f.get("evidence_type") or ""),
        "url": redact_url(f_url),
    }


def _redact_dict_values(data: Any) -> Any:
    """Recursively redact strings in dicts/lists to prevent secret leakage."""
    if isinstance(data, str):
        if data.startswith(("http://", "https://", "ws://", "wss://")):
            return redact_url(data)
        return redact_text(data)
    if isinstance(data, dict):
        out: dict[str, Any] = {}
        for k, v in data.items():
            if is_sensitive_query_key(k):
                out[k] = "<redacted>"
            else:
                out[k] = _redact_dict_values(v)
        return out
    if isinstance(data, list):
        return [_redact_dict_values(item) for item in data]
    return data


def determine_completeness(
    status: str,
    phase: str,
    aborted: bool,
    scan_gaps: Sequence[Any],
    unscannable_urls: Sequence[Any],
    truncation_counts: Mapping[str, Any],
    exhausted_truncations: Sequence[Any],
    node_count: int,
) -> tuple[str, list[str]]:
    """Determine explicit completeness (complete / partial / unknown) and reasons.

    Invariants:
    - Never present an in-progress scan as complete.
    - Never present an aborted, errored, gapped, or truncated scan as complete.
    - An empty scan or idle scan with no nodes is unknown.
    - Only a fully finished scan with no aborts, gaps, or truncations is complete.
    """
    reasons: list[str] = []
    norm_status = str(status or "").strip().lower()
    norm_phase = str(phase or "").strip().lower()

    # 1. In-progress states
    if norm_status in ("scanning", "running") or (
        norm_phase in ("crawl", "plan", "attack") and norm_status != "done"
    ):
        reasons.append("scan_in_progress")

    # 2. Abort states
    if aborted or norm_status == "aborted":
        reasons.append("scan_aborted")

    # 3. Error states
    if norm_status == "error":
        reasons.append("scan_error")

    # 4. Gaps and unscannable URLs
    if scan_gaps:
        reasons.append("scan_gaps_present")
    if unscannable_urls:
        reasons.append("unscannable_urls_present")

    # 5. Truncations
    if truncation_counts or exhausted_truncations:
        reasons.append("truncation_detected")

    if reasons:
        return "partial", sorted(set(reasons))

    # Completed check
    if norm_status in ("done", "completed"):
        if node_count == 0:
            return "unknown", ["empty_scan"]
        return "complete", ["scan_completed"]

    if norm_status in ("idle", ""):
        return "unknown", ["empty_scan" if node_count == 0 else "scan_idle"]

    if node_count == 0:
        return "unknown", ["empty_scan"]

    return "unknown", ["status_unknown"]


def project_crawl_graph(scan_data: Mapping[str, Any]) -> dict[str, Any]:
    """Pure projection function (no I/O) returning a crawl graph snapshot.

    Builds nodes (pages, forms, params, unknown), edges, and per-node references
    to existing actions, inputs, and findings. Applies redaction to all URLs and
    sensitive parameters, derives stable deterministic IDs, and asserts explicit completeness.
    """
    if not isinstance(scan_data, Mapping):
        scan_data = {}

    nodes_by_id: dict[str, dict[str, Any]] = {}
    edges_set: set[tuple[str, str, str]] = set()

    findings_list = [
        f for f in scan_data.get("findings", [])
        if isinstance(f, Mapping)
    ]
    finding_refs = [_build_finding_reference(f) for f in findings_list]

    # Index findings by normalized URL
    findings_by_norm_url: dict[str, list[dict[str, Any]]] = {}
    for ref in finding_refs:
        norm_u = normalize_url_for_key(ref["url"])
        findings_by_norm_url.setdefault(norm_u, []).append(ref)

    # 1. Ingest explicit raw nodes (e.g. unknown node kinds, pre-formed nodes)
    raw_nodes = scan_data.get("nodes", [])
    if isinstance(raw_nodes, Sequence):
        for raw_node in raw_nodes:
            if not isinstance(raw_node, Mapping):
                continue
            orig_kind = str(raw_node.get("kind", ""))
            kind = normalize_node_kind(orig_kind)
            raw_url = str(raw_node.get("url") or "")
            safe_url = redact_url(raw_url)
            ident = str(raw_node.get("id") or raw_node.get("name") or raw_node.get("label") or "")
            node_id = generate_node_id(kind, raw_url, ident)
            norm_u = normalize_url_for_key(safe_url)

            label = str(raw_node.get("label") or raw_node.get("name") or safe_url)
            safe_label = redact_url(label) if label.startswith(("http://", "https://")) else redact_text(label)

            meta = dict(raw_node.get("metadata") or {})
            if orig_kind and orig_kind != kind:
                meta["original_kind"] = orig_kind

            node_dict = {
                "id": node_id,
                "kind": kind,
                "url": safe_url,
                "label": safe_label,
                "parent_id": raw_node.get("parent_id"),
                "actions": _redact_dict_values(list(raw_node.get("actions") or [])),
                "inputs": _redact_dict_values(list(raw_node.get("inputs") or [])),
                "findings": [],
                "metadata": _redact_dict_values(meta),
            }

            # Attach matching findings
            for f_ref in findings_by_norm_url.get(norm_u, []):
                node_dict["findings"].append(f_ref)

            nodes_by_id[node_id] = node_dict

    # 2. Ingest explicit raw edges
    raw_edges = scan_data.get("edges", [])
    if isinstance(raw_edges, Sequence):
        for raw_edge in raw_edges:
            if not isinstance(raw_edge, Mapping):
                continue
            src = str(raw_edge.get("source") or "")
            tgt = str(raw_edge.get("target") or "")
            ekind = str(raw_edge.get("kind") or "link")
            if src and tgt:
                edges_set.add((src, tgt, ekind))

    # 3. Ingest page_graph (e.g. from ScanEngine or MonitorServer)
    raw_page_graph = scan_data.get("page_graph", {})
    if isinstance(raw_page_graph, Mapping):
        for url, info in raw_page_graph.items():
            if not isinstance(url, str) or not url:
                continue
            info_dict = info if isinstance(info, Mapping) else {}
            safe_url = redact_url(url)
            norm_u = normalize_url_for_key(safe_url)
            page_id = generate_node_id("page", url)

            parent_url = str(info_dict.get("parent") or "")
            parent_id = generate_node_id("page", parent_url) if parent_url else None
            if parent_id:
                edges_set.add((parent_id, page_id, "navigates_to"))

            meta = {
                "depth": int(info_dict.get("depth", 0) or 0),
                "status": str(info_dict.get("status") or "done"),
                "forms_count": int(info_dict.get("forms", 0) or 0),
                "inputs_count": int(info_dict.get("inputs", 0) or 0),
                "params_count": int(info_dict.get("params", 0) or 0),
            }
            via = info_dict.get("via")
            if via and isinstance(via, Mapping):
                meta["via"] = _redact_dict_values(dict(via))

            if page_id not in nodes_by_id:
                page_node = {
                    "id": page_id,
                    "kind": "page",
                    "url": safe_url,
                    "label": safe_url,
                    "parent_id": parent_id,
                    "actions": [],
                    "inputs": [],
                    "findings": [],
                    "metadata": meta,
                }
                for f_ref in findings_by_norm_url.get(norm_u, []):
                    page_node["findings"].append(f_ref)
                nodes_by_id[page_id] = page_node
            else:
                nodes_by_id[page_id]["metadata"].update(meta)

            # URL parameters from query string
            try:
                parsed_q = parse_qsl(urlsplit(url).query, keep_blank_values=True)
            except Exception:
                parsed_q = []
            for q_name, _ in parsed_q:
                safe_q_name = redact_text(q_name)
                param_id = generate_node_id("param", url, f"query:{safe_q_name}")
                if param_id not in nodes_by_id:
                    p_node = {
                        "id": param_id,
                        "kind": "param",
                        "url": safe_url,
                        "label": safe_q_name,
                        "parent_id": page_id,
                        "actions": [],
                        "inputs": [{"name": safe_q_name, "carrier": "url_param"}],
                        "findings": [
                            f_ref for f_ref in findings_by_norm_url.get(norm_u, [])
                            if f_ref.get("field_name") == safe_q_name
                        ],
                        "metadata": {"carrier": "url_param"},
                    }
                    nodes_by_id[param_id] = p_node
                    edges_set.add((page_id, param_id, "has_param"))

    # 4. Ingest pages / crawled_pages (with rich form_details and param_names)
    pages_list = scan_data.get("pages") or scan_data.get("crawled_pages") or []
    if isinstance(pages_list, Sequence):
        for p in pages_list:
            if not isinstance(p, Mapping):
                continue
            p_url = str(p.get("url") or "")
            if not p_url:
                continue
            safe_url = redact_url(p_url)
            norm_u = normalize_url_for_key(safe_url)
            page_id = generate_node_id("page", p_url)

            if page_id not in nodes_by_id:
                page_node = {
                    "id": page_id,
                    "kind": "page",
                    "url": safe_url,
                    "label": safe_url,
                    "parent_id": None,
                    "actions": [],
                    "inputs": [],
                    "findings": list(findings_by_norm_url.get(norm_u, [])),
                    "metadata": {
                        "depth": int(p.get("depth", 0) or 0),
                        "forms_count": int(p.get("forms", 0) or 0),
                        "params_count": int(p.get("params", 0) or 0),
                    },
                }
                nodes_by_id[page_id] = page_node
            else:
                page_node = nodes_by_id[page_id]

            # Forms and form fields
            form_details = p.get("form_details", [])
            if isinstance(form_details, Sequence):
                for f_idx, form in enumerate(form_details):
                    if not isinstance(form, Mapping):
                        continue
                    f_action = str(form.get("action") or p_url)
                    safe_action = redact_url(f_action)
                    f_method = str(form.get("method") or "get").lower()
                    form_id = generate_node_id("form", p_url, str(f_idx))

                    form_node = {
                        "id": form_id,
                        "kind": "form",
                        "url": safe_action,
                        "label": f"Form {f_idx} ({f_method.upper()})",
                        "parent_id": page_id,
                        "actions": [{"action": safe_action, "method": f_method}],
                        "inputs": [],
                        "findings": [],
                        "metadata": {"form_index": f_idx, "method": f_method},
                    }

                    form_fields = form.get("fields", [])
                    field_names: set[str] = set()
                    if isinstance(form_fields, Sequence):
                        for field in form_fields:
                            if not isinstance(field, Mapping):
                                continue
                            fname = str(field.get("name") or "")
                            if not fname:
                                continue
                            safe_fname = redact_text(fname)
                            field_names.add(safe_fname)
                            ftype = str(field.get("type") or "text")
                            param_id = generate_node_id("param", p_url, f"form:{f_idx}:{safe_fname}")

                            param_node = {
                                "id": param_id,
                                "kind": "param",
                                "url": safe_action,
                                "label": safe_fname,
                                "parent_id": form_id,
                                "actions": [],
                                "inputs": [{"name": safe_fname, "type": ftype, "carrier": "form_field"}],
                                "findings": [
                                    f_ref for f_ref in findings_by_norm_url.get(norm_u, [])
                                    if f_ref.get("field_name") == safe_fname
                                ],
                                "metadata": {"carrier": "form_field", "form_index": f_idx},
                            }
                            nodes_by_id[param_id] = param_node
                            edges_set.add((form_id, param_id, "contains_param"))
                            form_node["inputs"].append({"name": safe_fname, "type": ftype})

                    # Form findings match if field_name is in form fields or field_name empty
                    form_node["findings"] = [
                        f_ref for f_ref in findings_by_norm_url.get(norm_u, [])
                        if f_ref.get("field_name") in field_names
                    ]
                    nodes_by_id[form_id] = form_node
                    edges_set.add((page_id, form_id, "contains_form"))

            # Param names
            param_names = p.get("param_names", [])
            if isinstance(param_names, Sequence):
                for pname in param_names:
                    safe_pname = redact_text(str(pname))
                    if not safe_pname:
                        continue
                    param_id = generate_node_id("param", p_url, f"query:{safe_pname}")
                    if param_id not in nodes_by_id:
                        p_node = {
                            "id": param_id,
                            "kind": "param",
                            "url": safe_url,
                            "label": safe_pname,
                            "parent_id": page_id,
                            "actions": [],
                            "inputs": [{"name": safe_pname, "carrier": "url_param"}],
                            "findings": [
                                f_ref for f_ref in findings_by_norm_url.get(norm_u, [])
                                if f_ref.get("field_name") == safe_pname
                            ],
                            "metadata": {"carrier": "url_param"},
                        }
                        nodes_by_id[param_id] = p_node
                        edges_set.add((page_id, param_id, "has_param"))

    # 5. Ingest visited_urls fallback
    visited_urls = scan_data.get("visited_urls", [])
    if isinstance(visited_urls, Sequence):
        for v_url in visited_urls:
            if not isinstance(v_url, str) or not v_url:
                continue
            page_id = generate_node_id("page", v_url)
            safe_url = redact_url(v_url)
            norm_u = normalize_url_for_key(safe_url)
            if page_id not in nodes_by_id:
                nodes_by_id[page_id] = {
                    "id": page_id,
                    "kind": "page",
                    "url": safe_url,
                    "label": safe_url,
                    "parent_id": None,
                    "actions": [],
                    "inputs": [],
                    "findings": list(findings_by_norm_url.get(norm_u, [])),
                    "metadata": {},
                }

    # 6. Ingest attack_plans if available
    attack_plans = scan_data.get("attack_plans", [])
    if isinstance(attack_plans, Sequence):
        for plan in attack_plans:
            if not isinstance(plan, Mapping):
                continue
            plan_url = str(plan.get("url") or "")
            if not plan_url:
                continue
            safe_plan_url = redact_url(plan_url)
            page_id = generate_node_id("page", plan_url)
            page_node = nodes_by_id.get(page_id)
            if page_node:
                page_node["metadata"]["page_purpose"] = redact_text(str(plan.get("page_purpose") or ""))

    # Sort nodes and edges deterministically
    nodes_list = sorted(
        nodes_by_id.values(),
        key=lambda n: (n["kind"], n["id"]),
    )
    edges_list = [
        {"source": s, "target": t, "kind": k}
        for s, t, k in sorted(edges_set)
    ]

    # Explicit completeness calculation
    status = str(scan_data.get("status") or "")
    phase = str(scan_data.get("phase") or "")
    aborted = bool(scan_data.get("aborted", False))
    scan_gaps = scan_data.get("scan_gaps") or []
    unscannable_urls = scan_data.get("unscannable_urls") or []
    truncation_counts = scan_data.get("truncation_counts") or {}
    exhausted_truncations = scan_data.get("exhausted_truncations") or []

    completeness, completeness_reasons = determine_completeness(
        status=status,
        phase=phase,
        aborted=aborted,
        scan_gaps=scan_gaps if isinstance(scan_gaps, Sequence) else [],
        unscannable_urls=unscannable_urls if isinstance(unscannable_urls, Sequence) else [],
        truncation_counts=truncation_counts if isinstance(truncation_counts, Mapping) else {},
        exhausted_truncations=exhausted_truncations if isinstance(exhausted_truncations, Sequence) else [],
        node_count=len(nodes_list),
    )

    summary = {
        "total_nodes": len(nodes_list),
        "pages_count": sum(1 for n in nodes_list if n["kind"] == "page"),
        "forms_count": sum(1 for n in nodes_list if n["kind"] == "form"),
        "params_count": sum(1 for n in nodes_list if n["kind"] == "param"),
        "unknown_count": sum(1 for n in nodes_list if n["kind"] == "unknown"),
        "total_edges": len(edges_list),
        "findings_count": sum(len(n["findings"]) for n in nodes_list if n["kind"] == "page"),
    }

    raw_target = str(scan_data.get("target_url") or scan_data.get("target") or "")
    return {
        "version": SCHEMA_VERSION,
        "scan_id": str(scan_data.get("scan_id") or ""),
        "target_url": redact_url(raw_target),
        "completeness": completeness,
        "completeness_reasons": completeness_reasons,
        "nodes": nodes_list,
        "edges": edges_list,
        "summary": summary,
    }

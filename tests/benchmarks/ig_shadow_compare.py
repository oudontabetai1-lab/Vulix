"""replay の work 実行結果を使い、現行順序（FIFO）と情報利得順序を仮想的に比較する（shadow 評価）。

実際の実行順序は変えない。work の結果（確証数）は work ごとに決定論なので、順序を入れ替えても
結果は変わらないという前提で、「その順で走らせた場合に何 step 目で確証が出るか」を数える。
"""
from __future__ import annotations

from wscan.information_gain import rank_candidates


def compare_trace(trace: list[dict], *, budget: int | None = None) -> dict:
    """work_trace（1 回の一括実行 = 1 要素）を FIFO と IG で比較する。"""
    rows = {"fifo": [], "ig": [], "ig_pure": []}
    for batch in trace:
        cands, results = batch["candidates"], batch["results"]
        fifo = [c.candidate_id for c in cands]
        orders = {
            "fifo": fifo,
            "ig": [r.candidate_id for r in rank_candidates(cands)],
            "ig_pure": [r.candidate_id for r in rank_candidates(cands, mandatory_first=False)],
        }
        mandatory = {c.candidate_id for c in cands if c.mandatory}
        cut = len(fifo) if budget is None else min(budget, len(fifo))
        for name, order in orders.items():
            confirm_steps = [i for i, w in enumerate(order, 1) if results.get(w, 0) > 0]
            rows[name].append({
                "first_confirm_step": confirm_steps[0] if confirm_steps else None,
                "last_confirm_step": confirm_steps[-1] if confirm_steps else None,
                "confirmed": len(confirm_steps),
                "mandatory_covered_in_budget": mandatory <= set(order[:cut]),
            })
    return rows

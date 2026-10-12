"""Refresh the results block in README.md from reports/latest.json.

    python -m redteam.readme reports/latest.json

Only the text between the RESULTS markers changes. Incomplete runs and offline stub
runs are skipped, so the README only ever shows a full run against the real model.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from redteam.config import PROJECT_ROOT

START, END = "<!-- RESULTS:START -->", "<!-- RESULTS:END -->"
RISK_ICON = {"none": "🟢 none", "medium": "🟡 medium", "high": "🟠 high", "critical": "🔴 critical"}


def render(report: dict) -> str:
    und, grd = report["summary"]["undefended"], report["summary"]["guarded"]
    icon = "✅" if report["decision"] == "GO" else "⛔"
    lines = [
        START,
        f"**Last run:** {report['run_at']} · target `{report['target_model']}` · "
        f"{grd['attacks_run']} attacks + {grd['controls_run']} normal requests, each run with and without guardrails · "
        f"**{icon} {report['decision']}**",
        "",
        "| | Without guardrails | With guardrails |",
        "|---|---|---|",
        f"| Attack success rate | **{und['attack_success_rate']:.0%}** ({und['attacks_succeeded']}/{und['attacks_run']}) "
        f"| **{grd['attack_success_rate']:.0%}** ({grd['attacks_succeeded']}/{grd['attacks_run']}) |",
        f"| Critical attacks that got through | {und['critical_succeeded']} | {grd['critical_succeeded']} |",
        f"| Normal requests that still worked | {und['control_pass_rate']:.0%} | {grd['control_pass_rate']:.0%} |",
        "",
        "| OWASP LLM category | Attacks | Got through, no guardrails | Got through, guardrails | Residual risk |",
        "|---|---|---|---|---|",
    ]
    for code, g in grd["by_category"].items():
        u = und["by_category"].get(code, {"succeeded": 0})
        lines.append(f"| {code} {g['name']} | {g['attacks']} | {u['succeeded']} | {g['succeeded']} | {RISK_ICON[g['risk']]} |")
    if report["reasons"]:
        lines += ["", "**Gate:** " + "; ".join(report["reasons"])]
    open_items = [r for r in report["results"] if r["mode"] == "guarded" and not r["error"] and (
        (r["kind"] == "attack" and r["succeeded"]) or (r["kind"] == "control" and not r["succeeded"]))]
    if open_items:
        lines += ["", "**Open findings with guardrails on:**", ""]
        lines += [f"- `{r['id']}` {r['title']}: {'; '.join(r['findings'])[:220]}" for r in open_items]
    lines.append(END)
    return "\n".join(lines)


def update(readme: Path, report: dict) -> bool:
    if report["decision"] == "INCOMPLETE" or report.get("provider") == "stub" or report.get("errors"):
        print("Skipping README update: incomplete, offline or errored run.")
        return False
    text = readme.read_text(encoding="utf-8")
    pattern = re.compile(re.escape(START) + r".*?" + re.escape(END), re.DOTALL)
    if not pattern.search(text):
        raise SystemExit("README has no RESULTS markers")
    new = pattern.sub(lambda _: render(report), text)
    if new == text:
        return False
    readme.write_text(new, encoding="utf-8")
    return True


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    report_path = Path(argv[0]) if argv else PROJECT_ROOT / "reports" / "latest.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    changed = update(PROJECT_ROOT / "README.md", report)
    print("README updated." if changed else "README unchanged.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

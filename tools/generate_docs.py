#!/usr/bin/env python3
"""Generate route table and both skill copies; --check fails on drift."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from iterm2_harness.routes import directory


def outputs():
    api = ROOT / "docs/API.md"
    start, end = "<!-- BEGIN GENERATED ROUTES -->", "<!-- END GENERATED ROUTES -->"
    before, rest = api.read_text().split(start, 1)
    _, after = rest.split(end, 1)
    rows = ["| Method | Path | Required capability | v1 alias |",
            "|---|---|---|---|"]
    for route in directory():
        authority = route["scope"] or ("Authenticated" if route["auth"] else "Public")
        rows.append("| %s | `%s` | `%s` | %s |" %
                    (route["method"], route["path"], authority,
                     "Yes" if route["v1_alias"] else "No"))
    skill = (ROOT / "tools/skill_template.md").read_text()
    return {api: before + start + "\n\n" + "\n".join(rows) + "\n\n" + end + after,
            ROOT / "SKILL.md": skill, ROOT / "skills/iterm2-harness/SKILL.md": skill}


if __name__ == "__main__":
    mismatch = []
    for path, expected in outputs().items():
        if not path.exists() or path.read_text() != expected:
            mismatch.append(str(path.relative_to(ROOT)))
            if "--check" not in sys.argv:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(expected)
    if mismatch and "--check" in sys.argv:
        raise SystemExit("Generated documentation differs: " + ", ".join(mismatch))

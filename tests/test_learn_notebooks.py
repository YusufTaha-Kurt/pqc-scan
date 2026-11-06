"""Execute the code cells of the learn notebooks; their asserts must hold."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

import pytest

NOTEBOOKS = sorted((Path(__file__).resolve().parent.parent / "docs" / "learn").glob("*.ipynb"))


def test_notebooks_exist() -> None:
    assert {p.stem for p in NOTEBOOKS} == {"bb84", "grover", "shor"}


@pytest.mark.parametrize("path", NOTEBOOKS, ids=lambda p: p.stem)
def test_notebook_runs(path: Path) -> None:
    notebook = json.loads(path.read_text(encoding="utf-8"))
    namespace: dict[str, object] = {"__name__": "__notebook__"}
    with contextlib.redirect_stdout(io.StringIO()) as output:
        for cell in notebook["cells"]:
            if cell["cell_type"] == "code":
                exec(compile("".join(cell["source"]), str(path), "exec"), namespace)  # noqa: S102
    assert output.getvalue()  # every notebook prints something to look at

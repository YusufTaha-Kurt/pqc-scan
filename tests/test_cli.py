from typer.testing import CliRunner

from pqc_scan import __version__
from pqc_scan.cli import AUTHORIZATION_WARNING, app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_help_contains_authorization_warning() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    normalized = " ".join(result.output.split())
    assert "written permission" in normalized
    assert "written permission" in AUTHORIZATION_WARNING

"""
Tests for the cli
"""
from typer.testing import CliRunner
from scf import __version__, cli


runner = CliRunner()


def test_version():
    """
    Test if the correct version is printed
    """
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert f"v{__version__}\n" in result.stdout

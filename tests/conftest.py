from __future__ import annotations

import logging

import pytest

from tests.fakes import assert_clean


@pytest.fixture(autouse=True)
def fast_purge_retries(monkeypatch):
    monkeypatch.setattr("secret_remediation.purge.RETRY_DELAYS", (0.0, 0.01))


@pytest.fixture(autouse=True)
def hermes_home(tmp_path, monkeypatch):
    home = tmp_path / "hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("TERMINAL_CWD", raising=False)
    return home


@pytest.fixture(autouse=True)
def no_secret_in_output(capsys):
    records: list[str] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record.getMessage())

    handler = Capture()
    root = logging.getLogger()
    root.addHandler(handler)
    yield
    from secret_remediation.purge import flush_purges

    flush_purges()
    root.removeHandler(handler)
    captured = capsys.readouterr()
    assert_clean(captured.out)
    assert_clean(captured.err)
    assert_clean("\n".join(records))
    from secret_remediation.paths import incidents_path

    path = incidents_path()
    if path.is_file():
        assert_clean(path.read_text(encoding="utf-8"))

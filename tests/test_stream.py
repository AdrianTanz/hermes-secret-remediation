from __future__ import annotations

from secret_remediation.redact import fingerprint
from secret_remediation.scan import format_report, scan_file
from secret_remediation.stream import CHUNK_BYTES, scan_byte_stream, scan_texts
from tests.fakes import GITHUB, assert_clean


def test_secret_split_across_chunks_is_one_fingerprint():
    head = "x" * (CHUNK_BYTES - 10)
    tail = "y" * 100
    blob = (head + GITHUB + tail).encode()
    pieces = [blob[:CHUNK_BYTES], blob[CHUNK_BYTES:]]
    assert len(pieces) == 2
    assert GITHUB.encode() not in pieces[0]
    assert GITHUB.encode() not in pieces[1]

    def chunks():
        yield from pieces

    hits = scan_byte_stream(chunks())
    assert len(hits) == 1
    hit, _line = hits[0]
    assert hit.fingerprint == fingerprint(GITHUB)
    assert_clean(repr(hit))


def test_large_session_file_is_not_loaded_as_one_string(tmp_path):
    path = tmp_path / "session.jsonl"
    filler = "a" * CHUNK_BYTES
    path.write_bytes((filler + "\n" + GITHUB + "\n" + filler).encode())
    calls = {"n": 0}

    def counting():
        with path.open("rb") as handle:
            while True:
                blob = handle.read(CHUNK_BYTES)
                if not blob:
                    return
                calls["n"] += 1
                assert len(blob) <= CHUNK_BYTES
                yield blob

    hits = scan_byte_stream(counting())
    assert calls["n"] >= 3
    assert hits[0][0].fingerprint == fingerprint(GITHUB)
    findings_text = format_report(
        [],
        heading="unused",
    )
    assert_clean(findings_text)


def test_session_file_report_has_fingerprint_only(tmp_path):
    from secret_remediation.scan import Finding
    from secret_remediation.redact import PublicHit

    path = tmp_path / "sessions" / "abc.jsonl"
    path.parent.mkdir()
    path.write_text("note\n" + GITHUB + "\n", encoding="utf-8")
    found = scan_file(path, path.parent, unbounded=True)
    assert len(found) == 1
    assert isinstance(found[0], Finding)
    report = format_report(found, heading="secret-remediation scan")
    assert fingerprint(GITHUB) in report
    assert "abc.jsonl" in report
    assert_clean(report)
    assert not hasattr(found[0], "value")


def test_text_stream_does_not_require_a_joined_buffer():
    parts = ["hello ", GITHUB[:8], GITHUB[8:], " bye"]

    def pieces():
        yield from parts

    hits = scan_texts(pieces())
    assert len(hits) == 1
    assert hits[0][0].fingerprint == fingerprint(GITHUB)

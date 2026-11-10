# Checklist

The task note `05_Systems/Tasks/2026-11-10-1441-hermes-secret-remediation-plugin.md` at commit `01e39471` in `AdrianTanz/SecondBrain` was not readable from this environment (private repository, `gh` unauthenticated, raw URL 404). The boxes below follow the build instructions and Adrian's later answers. They are not a verbatim copy of that note.

## 1. Plugin shape

- [x] `plugin.yaml` plus `register(ctx)`
- [x] Catalogue id and title: `secret-remediation`
- [x] Author: Adrian Tanz, solo

## 2. Hooks verified against Hermes source

Checked against Hermes Agent v0.23.1 (`hermes_cli/plugins_context.py`, hook docs).

- [x] `pre_llm_call`
- [x] `pre_tool_call`
- [x] `transform_tool_result`
- [x] `transform_terminal_output`
- [x] `transform_llm_output` (`hold_stream=True`)
- [x] `ctx.register_redaction_patterns`
- [x] Does not call `ctx.redact_text()`

## 3. Secrets stay out of output and storage

- [x] Incidents store kind, fingerprint, length, source, location
- [x] Reports and slash-command replies show the fingerprint
- [x] Tests use synthetic tokens and fail if the full value appears in stdout, stderr, logs, or the incident file
- [x] Session history, logs, and `state.db` are streamed in windows. The file is not joined into one string

## 4. Advice only

- [x] Rotation steps are text
- [x] Git-history cleanup is text (names git-filter-repo and BFG, does not run them)
- [x] No live revoke API
- [x] No history rewrite
- [x] No push, and no `--force` command

## 5. Zero-model schedule

- [x] `hermes secret-remediation schedule`
- [x] Writes `$HERMES_HOME/scripts/secret-remediation-scan.py`
- [x] Creates `hermes cron create <schedule> --no-agent --script secret-remediation-scan.py`
- [x] The script calls `scheduled_main` and does not call a model
- [x] `hermes secret-remediation scan`
- [x] `/secret-incident`

## 6. Default paths, and a way to change them

From Hermes v0.23.1:

- [x] Workspace: `TERMINAL_CWD` when it is a real directory and not a sentinel (`agent/runtime_cwd.py`, `tools/file_tools_paths.py`), else the process cwd
- [x] Logs: `$HERMES_HOME/logs` (`hermes_logging.setup_logging`)
- [x] Session history: `$HERMES_HOME/sessions` (`divert_session_transcript_jsonl`, `_remove_session_files`) plus `$HERMES_HOME/state.db` and `state.db-wal` (`doctor_state.py`)
- [x] `hermes secret-remediation paths`, `paths set`, `paths reset`, and `--path` on `scan` and `schedule`

## 7. Licence

- [x] MIT, final
- [x] Copyright holder Adrian Tanz, 2026
- [ ] Byte-for-byte diff against the private GitHub `LICENSE` (that file returned 404 here). This tree uses the standard GitHub MIT template with that copyright line.

## 8. Hackathon pack, not a submission

- [x] `catalog/secret-remediation.yaml` with repo URL `https://github.com/AdrianTanz/hermes-secret-remediation`
- [x] `catalog/PR_DESCRIPTION.md`
- [x] `README.md`
- [x] `demo/DEMO_SCRIPT.md` (storyboard, under 90 seconds)
- [x] `DEMO_POST.md` draft, tags `@NousResearch`, not posted
- [x] No catalogue pull request, no X post, no form submission

## 9. Tests

- [x] `python3 -m pytest` — 28 passed in this environment
- [ ] `hermes plugins validate` / `hermes plugins doctor` (Hermes is not installed here)
- [ ] A live Hermes session: paste a fake token, confirm the turn is blocked and the transcript placeholder does not contain it

## 10. Open for Adrian

- [ ] Read the private task note and mark anything this build missed
- [ ] Diff `LICENSE` with the commit already on `AdrianTanz/hermes-secret-remediation`
- [ ] Mirror this tree to that GitHub repo, then replace the catalogue `sha` with the full 40-character commit
- [ ] Run `hermes plugins validate` on the pinned commit
- [ ] Approve or edit `DEMO_POST.md` before anything is posted
- [ ] Open the catalogue PR, post the demo, and submit the form only after that review

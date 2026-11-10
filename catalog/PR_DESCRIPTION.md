# secret-remediation

Draft for Adrian. Do not open this pull request until he has reviewed it and the catalogue `sha` is the real commit on `https://github.com/AdrianTanz/hermes-secret-remediation`.

## What it does

`secret-remediation` stops credential-shaped text from travelling further through Hermes, and it tells the user how to rotate the credential and clean git history. The value is not stored and not printed. Incidents carry a kind and a fingerprint.

Author: Adrian Tanz.

## Surfaces

- Hooks: `pre_llm_call`, `pre_tool_call`, `transform_tool_result`, `transform_terminal_output`, `transform_llm_output` (`hold_stream=True`)
- `ctx.register_redaction_patterns` (additive). The plugin does not call `ctx.redact_text()`
- CLI: `hermes secret-remediation scan|schedule|paths|advice|incidents`
- Slash command: `/secret-incident`
- Cron: writes `$HERMES_HOME/scripts/secret-remediation-scan.py` and runs `hermes cron create <schedule> --no-agent --script secret-remediation-scan.py`. The script does not call a model.

`requires_hermes: ">=0.22.0"`. Those hooks and `register_redaction_patterns` are present on the v0.22.0, v0.22.7, and v0.23.1 tags.

## Default paths

- Workspace: `TERMINAL_CWD` when it names a real directory and is not one of the sentinels in `tools/file_tools_paths.py` (`""`, `"."`, `"./"`, `"auto"`, `"cwd"`). Otherwise the process cwd (`agent/runtime_cwd.py` `resolve_agent_cwd`).
- `$HERMES_HOME/logs` (`hermes_logging.setup_logging`)
- `$HERMES_HOME/sessions` (`hermes_state.divert_session_transcript_jsonl`, `hermes_state_sessions._remove_session_files`)
- `$HERMES_HOME/state.db` and `state.db-wal` (`hermes_cli/doctor_state.py`)

`hermes secret-remediation paths set` replaces that list. `paths reset` restores it.

Session history, logs, and the database are read in 64KiB windows. A match is hashed in the window. The value is not written to the report or the incident log.

## Rule 13

- Reads the files on the scan list. By default that is the workspace, Hermes logs, session files, and `state.db` / `state.db-wal`. It does not read `$HERMES_HOME/.env` or `$HERMES_HOME/auth.json`.
- Does not use a value it finds. It hashes it, discards it, and stores the fingerprint.
- Writes `$HERMES_HOME/plugin-data/agent-plugin-secret-remediation-<digest>/incidents.jsonl` and `scan_paths.json` (mode 0600).
- Writes `$HERMES_HOME/scripts/secret-remediation-scan.py` (mode 0700).
- Spawns `hermes cron create … --no-agent --script …` when scheduling. If `hermes` is not on `PATH`, the wrapper is still written and the command is printed.
- Spawns read-only `git rev-parse`, `rev-list`, `grep`, and `show` only when `--git-history` is set. No other git subcommand is allowed. Git history rewrite is not implemented.
- No network calls, no telemetry, no revoke API, no push.
- Blocks the current turn and blocks tool calls when a credential is present. A failed scan fails closed (the text is withheld, not forwarded).
- `hold_stream` on `transform_llm_output` so the raw reply is not streamed to the user.
- Tests under `tests/fakes.py` contain synthetic tokens that match the detectors. They are not live credentials.

## Not in this version

Live revoke APIs are cut. History rewrite and push are cut. Both are described as steps for the user to run.

# secret-remediation

## What it does

`secret-remediation` stops credential-shaped text from travelling further through Hermes, and it tells the user how to rotate the credential and clean git history. Incident lines store a kind and a fingerprint, not the value. Hermes can still have written the typed text; the plugin then tries to replace it in `messages.display_metadata.withheld_prompt`, `session_admissions.payload_json`, and `spawn-ledger.json` `argv`. Writes happen by default, including after a block. `purge --dry-run` only prints counts. Shell history (files outside Hermes) and chat history are rewritten unless you opt out. See the README section Purge.

Author: AdrianTanz.

## Surfaces

- Hooks: `pre_llm_call`, `pre_tool_call`, `transform_tool_result`, `transform_terminal_output`, `transform_llm_output` (`hold_stream=True`)
- `ctx.register_redaction_patterns` (additive). The plugin does not call `ctx.redact_text()`
- CLI: `hermes secret-remediation scan|purge|schedule|paths|advice|incidents`. `purge` writes unless `--dry-run`. Opt out: `--no-sessions`, `--no-messages`, `--no-shell-history`, `--no-backups`, `--no-vacuum`. `--keep-backups` keeps the safety copy.
- Slash command: `/secret-incident`
- Cron: writes `$HERMES_HOME/scripts/secret-remediation-scan.sh`, which execs `hermes secret-remediation scan --quiet`, and runs `hermes cron create "0 3 * * *" --no-agent --script secret-remediation-scan.sh --deliver local --name secret-remediation-scan`. There is no `ctx.register_cron_job`. The script does not call a model.

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
- Does not send a value it finds to a model, a revoke API, or the network. It hashes it. Incident lines store the fingerprint and the last 4 characters, not the value.
- Writes happen by default, on a block and on `purge` / `scan --purge`. `--dry-run` prints counts only. Opt out with `--no-sessions`, `--no-messages`, `--no-shell-history`, `--no-backups`, `--no-vacuum`, or the matching `purge_*` settings and `SECRET_REMEDIATION_NO_*` env vars.
- By default it rewrites shell history and chat history. Shell history is outside Hermes: `~/.bash_history`, `~/.zsh_history`, and fish history. Chat history is the Hermes columns and `$HERMES_HOME/sessions/**/*.jsonl` (recursive).
- Placeholder rewrites:
  - `messages.display_metadata` key `withheld_prompt`. A blocked-turn `/retry` reads this key.
  - `messages.content`, `api_content`, `tool_calls`, and the other `display_metadata` strings. This is separate from that `/retry`. A replayed tool call sends the placeholder in its arguments, because Hermes re-reads the input from `tool_calls`.
  - `session_admissions.payload_json`, and `payload_digest` recomputed over the redacted payload. Replaying the original request is refused. That is expected. The old value is not restored.
  - `spawn-ledger.json` field `argv`
  - `state-snapshots/**/state.db` and `state.db.pre-update-emergency-*.bak`
- `VACUUM` plus `PRAGMA secure_delete` on that connection only, when `state.db` and its WAL are not open. If they are open, the summary names `incomplete=vacuum` and the other stores still finish. Later Hermes writes do not inherit `secure_delete`.
- A safety copy is deleted only after the file or database reopens, parses, keeps the same line and row counts, differs only by placeholders, and still has a matching `payload_digest`. On a failed check or a crash mid-rewrite, the copy is kept and its path is printed. `--keep-backups` keeps it anyway.
- Not covered: provider logs (the report prints `rotate_or_revoke=<kind>` and does not call a provider), `backups/pre-update-*.zip` and `backups/pre-migration-*.zip` (counted, not rewritten), Time Machine, cloud sync, other external backups, `sessions.title`, terminal scrollback, a secret split across JSONL lines, and SSD remnants.
- A failed rewrite is logged as `purge_failed` with no secret. Hermes can write `withheld_prompt` again after the short automatic retry. A running shell can write its memory back over a history file on exit. Close other shells first, or run `history -c` in them. History-file mtime, permissions, and ownership are kept. `scan --purge` accepts the same `--no-*` flags as `purge`.
- Writes `$HERMES_HOME/plugin-data/secret-remediation/incidents.jsonl` via `plugin_data_dir("secret-remediation")`, plus `scan_paths.json` (mode 0600).
- Writes `$HERMES_HOME/scripts/secret-remediation-scan.sh` (mode 0700).
- Spawns `hermes cron create … --no-agent --script …` when scheduling. If `hermes` is not on `PATH`, the wrapper is still written and the command is printed.
- Spawns read-only `git rev-parse`, `rev-list`, `grep`, and `show` only when `--git-history` is set. No other git subcommand is allowed. Git history rewrite is not implemented.
- No network calls, no telemetry, no revoke API, no push.
- Blocks the current turn and blocks tool calls when a credential is present. A failed scan fails closed (the text is withheld, not forwarded).
- `hold_stream` on `transform_llm_output` so the raw reply is not streamed to the user.
- Tests under `tests/fakes.py` contain synthetic tokens that match the detectors. They are not live credentials.

## Not in this version

Live revoke APIs are cut. History rewrite and push are cut. Both are described as steps for the user to run.

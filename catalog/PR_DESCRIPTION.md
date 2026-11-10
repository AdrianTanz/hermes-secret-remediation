# secret-remediation

Draft for Adrian. Do not open this pull request until he has reviewed it and the catalogue `sha` is the real commit on `https://github.com/AdrianTanz/hermes-secret-remediation`.

## What it does

`secret-remediation` stops credential-shaped text from travelling further through Hermes, and it tells the user how to rotate the credential and clean git history. Incident lines store a kind and a fingerprint, not the value. Hermes can still have written the typed text; the plugin then tries to replace it in `messages.display_metadata.withheld_prompt`, `session_admissions.payload_json`, and `spawn-ledger.json` `argv`. That purge does not cover provider logs, backups, shell history, or session JSONL. See the README section Known limitations.

Author: AdrianTanz.

## Surfaces

- Hooks: `pre_llm_call`, `pre_tool_call`, `transform_tool_result`, `transform_terminal_output`, `transform_llm_output` (`hold_stream=True`)
- `ctx.register_redaction_patterns` (additive). The plugin does not call `ctx.redact_text()`
- CLI: `hermes secret-remediation scan|schedule|paths|advice|incidents`
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
- After a block, and when `purge --apply` or `scan --purge --apply` is used, rewrites credential-shaped text to the `[secret:kind:fingerprint]` placeholder in:
  - `$HERMES_HOME/state.db` `messages.display_metadata` key `withheld_prompt`
  - `$HERMES_HOME/state.db` `session_admissions.payload_json`, and `payload_digest` when that column exists (Hermes v0.23.1 canonical hash of the redacted payload)
  - `spawn-ledger.json` field `argv`, at `$HERMES_HOME/spawn-ledger.json` and, when the home is `<root>/profiles/<name>`, at `<root>/spawn-ledger.json`
- `purge` and `scan --purge` without `--apply` only print counts. They do not write those stores.
- Opt-in flags, dry-run unless `--apply`, each file backed up under `plugin-data/secret-remediation/backups/` before a rewrite. A failed backup leaves the original and logs `purge_failed`. The output is counts and kind names, not the secret.
  - `--sessions` rewrites `$HERMES_HOME/sessions/**/*.jsonl` line by line. A value split across lines stays.
  - `--messages` rewrites `messages.content`, `api_content`, `tool_calls`, and `display_metadata` strings other than `withheld_prompt`. Resume and `/retry` then see the placeholder, including tool arguments. `sessions.title` is not rewritten.
  - `--vacuum` sets `PRAGMA secure_delete` for that connection only and runs `VACUUM` on the live `state.db`. It refuses if another process has the database open or `/proc` cannot be checked. Later Hermes writes do not inherit `secure_delete`. The backup still holds the old pages.
  - `--shell-history` rewrites `~/.bash_history`, `~/.zsh_history`, and fish history. A running shell can write its in-memory history back over the file on exit.
  - `--backups` rewrites `state-snapshots/**/state.db` and `state.db.pre-update-emergency-*.bak`. Zip files in `backups/` are counted and not rewritten. Other backups are out of scope.
- Provider logs are not cleared and no provider API is called. The report prints `rotate_or_revoke=<kind>` plus a documentation link when one exists.
- The default purge still does not clear `sessions.title`, zip archives, arbitrary backups, terminal scrollback, SSD remnants, or incident fingerprints. A failed rewrite is logged as `purge_failed` and the plaintext can remain. Hermes can write `withheld_prompt` again after the short automatic retry.
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

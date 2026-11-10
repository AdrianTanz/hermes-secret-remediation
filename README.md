# secret-remediation

Hermes Agent plugin. It finds credential-shaped text in the Hermes workspace, in Hermes logs, and in session history, then records a fingerprint. It does not keep the value.

Author: Adrian Tanz.

The public repo this will be published from is [AdrianTanz/hermes-secret-remediation](https://github.com/AdrianTanz/hermes-secret-remediation).

## What it does

- Blocks the current user message (`pre_llm_call`) when it contains a credential, before the model sees it.
- Blocks a tool call (`pre_tool_call`) when any nested argument contains a credential.
- Rewrites tool results, terminal output, and the final reply (`transform_tool_result`, `transform_terminal_output`, `transform_llm_output` with `hold_stream`). The reply is held until it has been rewritten.
- Registers the same patterns with `ctx.register_redaction_patterns`, so Hermes's own redactor masks them in logs and transcripts. It does not call `ctx.redact_text()`.
- Writes incidents under `$HERMES_HOME/plugin-data/`. Each row has a kind, a 12-character SHA-256 fingerprint, a length, a source, and a location. The value is not in the row.
- Prints rotation steps and git-history cleanup as text. It does not call a revoke API, rewrite history, or push.
- `hermes secret-remediation schedule` writes `$HERMES_HOME/scripts/secret-remediation-scan.py` and creates `hermes cron create <schedule> --no-agent --script secret-remediation-scan.py`. That job does not call a model. Empty stdout means nothing new.

A scanner error on the way into the model or into a tool stops the turn or the tool. A scanner error on output replaces the text with a fixed withhold line. The original text is not forwarded.

## Default scan paths

Resolved from Hermes Agent v0.23.1:

| Role | Path | Source |
| --- | --- | --- |
| Workspace | `$TERMINAL_CWD` when it is a real directory and not `""`, `"."`, `"./"`, `"auto"`, or `"cwd"`. Otherwise the process cwd. | `agent/runtime_cwd.py` `resolve_agent_cwd`, `tools/file_tools_paths.py` `_TERMINAL_CWD_SENTINELS` |
| Logs | `$HERMES_HOME/logs` | `hermes_logging.setup_logging` |
| Session files | `$HERMES_HOME/sessions` (`<id>.jsonl`, `<id>.json`, `session_<id>.json`, `request_dump_<id>_*.json`) | `hermes_state.divert_session_transcript_jsonl`, `hermes_state_sessions._remove_session_files` |
| Session database | `$HERMES_HOME/state.db` and `state.db-wal` | `hermes_cli/doctor_state.py` |

Session history, logs, and the database are streamed in 64KiB windows with an 8KiB overlap. A match is hashed inside the window. The file is not loaded as one string, and the value is not emitted.

Workspace files larger than 32MiB, and workspace files whose first 8KiB contain a NUL, are skipped. Session history and logs are not capped that way.

`$HERMES_HOME/.env` and `$HERMES_HOME/auth.json` are not read.

The list is configurable:

```bash
hermes secret-remediation paths
hermes secret-remediation paths set --path ~/src/app --path ~/.hermes/logs --path ~/.hermes/sessions
hermes secret-remediation paths reset
hermes secret-remediation scan --path ~/src/app
```

`scan --path` and `schedule --path` apply to that invocation. `paths set` is the saved list used when you omit `--path`.

## Install into Hermes

Hermes 0.22.0 or newer.

From this checkout, before the GitHub repo is public:

```bash
mkdir -p ~/.hermes/plugins
rm -rf ~/.hermes/plugins/secret-remediation
cp -a . ~/.hermes/plugins/secret-remediation
hermes plugins enable secret-remediation
```

After `AdrianTanz/hermes-secret-remediation` is public:

```bash
hermes plugins install AdrianTanz/hermes-secret-remediation --enable
```

Check the load:

```bash
hermes plugins doctor ~/.hermes/plugins/secret-remediation --ci
```

## Commands

```bash
hermes secret-remediation scan
hermes secret-remediation scan --git-history
hermes secret-remediation scan --json
hermes secret-remediation schedule
hermes secret-remediation schedule --every "every 6h" --deliver local
hermes secret-remediation advice github_pat
hermes secret-remediation incidents
```

In a session:

```text
/secret-incident
/secret-incident advice
/secret-incident <id>
```

`--git-history` is off unless you set it. It runs read-only `git rev-list`, `git grep -l`, and `git show`, capped at 40 commits, and streams each blob. It does not rewrite the repository.

The cron script prints only fingerprints that are not already in the incident log. A clean tick prints nothing, which is how Hermes no-agent cron stays silent.

## Tests

```bash
python3 -m pytest
```

The tests use synthetic tokens. They fail if a full token appears in stdout, stderr, log records, or the incident file.

## Limits

- Prefixes and a PEM block. Not every encoding, split, or low-entropy password.
- `pre_llm_call` can block the current message. It cannot rewrite an earlier transcript row that already contains a credential.
- `hold_stream` stops the final reply from streaming the raw text. Tool-progress lines are Hermes's own display and are outside this hook.
- This plugin was not executed inside a running Hermes process in the environment that built it. `hermes plugins validate` still needs to be run on a machine that has Hermes installed.

## Licence

MIT. Copyright (c) 2026 Adrian Tanz.

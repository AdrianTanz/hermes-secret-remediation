# secret-remediation

A Hermes operator's credential has already shown up in a chat turn, a tool result, a log, or a commit. This plugin detects that leak, stops it going any further, and tells you how to rotate it and how to clean git history.

It is not another masking pack. Marketplace **secret-guard** takes keys in and redacts them on the way in. **redaction-pack** adds vendor regexes. This plugin starts after the leak. Masking a later turn does not un-leak a value that already reached a model, a pushed git object, or a sent chat. Rotate first.

Author: AdrianTanz.

Canonical repo, private until you approve a submission: [AdrianTanz/hermes-secret-remediation](https://github.com/AdrianTanz/hermes-secret-remediation).

## What it does

- `pre_llm_call` blocks the current message before any model call. The block text names the type and a fingerprint. Hermes stores a placeholder in the message body. The typed text is still on disk until the purge in Known limitations runs.
- `pre_tool_call` blocks a tool whose arguments contain a credential.
- `transform_tool_result`, `transform_terminal_output`, and `transform_llm_output` (`hold_stream=True`) rewrite matches so later turns stay masked.
- `ctx.register_redaction_patterns` adds those shapes to Hermes's own redactor. The plugin does not call `ctx.redact_text()`.
- Incidents go to `plugin_data_dir("secret-remediation")` (`$HERMES_HOME/plugin-data/secret-remediation/incidents.jsonl`): type, SHA-256 fingerprint (12 hex chars), last 4 characters, length, location, timestamp. The incident line does not contain the value. A failed purge is a `purge_failed` line with a fixed location code and an empty fingerprint.
- Rotation checklists and git-history cleanup are text. `git filter-repo` and BFG are shown as commands for you to run on a mirror clone. The plugin does not run them, does not push, and does not call a revoke API.

## Known limitations

Blocking a turn does not delete the text you typed. Hermes writes it after the hook returns. This plugin then tries to replace credential-shaped text with the same `[secret:kind:fingerprint]` placeholder in three places:

- `$HERMES_HOME/state.db` (mode 0600), `messages.display_metadata` key `withheld_prompt`
- `$HERMES_HOME/state.db`, `session_admissions.payload_json`, and `payload_digest` when that column exists. The digest is the Hermes v0.23.1 canonical hash of the redacted payload. A later Hermes that changes that hash can refuse a replay. It does not put the old value back.
- `spawn-ledger.json` (mode 0600) field `argv`, at `$HERMES_HOME/spawn-ledger.json` and, when the home is `<root>/profiles/<name>`, at `<root>/spawn-ledger.json`

The rewrite is one transaction for the database and an exclusive lock plus an atomic replace for the ledger. Other rows, columns, and ledger fields stay. A lock timeout or a corrupt file is appended to the incident log as `purge_failed` and the plaintext can remain. The automatic pass retries for about a second and a half, because Hermes stores `withheld_prompt` after the hook returns. A later flush from Hermes can write the value again after that window.

Manual pass. The default prints counts only:

```bash
hermes secret-remediation purge
hermes secret-remediation purge --apply
hermes secret-remediation scan --purge
hermes secret-remediation scan --purge --apply
```

A successful purge does not remove:

- Provider logs, or any copy that already reached a model, a fork, or a sent chat
- Shell history and terminal scrollback
- Backups and snapshots (`state-snapshots/`, `hermes backup`, `state.db` copies, files you copied)
- SQLite free-page slack, and `state.db-wal` when a checkpoint cannot run. This plugin does not `VACUUM` a live database
- `$HERMES_HOME/sessions/` JSONL files
- `messages.content`, `messages.api_content`, `messages.tool_calls`, session titles, and any `display_metadata` key other than `withheld_prompt`
- Incident lines, which keep a fingerprint and the last 4 characters

Rotate the credential. Replacing or deleting a local file does not un-leak a value that already left the machine. After you rotate, delete shell history and any backup or session JSONL that still has the old value. If you need the free pages gone, stop Hermes and `VACUUM` `state.db` yourself. This plugin will not do that.

Detection this version does not do:

- `Authorization: Basic`
- `password:` / `api_key:` / `secret:` with a colon. Only `=` assignments are detected, in the literal forms `password`, `PASSWORD`, `api_key`, `API_KEY`, `api-key`, `API-KEY`, `apikey`, `APIKEY`, `secret`, and `SECRET`
- Assignment values shorter than 8 characters, or the placeholders `changeme`, `password`, `secret`, `example`, `placeholder`, `none`, `null`, `true`, `false`, `undefined`, and `your…`
- URL userinfo for schemes other than http, https, postgres, postgresql, mysql, mongodb, mongodb+srv, redis, rediss, amqp, amqps, ftp, and ftps
- An unlabelled AWS secret access key that is 40 hex characters (the same shape as a git SHA), or one that contains neither `+` nor `/`. A mixed-case 40-character key that contains `+` or `/` is detected by this plugin's hooks and scan only. It is not registered with Hermes's redactor: that registry requires a literal prefix, and a bare key has none
- Generic `.env` lines that are not one of the assignments above and do not carry a known token prefix
- Encoded or split values

A git SHA, a UUID, a hash, a base64 image, and prose that mentions "password" without `password=` or `PASSWORD=` are not treated as secrets.

## Default scan paths

From a local Hermes Agent v0.23.1 install (`3b421578`) and its source:

| Role | Path | Where it comes from |
| --- | --- | --- |
| Workspace | `$TERMINAL_CWD` when it is a real directory and not `""`, `"."`, `"./"`, `"auto"`, or `"cwd"`. Otherwise the process cwd. | `agent/runtime_cwd.py`, `tools/file_tools_paths.py` |
| Logs | `$HERMES_HOME/logs` | `hermes_logging.setup_logging` |
| Session files | `$HERMES_HOME/sessions` | `hermes_state.divert_session_transcript_jsonl`, `hermes_state_sessions._remove_session_files` |
| Session database | `$HERMES_HOME/state.db` and `state.db-wal` | `hermes_cli/doctor_state.py` |

Log files this install actually created under `$HERMES_HOME/logs`:

- `agent.log`
- `errors.log`
- `gateway.log`
- `gateway-stdio.log`
- `gateway-exit-diag.log`
- `gateway_faulthandler.log`
- `curator/` (package-manager receipts)

`hermes_logging.py` also opens `gui.log` when Hermes is started in gui mode. That file was not created by the CLI session used to check this install.

Session history, logs, and `state.db` are streamed in 64KiB windows. A match is hashed inside the window. The value is not emitted. `$HERMES_HOME/.env`, `$HERMES_HOME/auth.json`, and the plugin data directory are skipped. A project `.env` you explicitly pass with `--path` or `--only-path` is read only to fingerprint a leak.

The list is configurable. An empty configured list does not fall back to the defaults.

```bash
hermes secret-remediation paths
hermes secret-remediation paths set --path ~/src/app
hermes secret-remediation paths reset
hermes secret-remediation scan --path ~/src/app          # extra path
hermes secret-remediation scan --only-path ~/src/app    # this list only
hermes secret-remediation scan --no-logs --no-sessions
hermes secret-remediation scan --diff
hermes secret-remediation scan --show HEAD
```

`plugin.yaml` `config_schema` keys: `scan_paths` (when set, replaces the defaults; empty scans nowhere), `include_logs`, `include_sessions`.

## Schedule

Hermes plugins cannot register a cron job. There is no `ctx.register_cron_job`. `ctx.register_cron_scheduler` replaces the cron backend and is not used.

`hermes secret-remediation schedule` writes `$HERMES_HOME/scripts/secret-remediation-scan.sh` and creates a no-agent job. The script calls `hermes secret-remediation scan --quiet`. That path does not call a model. Empty stdout is a silent tick. The default cadence is daily at 03:00, and you can pass `--every`.

The same job by hand:

```bash
hermes cron create "0 3 * * *" --no-agent --script secret-remediation-scan.sh --deliver local --name secret-remediation-scan
```

The cron job is not created at plugin load. Only `schedule` or that command creates it.

## Install

Hermes 0.22.0 or newer. Restart the CLI, gateway, or desktop backend after enable so the patterns register.

```bash
mkdir -p ~/.hermes/plugins
rm -rf ~/.hermes/plugins/secret-remediation
cp -a . ~/.hermes/plugins/secret-remediation
hermes plugins enable secret-remediation --no-allow-tool-override
```

After the GitHub repo is public:

```bash
hermes plugins install AdrianTanz/hermes-secret-remediation --enable
```

Checked on Hermes v0.23.1:

```bash
hermes plugins validate . --install-deps
hermes plugins doctor . --ci
```

In a session: `/secret-incident`, `/secret-incident scan`, `/secret-incident scan <path>`, `/secret-incident advice`.

## Tests

```bash
python3 -m pytest
```

Fixtures are synthetic (`ghp_FAKESECRET_testonly_aaaabbbbccccdddd`, `sk-test_fake_do_not_use_AAAABBBBCCCCDDDD`, and the same style for the other shapes). The suite fails if a full fixture value appears in captured stdout, stderr, log records, or the incident file. It covers a string, the block hook, a file, a git diff, a fake `agent.log`, and a fake session JSONL record.

## Non-goals

No git history rewrite, no `git filter-repo` or BFG execution, no push, no revoke API, no Discord or Slack deletion, no gitleaks or trufflehog, no binary, no skin of secret-guard or redaction-pack. The local purge is only the three stores in Known limitations.

## Licence

MIT. Copyright (c) 2026 AdrianTanz.

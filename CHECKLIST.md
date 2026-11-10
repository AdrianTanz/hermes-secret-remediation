# Checklist

Checked against the task note `05_Systems/Tasks/2026-11-10-1441-hermes-secret-remediation-plugin.md` (uploaded copy of that note, plus `04_Projects/hermes-hackathon-secret-remediation.md`). Section numbers below are that note's sections.

## Section 1 — Problem

- [x] Written for a Hermes operator whose credential is already in a turn, a tool result, a log, or a commit
- [x] README and the block message say this is not secret-guard or redaction-pack
- [x] README, block text, scan report, and advice lead with: masking does not un-leak; rotate first
- [x] Demo storyboard is detect → contain → guided rotate (`demo/DEMO_SCRIPT.md`)

## Section 2 — Scope

- [x] Native plugin: `plugin.yaml` + `register(ctx)`
- [x] Detect on `pre_llm_call`, `pre_tool_call`, `transform_tool_result`, `transform_terminal_output`, `transform_llm_output`, `scan`, `--diff`, and `--show`
- [x] `ctx.register_redaction_patterns` plus the transform hooks
- [x] Issuer checklists and copy-paste `git filter-repo` / BFG text. Nothing in that text is executed
- [x] Incident log under `plugin_data_dir("secret-remediation")`: type, hash, last 4, location, timestamp
- [x] CLI and `/secret-incident`, including `/secret-incident scan`
- [x] Fake-token tests
- [x] `hermes plugins validate /workspace --install-deps` passed
- [x] `hermes plugins doctor /workspace --ci` passed (5 hooks)
- [x] No history rewrite, no push, no revoke API, no session purge, no gitleaks, no skin of secret-guard
- [x] README non-goals block

## Section 3 — Real Hermes plugin

- [x] Manifest fields, MIT, homepage, `requires_hermes: ">=0.22.0"`
- [x] Hooks, CLI, slash command, redaction patterns registered from `register(ctx)`
- [x] No `ctx.redact_text()`, no core rebind (`no core override` check passed)
- [x] No `tools.override`, no required env
- [x] Drop-in install path documented. Catalogue YAML is a draft. The `sha` is still a placeholder

## Section 4 — Incident flow

- [x] Deterministic patterns, no model call on the scan path
- [x] Defaults: workspace, `$HERMES_HOME/logs`, `$HERMES_HOME/sessions`, `state.db` and `state.db-wal`
- [x] Log filenames taken from a scratch Hermes v0.23.1 install, listed in the README
- [x] `config_schema` plus `--path`, `--only-path`, `--no-logs`, `--no-sessions`
- [x] An empty saved list or an empty `scan_paths` setting does not invent paths
- [x] Skip `$HERMES_HOME/.env`, `auth.json`, and the plugin data dir
- [x] Block text: type, fingerprint, last 4, rotate first, turn not sent
- [x] Hook failures return a fixed message and do not include the value
- [x] Live turn: `hermes -z` with the synthetic GitHub token was blocked. `messages.content` is the Hermes placeholder and does not contain the token. `agent.log` does not contain it
- [ ] Hermes core still stores the original text in `messages.display_metadata.withheld_prompt`, `session_admissions.payload_json`, and `spawn-ledger.json`. Purging session rows is a cut item, so the plugin does not delete them

## Section 5 — Scheduled scan

- [x] No `ctx.register_cron_job`, and `register_cron_scheduler` is not used
- [x] `hermes secret-remediation scan` with no extra path uses the defaults
- [x] `/secret-incident scan`
- [x] `schedule` writes `$HERMES_HOME/scripts/secret-remediation-scan.sh`, which execs `hermes secret-remediation scan --quiet`
- [x] Cron create is `hermes cron create "0 3 * * *" --no-agent --script secret-remediation-scan.sh --deliver local --name secret-remediation-scan`
- [x] README states the plugin cannot register cron itself and includes that one-liner
- [x] Quiet scan prints nothing when there is no new fingerprint
- [x] Not created at `register()` time

## Section 6 — Tests

- [x] Fixtures are the note's `ghp_FAKESECRET_testonly_aaaabbbbccccdddd` and `sk-test_fake_do_not_use_AAAABBBBCCCCDDDD`, plus the same style for the other shapes
- [x] String, redact, `pre_llm_call`, temp file, git diff, fake `agent.log`, fake session JSONL, incident file
- [x] Autouse check fails if the full value is in stdout, stderr, log records, or `incidents.jsonl`
- [x] `validate --install-deps` and `doctor --ci` were run locally against Hermes v0.23.1. They are not wired to a CI workflow in this repo

## Section 7 — Deliverables

- [x] Origin draft on `main`. GitHub mirror is yours
- [x] README and `catalog/PR_DESCRIPTION.md`
- [x] `DEMO_POST.md` tags `@NousResearch` and is not posted
- [ ] Catalogue pull request, X post, and Typeform. Not done. You asked for those to wait

## Section 8 — Hackathon rules that are not UNCLEAR

- [x] Native plugin, public-hook surfaces, SemVer floor, no binary, no telemetry, no credential use, no self-update
- [x] Rule 13 disclosures are in the README and `catalog/PR_DESCRIPTION.md` (file reads, script write, cron create, read-only git)
- [x] UNCLEAR rows (eligibility terms, team size, required licence, prize conditions) were not turned into extra scope. MIT and solo author follow your decisions

## Section 9 — MUST / CUT

- [x] MUST items 1–7 are in the tree and were exercised
- [x] MUST item 8 is split: validate and doctor are green; the public repo, catalogue PR, posted demo, and Typeform are waiting on you
- [x] CUT items are absent: no revoke client, no gitleaks, no session purge, no desktop UI, no cron-backend replacement

## Still unverified

- `messages.display_metadata.withheld_prompt` keeps the typed text. That is Hermes, after a block, and this plugin does not rewrite the database
- `gui.log` was not created, because this check did not start Hermes in gui mode
- Catalogue CI on a public pin. The `sha` in `catalog/secret-remediation.yaml` is still `0000…`

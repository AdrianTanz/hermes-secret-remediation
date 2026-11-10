# Checklist

Operator checks for this plugin. Paths below are Hermes homes, not a build machine.

## Behaviour

- [x] Detects a credential in the user message, tool arguments, tool output, terminal output, and model output
- [x] `pre_llm_call` and `pre_tool_call` block, and a scanner error fails closed
- [x] Incidents store a kind, a fingerprint, and the last 4 characters. The value is not in the incident line
- [x] After a block, a purge tries to replace the value in `state.db` `messages.display_metadata.withheld_prompt`, `state.db` `session_admissions.payload_json`, and `spawn-ledger.json` `argv`
- [x] `hermes secret-remediation purge` and `scan --purge` print counts only. `--apply` rewrites those stores
- [x] The purge does not remove provider logs, backups, shell history, session JSONL, or other database columns

## Tests

- [x] `python3 -m pytest`
- [ ] `hermes plugins validate . --install-deps` and `hermes plugins doctor . --ci` on a local Hermes 0.22 or newer

## Not in this tree

- The catalogue pull request, a public repo, and the demo post stay off until you approve them

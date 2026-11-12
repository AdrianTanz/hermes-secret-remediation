# Checklist

Operator checks for this plugin. Paths below are Hermes homes, not a build machine.

## Behaviour

- [x] Detects a credential in the user message, tool arguments, tool output, terminal output, and model output
- [x] `pre_llm_call` and `pre_tool_call` block, and a scanner error fails closed
- [x] Incidents store a kind, a fingerprint, and the last 4 characters. The value is not in the incident line
- [x] A block does not purge. `state.db`, `spawn-ledger.json`, snapshot databases, and session JSONL are never written
- [x] `hermes secret-remediation purge` reports session ids and `hermes sessions delete`. `--shell-history` is the only write, and it is off unless named
- [x] The purge does not remove provider logs, zip backups, or Hermes-owned stores

## Tests

- [x] `python3 -m pytest`
- [x] `hermes plugins validate . --install-deps` and `hermes plugins doctor . --ci` on Hermes v0.23.1 (`3b421578`)

## Not in this tree

- The catalogue pull request, a public repo, and the demo post stay off until you approve them

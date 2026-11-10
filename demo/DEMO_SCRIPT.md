# Demo storyboard

90 seconds. Detect, then contain, then tell the operator to rotate. Use only the synthetic token from `tests/fakes.py`. Do not let the characters stay readable on screen.

| Time | Picture | Say |
| --- | --- | --- |
| 0–10s | Title: secret-remediation. One line under it: after the leak, not another masker. | secret-guard already stops a key on the way in. This is for the key that is already in the chat or the repo. |
| 10–28s | Paste the fake token into Hermes. The reply is the block: type, fingerprint, last 4, "rotate it first", "I have not sent this turn to the model." | Detect. The turn never reaches the model. Masking this later does not un-leak it. Rotate first. |
| 28–46s | A file read whose output contained the same fake token. The tool result on screen is `[secret:github_pat:…]`. | Contain. Tool output, terminal output, and the reply are rewritten, and the stream is held until that rewrite exists. |
| 46–64s | `/secret-incident`, then `/secret-incident advice github_pat`. The advice is the GitHub checklist and the filter-repo text. | Guide. The checklist is text. The plugin does not call GitHub, does not rewrite history, and does not push. |
| 64–80s | `hermes secret-remediation scan` on a fixture with a fake `agent.log` line and a one-line session JSONL. Output is fingerprints and paths. | The default scan is the workspace, `$HERMES_HOME/logs`, and session history. Those files are streamed. Only the fingerprint comes out. |
| 80–90s | `hermes cron list` showing `secret-remediation-scan`, no-agent, script `secret-remediation-scan.sh`. | The schedule is Hermes cron with no model call. End card: Adrian Tanz. |

Total: 90 seconds.

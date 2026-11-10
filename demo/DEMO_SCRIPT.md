# Demo storyboard

Under 90 seconds. Use a synthetic token, never a live one. The recording must not show the token. Cover the fingerprint on screen if a fixture file is visible.

| Time | Picture | Say |
| --- | --- | --- |
| 0–8s | Title: secret-remediation. Hermes chat, empty. | Hermes will take a pasted credential and send it to the model. This plugin stops that. |
| 8–22s | Paste a fake `ghp_` token into the chat and send. Cut before the characters are readable, or type into a field that is blurred. | The turn never reaches the model. The reply names a fingerprint and the kind. The value is not on screen. |
| 22–36s | Trigger a tool whose output contains the same fake token (a file read). Show the redacted line `[secret:github_pat:…]`. | Tool output and the final reply are rewritten before they are stored. Streaming is held until the rewrite exists. |
| 36–50s | Run `/secret-incident`. The list shows the fingerprint, the kind, and the location. Then `/secret-incident advice`. | Rotation steps and git-history cleanup are text. The plugin does not revoke the token, rewrite history, or push. |
| 50–68s | Terminal: `hermes secret-remediation scan` on a fixture repo. The line is `github_pat fp=… worktree notes.txt:1`. | Default scan is the Hermes workspace, `$HERMES_HOME/logs`, and session history. Session files are streamed. Only the fingerprint comes out. |
| 68–82s | `hermes secret-remediation schedule`, then `hermes cron list`. The job shows `--no-agent` and `secret-remediation-scan.py`. | The schedule writes a script under `$HERMES_HOME/scripts` and creates a no-agent cron job. That job does not call a model. A clean tick stays silent. |
| 82–90s | End card: fingerprint only. No revoke. No history rewrite. | secret-remediation. Adrian Tanz. |

Total: 90 seconds.

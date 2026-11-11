# Demo recording

73.5 seconds. 1080p. The tape is `demo/demo.tape`. `demo/render.sh` builds `demo/secret-remediation-demo.mp4`.

Throwaway home only: `/tmp/sr-demo`. The only credential is `GITHUB` from `tests/fakes.py`. It is never typed and never printed. The screen shows a fingerprint and the last 4 characters.

Recorded against `80d4499`. The opt-out is plain `purge --no-sessions`, not `scan --purge`.

| Time | Picture |
| --- | --- |
| 0:00–0:03 | Title. secret-remediation. after the leak, not another masker. |
| 0:03–0:07 | `HOME=/tmp/sr-demo/home` and `HERMES_HOME` under that same tree. |
| 0:07–0:15 | Detect. `pre_llm_call` blocks. Fingerprint, last 4, rotate first, "I have not sent this turn to the model." Tool result is `[secret:github_pat:…]`. |
| 0:15–0:22 | Scan of the throwaway session and `state.db`. Two findings. Values are not shown. |
| 0:22–0:31 | `purge` with no flags. Report says `applied`, `safety_copies_deleted=4`, and `copies=0`. |
| 0:31–0:40 | Re-seed off screen, then `purge --dry-run`. Hashes match. `unchanged=yes`. |
| 0:40–0:49 | `purge --no-sessions`. Session stays (`jsonl=yes`). `state.db` and shell history are cleared. |
| 0:49–0:55 | Scan still finds the one session line the opt-out left. |
| 0:55–1:01 | `purge` with no flags clears that session. `safety_copies_deleted=2`. |
| 1:01–1:09 | Re-scan. No credential material found. `copies=0`. |
| 1:09–1:13.5 | End card. Rotate first. @NousResearch. AdrianTanz. |

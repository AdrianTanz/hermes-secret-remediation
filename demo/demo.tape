# Reproducible 1080p terminal recording.
# Run from the repo root: demo/render.sh
# Throwaway home only. The fixture value is never typed.

Output demo/terminal.mp4

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 34
Set LineHeight 1.0
Set Width 1920
Set Height 1080
Set Padding 20
Set Framerate 30
Set PlaybackSpeed 1.0
Set TypingSpeed 15ms
Set Theme "Catppuccin Mocha"
Set WindowBar "Colorful"
Set WindowBarSize 20

Hide
Type "unset HISTFILE" Enter
Type "set +o history" Enter
Type "export HISTSIZE=0" Enter
Type "source demo/env.sh" Enter
Type "clear" Enter
Show

Type "echo HOME=$HOME" Enter
Sleep 300ms
Type "echo HERMES_HOME=$HERMES_HOME" Enter
Sleep 2.5s

Ctrl+L
Sleep 200ms
Type "echo 'DETECT  the turn never reaches the model'" Enter
Sleep 300ms
Type "detect" Enter
Sleep 6.5s

Ctrl+L
Sleep 200ms
Type "echo 'SCAN  fingerprints and paths only'" Enter
Sleep 300ms
Type "plant" Enter
Sleep 300ms
Type "hermes secret-remediation scan" Enter
Sleep 5.5s

Ctrl+L
Sleep 200ms
Type "echo 'PURGE  writes by default'" Enter
Sleep 300ms
Type "hermes secret-remediation purge" Enter
Sleep 500ms
Type "status now" Enter
Sleep 6.5s

Hide
Type "plant" Enter
Type "status before" Enter
Type "clear" Enter
Show

Ctrl+L
Sleep 200ms
Type "echo 'DRY-RUN  --dry-run writes nothing'" Enter
Sleep 300ms
Type "hermes secret-remediation purge --dry-run" Enter
Sleep 500ms
Type "status after" Enter
Sleep 6.5s

Ctrl+L
Sleep 200ms
Type "echo 'OPT-OUT  purge --no-sessions'" Enter
Sleep 300ms
Type "hermes secret-remediation purge --no-sessions" Enter
Sleep 500ms
Type "status now" Enter
Sleep 6s

Ctrl+L
Sleep 200ms
Type "echo 'SCAN  the session the opt-out left'" Enter
Sleep 300ms
Type "hermes secret-remediation scan" Enter
Sleep 5s

Ctrl+L
Sleep 200ms
Type "echo 'PURGE  that session'" Enter
Sleep 300ms
Type "hermes secret-remediation purge" Enter
Sleep 4.5s

Ctrl+L
Sleep 200ms
Type "echo 'RE-SCAN'" Enter
Sleep 300ms
Type "hermes secret-remediation scan" Enter
Sleep 500ms
Type "status now" Enter
Sleep 5.5s

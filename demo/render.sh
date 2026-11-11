#!/bin/bash
# Render demo/demo.tape to a 1080p MP4 with title and end cards.
# Never reads a real home. Requires vhs, ttyd, ffmpeg, and ffprobe on PATH.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

if ! command -v vhs >/dev/null || ! command -v ffmpeg >/dev/null || ! command -v ffprobe >/dev/null; then
  echo "render: need vhs, ffmpeg, and ffprobe on PATH" >&2
  exit 1
fi

FONT_BOLD=/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Bold.ttf
FONT=/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

TITLE_SEC=3.4
END_SEC=4.6

vhs demo/demo.tape

ffmpeg -y -f lavfi -i "color=c=0x11111b:s=1920x1080:r=30:d=${TITLE_SEC}" \
  -vf "drawtext=fontfile=${FONT_BOLD}:text='secret-remediation':fontsize=86:fontcolor=0xcdd6f4:x=(w-text_w)/2:y=(h/2)-110,\
drawtext=fontfile=${FONT}:text='after the leak\, not another masker.':fontsize=42:fontcolor=0x89b4fa:x=(w-text_w)/2:y=(h/2)+10" \
  -pix_fmt yuv420p -c:v libx264 -preset medium -crf 18 "$WORK/title.mp4"

ffmpeg -y -f lavfi -i "color=c=0x11111b:s=1920x1080:r=30:d=${END_SEC}" \
  -vf "drawtext=fontfile=${FONT}:text='Rotate first.':fontsize=54:fontcolor=0xcdd6f4:x=(w-text_w)/2:y=(h/2)-150,\
drawtext=fontfile=${FONT_BOLD}:text='@NousResearch':fontsize=78:fontcolor=0x89b4fa:x=(w-text_w)/2:y=(h/2)-30,\
drawtext=fontfile=${FONT}:text='AdrianTanz':fontsize=40:fontcolor=0xa6adc8:x=(w-text_w)/2:y=(h/2)+90" \
  -pix_fmt yuv420p -c:v libx264 -preset medium -crf 18 "$WORK/end.mp4"

ffmpeg -y \
  -i "$WORK/title.mp4" \
  -i demo/terminal.mp4 \
  -i "$WORK/end.mp4" \
  -filter_complex "[0:v]scale=1920:1080,fps=30,format=yuv420p,setsar=1[a];[1:v]scale=1920:1080,fps=30,format=yuv420p,setsar=1[b];[2:v]scale=1920:1080,fps=30,format=yuv420p,setsar=1[c];[a][b][c]concat=n=3:v=1:a=0[v]" \
  -map "[v]" -an -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p -movflags +faststart \
  "$WORK/demo.mp4"

mv "$WORK/demo.mp4" demo/secret-remediation-demo.mp4
rm -f demo/terminal.mp4

duration=$(ffprobe -v error -show_entries format=duration -of default=nw=1:nk=1 demo/secret-remediation-demo.mp4)
bytes=$(wc -c < demo/secret-remediation-demo.mp4)
printf '%s\n%s\n' "$duration" "$bytes"
python3 - "$duration" "$bytes" << 'PY'
import sys
duration = float(sys.argv[1])
size = int(sys.argv[2])
if duration >= 90:
    raise SystemExit(f"render: duration {duration:.2f}s is not under 90")
if size >= 15 * 1024 * 1024:
    raise SystemExit(f"render: {size} bytes is not under 15MB")
PY

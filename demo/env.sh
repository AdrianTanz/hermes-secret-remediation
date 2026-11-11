# Source this from the demo shell. It never prints a credential.
# The only home it will create or destroy is /tmp/sr-demo.
set +o history
unset HISTFILE
HISTSIZE=0
HISTFILESIZE=0
export HOME=/tmp/sr-demo/home
export HERMES_HOME=/tmp/sr-demo/home/.hermes
export TERMINAL_CWD=/tmp/sr-demo/work
DEMO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export PYTHONPATH="${DEMO_ROOT}${PYTHONPATH:+:$PYTHONPATH}"
export PATH="${DEMO_ROOT}/demo/bin:${PATH}"
case "$PWD" in
  /tmp/sr-demo|/tmp/sr-demo/*) cd / ;;
esac
rm -rf /tmp/sr-demo
mkdir -p "$HOME" "$HERMES_HOME" "$TERMINAL_CWD" /tmp/sr-demo
cd "$TERMINAL_CWD"
export PS1='sr-demo \$ '
export PYTHONUNBUFFERED=1
shopt -s checkwinsize

#!/usr/bin/env bash
# Run under Xvfb with a session bus. Only synthetic demo data is captured.
set -euo pipefail
mkdir -p artifacts
export LIBGL_ALWAYS_SOFTWARE=1
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-$(mktemp -d)}"
chmod 700 "$XDG_RUNTIME_DIR"
openbox > artifacts/window-manager.log 2>&1 &
wm=$!
trap 'kill "$wm" 2>/dev/null || true' EXIT
sleep 1
./target/debug/rejection-rejector --demo --screenshot artifacts/native-review.png > artifacts/native-gui.log 2>&1 &
app=$!
for i in $(seq 1 40); do
  if ! kill -0 "$app" 2>/dev/null; then
    wait "$app"
    cat artifacts/native-gui.log
    test -s artifacts/native-review.png
    exit 0
  fi
  if [ "$i" -eq 10 ]; then scrot artifacts/desktop-diagnostic.png || true; fi
  sleep 1
done
cat artifacts/native-gui.log
scrot artifacts/desktop-diagnostic.png || true
kill "$app" 2>/dev/null || true
wait "$app" 2>/dev/null || true
echo 'Native GUI smoke test failed; diagnostic screenshot does not replace native capture.' >&2
exit 1

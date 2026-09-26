#!/usr/bin/env bash
# Captures each actual native screen, using synthetic data only.
set -euo pipefail
mkdir -p artifacts
export LIBGL_ALWAYS_SOFTWARE=1
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-$(mktemp -d)}"
chmod 700 "$XDG_RUNTIME_DIR"
openbox > artifacts/window-manager.log 2>&1 &
wm=$!
app=''
trap 'test -z "$app" || kill "$app" 2>/dev/null || true; kill "$wm" 2>/dev/null || true' EXIT
sleep 1
capture() {
  local view="$1" width="$2" height="$3" name="$4"
  local log="artifacts/$name.log" image="artifacts/$name.png"
  ./target/debug/rejection-rejector --demo --demo-view "$view" --demo-width "$width" --demo-height "$height" --screenshot "$image" > "$log" 2>&1 &
  app=$!
  for i in $(seq 1 40); do
    if ! kill -0 "$app" 2>/dev/null; then
      if ! wait "$app"; then cat "$log"; return 1; fi
      app=''
      cat "$log"
      test -s "$image"
      echo "GUI_QA_OUTPUT $view ${width}x${height} $image"
      return 0
    fi
    if [ "$i" -eq 10 ]; then scrot "artifacts/$name-diagnostic.png" || true; fi
    sleep 1
  done
  cat "$log"
  kill "$app" 2>/dev/null || true
  wait "$app" 2>/dev/null || true
  app=''
  return 1
}
for view in overview review activity local-ai settings; do
  capture "$view" 1440 940 "native-$view"
done
capture review 1180 760 native-review-min

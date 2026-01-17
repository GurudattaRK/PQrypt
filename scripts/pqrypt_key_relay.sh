#!/usr/bin/env zsh
set -euo pipefail

ADB=${ADB:-/Users/gkondampallikar/Library/Android/sdk/platform-tools/adb}
REMOTE_DIR=${REMOTE_DIR:-/sdcard/Documents/PQrypt}
POLL=${POLL:-1}
STABLE=${STABLE:-3}

SCRIPT_DIR="${0:A:h}"

MODE=""
LOCAL_PATH1=""
LOCAL_PATH2=""

raw_mode="${1:-}"
case "$raw_mode" in
  1|"key"|"KEY"|"Key")
    MODE="key"
    LOCAL_PATH1="${2:-}"
    LOCAL_PATH2="${3:-}"
    ;;
  2|"data"|"DATA"|"Data")
    MODE="data"
    LOCAL_PATH1="${2:-}"
    LOCAL_PATH2="${3:-}"
    ;;
  3|"file"|"FILE"|"File")
    MODE="file"
    LOCAL_PATH1="${2:-}"
    LOCAL_PATH2="${3:-}"
    ;;
  *)
    MODE="key"
    LOCAL_PATH1="${1:-}"
    LOCAL_PATH2="${2:-}"
    ;;
esac

if (( $# > 3 )); then
  echo "Usage: ${0:t} [1|2|3|key|data|file] [local_path1] [local_path2]" >&2
  echo "  (default mode is key)" >&2
  exit 1
fi

if [[ "$MODE" != "key" && "$MODE" != "data" && "$MODE" != "file" ]]; then
  echo "Usage: ${0:t} [1|2|3|key|data|file] [local_path1] [local_path2]" >&2
  echo "  1,key : relay PQC key-exchange files (1.key, 2.key, 3.key and final.key if present)" >&2
  echo "  2,data: relay Secure Share files (1.key, 2.key, then combined .pqrypt file; no final.key expected)" >&2
  echo "  3,file: relay any .pqrypt file that appears first on either endpoint (no key steps)" >&2
  echo "  local_path1/local_path2: folder OR executable path (uses its parent folder)" >&2
  echo "  Hint: if multiple Android devices are connected, set ANDROID_SERIAL to pick one." >&2
  exit 1
fi

normalize_local_root() {
  local p="$1"
  [[ -z "$p" ]] && return 0
  p="${~p}"
  p="${p:A}"
  if [[ -f "$p" ]]; then
    echo "${p:h}"
    return 0
  fi
  if [[ -d "$p" ]]; then
    echo "$p"
    return 0
  fi
  echo "$p"
}

LOCAL_PATH1="$(normalize_local_root "$LOCAL_PATH1")"
LOCAL_PATH2="$(normalize_local_root "$LOCAL_PATH2")"

TRANSFERS_DIR="$SCRIPT_DIR/transfers"
mkdir -p "$TRANSFERS_DIR/sender" "$TRANSFERS_DIR/receiver"

# Auto-pick endpoints based on Android devices and optional local paths
# Priority:
# 1. If 2 local paths provided: use them regardless of Android devices
# 2. If 1 local path provided: use first Android device + local path
# 3. If 2+ Android devices: use first 2 Android devices
# 4. If 1 Android device: use Android device + script folder
# 5. If 0 Android devices: use ./A and ./B
devs=($(command "$ADB" devices | /usr/bin/awk 'NR>1 && $2=="device"{print $1}'))

EP1=""
EP2=""
if [[ -n "$LOCAL_PATH1" && -n "$LOCAL_PATH2" ]]; then
  # Two local paths provided - ignore Android devices
  EP1="local:$LOCAL_PATH1"
  EP2="local:$LOCAL_PATH2"
elif [[ -n "$LOCAL_PATH1" ]]; then
  # One local path provided - need exactly 1 Android device
  if (( ${#devs[@]} >= 1 )); then
    local pick="${ANDROID_SERIAL:-}"
    if [[ -n "$pick" ]]; then
      local found=0
      for d in "${devs[@]}"; do
        if [[ "$d" == "$pick" ]]; then found=1; break; fi
      done
      if (( found == 0 )); then
        echo "Warning: ANDROID_SERIAL=$pick not found in connected devices; using ${devs[1]}" >&2
        pick="${devs[1]}"
      fi
    else
      if (( ${#devs[@]} > 1 )); then
        echo "Warning: multiple Android devices found; using ${devs[1]}. Set ANDROID_SERIAL to choose." >&2
      fi
      pick="${devs[1]}"
    fi

    EP1="adb:$pick"
    EP2="local:$LOCAL_PATH1"
  else
    echo "Error: 1 local path provided but no Android devices found. Connect 1 device or provide 2 local paths." >&2
    exit 1
  fi
elif (( ${#devs[@]} >= 2 )); then
  # 2+ Android devices - use first 2
  EP1="adb:${devs[1]}"
  EP2="adb:${devs[2]}"
elif (( ${#devs[@]} == 1 )); then
  # 1 Android device - use script folder as second endpoint
  EP1="adb:${devs[1]}"
  EP2="local:$SCRIPT_DIR"
else
  # 0 Android devices - use local folders
  mkdir -p "$SCRIPT_DIR/A" "$SCRIPT_DIR/B"
  EP1="local:$SCRIPT_DIR/A"
  EP2="local:$SCRIPT_DIR/B"
fi

echo "Endpoints: $EP1 , $EP2"

ep_kind() { echo "${1%%:*}"; }
ep_root() { echo "${1#*:}"; }

ensure_endpoint() {
  local ep="$1"
local kind="$(ep_kind "$ep")"
local root="$(ep_root "$ep")"
  if [[ "$kind" == "adb" ]]; then
    command "$ADB" -s "$root" shell "mkdir -p \"$REMOTE_DIR\"" >/dev/null
  else
    /bin/mkdir -p "$root"
  fi
}

ensure_endpoint "$EP1"
ensure_endpoint "$EP2"

exists() {
  local ep="$1"
local file="$2"
local kind="$(ep_kind "$ep")"
local root="$(ep_root "$ep")"
  if [[ "$kind" == "adb" ]]; then
    command "$ADB" -s "$root" shell "test -f \"$REMOTE_DIR/$file\"" >/dev/null 2>&1
  else
    [[ -f "$root/$file" ]]
  fi
}

local_size_of() {
  local p="$1"
  if command stat -f%z "$p" >/dev/null 2>&1; then
    command stat -f%z "$p"
  else
    command stat -c%s "$p"
  fi
}

size_of() {
  local ep="$1"
local file="$2"
local kind="$(ep_kind "$ep")"
local root="$(ep_root "$ep")"
  if [[ "$kind" == "adb" ]]; then
    command "$ADB" -s "$root" shell "wc -c < \"$REMOTE_DIR/$file\" 2>/dev/null" | /usr/bin/tr -dc '0-9'
  else
    local_size_of "$root/$file" 2>/dev/null | /usr/bin/tr -dc '0-9'
  fi
}

wait_stable() {
  local ep="$1" file="$2" timeout="${3:-300}"
  local last="-1" stable=0
  local end=$(( $(/bin/date +%s) + timeout ))
  while (( $(/bin/date +%s) < end )); do
    if ! exists "$ep" "$file"; then
      stable=0; last="-1"; /bin/sleep "$POLL"; continue
    fi
    local sz="$(size_of "$ep" "$file")"
    if [[ -z "$sz" || "$sz" == "0" ]]; then
      stable=0; last="-1"; /bin/sleep "$POLL"; continue
    fi
    if [[ "$sz" == "$last" ]]; then
      (( stable++ ))
    else
      stable=0
    fi
    last="$sz"
    if (( stable >= STABLE )); then return 0; fi
    /bin/sleep "$POLL"
  done
  return 1
}

pull_to_local() {
  local ep="$1"
local file="$2"
local dest="$3"
local kind="$(ep_kind "$ep")"
local root="$(ep_root "$ep")"
  /bin/mkdir -p "${dest:h}"
  if [[ "$kind" == "adb" ]]; then
    command "$ADB" -s "$root" pull "$REMOTE_DIR/$file" "$dest" >/dev/null
  else
    /bin/cp -f "$root/$file" "$dest"
  fi
}

push_from_local() {
  local src="$1"
local ep="$2"
local file="$3"
local kind="$(ep_kind "$ep")"
local root="$(ep_root "$ep")"
  if [[ "$kind" == "adb" ]]; then
    command "$ADB" -s "$root" push "$src" "$REMOTE_DIR/$file" >/dev/null
  else
    /bin/mkdir -p "$root"
    /bin/cp -f "$src" "$root/$file"
  fi
}

other_ep() {
  local ep="$1"
  if [[ "$ep" == "$EP1" ]]; then echo "$EP2"; else echo "$EP1"; fi
}

relay_file() {
  local file="$1" from_ep="$2" to_ep="$3" from_role="$4"
  local staged="$TRANSFERS_DIR/$from_role/$file"
  if ! wait_stable "$from_ep" "$file"; then
    echo "Timeout waiting for $file on $from_ep" >&2
    exit 10
  fi
  pull_to_local "$from_ep" "$file" "$staged"
  push_from_local "$staged" "$to_ep" "$file"
}

find_pqrypt_name() {
  local ep="$1"
  local kind="$(ep_kind "$ep")"
  local root="$(ep_root "$ep")"

  if [[ "$kind" == "adb" ]]; then
    local out
    # Use ls instead of a for-loop inside the device shell to avoid 'f: parameter not set' issues
    out="$(command "$ADB" -s "$root" shell "ls \"$REMOTE_DIR\"/*.pqrypt 2>/dev/null | head -n 1" 2>/dev/null | /usr/bin/tr -d '\r')" || out=""
    out="${out##*/}"
    if [[ -n "$out" ]]; then
      echo "$out"
    fi
  else
    local files=("$root"/*.pqrypt(N))
    if (( ${#files[@]} > 0 )); then
      echo "${files[1]:t}"
    fi
  fi

  # Always succeed so that polling loops under `set -e` don't abort the script
  return 0
}

if [[ "$MODE" == "file" ]]; then
  echo "File mode: waiting for any .pqrypt on either endpoint..."
  PQ="" SRC_EP="" DST_EP=""
  while [[ -z "$PQ" ]]; do
    for ep in "$EP1" "$EP2"; do
      name="$(find_pqrypt_name "$ep")"
      if [[ -n "$name" ]]; then
        if wait_stable "$ep" "$name"; then
          SRC_EP="$ep"; DST_EP="$(other_ep "$ep")"; PQ="$name"; break
        fi
      fi
    done
    [[ -z "$PQ" ]] && /bin/sleep "$POLL"
  done
  echo "Relaying $PQ from $SRC_EP to $DST_EP"
  role="sender"; [[ "$SRC_EP" == "$EP2" ]] && role="receiver"
  relay_file "$PQ" "$SRC_EP" "$DST_EP" "$role"
  echo "Done (file mode)."
  exit 0
fi

# Determine sender by first 1.key
echo "Waiting for 1.key on either endpoint..."
SENDER_EP="" RECEIVER_EP=""
while [[ -z "$SENDER_EP" ]]; do
  for ep in "$EP1" "$EP2"; do
    if exists "$ep" "1.key"; then
      if wait_stable "$ep" "1.key"; then
        SENDER_EP="$ep"
        RECEIVER_EP="$(other_ep "$ep")"
        break
      fi
    fi
  done
  /bin/sleep "$POLL"
done

echo "Sender: $SENDER_EP | Receiver: $RECEIVER_EP"

echo "Relaying 1.key (sender -> receiver)"
relay_file "1.key" "$SENDER_EP" "$RECEIVER_EP" "sender"

echo "Waiting for 2.key on receiver..."
relay_file "2.key" "$RECEIVER_EP" "$SENDER_EP" "receiver"

if [[ "$MODE" == "key" ]]; then
  echo "Waiting for 3.key on sender..."
  relay_file "3.key" "$SENDER_EP" "$RECEIVER_EP" "sender"
else
  echo "Waiting for .pqrypt file on sender..."
  PQ=""
  while [[ -z "$PQ" ]]; do
    PQ="$(find_pqrypt_name "$SENDER_EP")"
    [[ -z "$PQ" ]] && /bin/sleep "$POLL"
  done
  echo "Relaying $PQ (sender -> receiver)"
  relay_file "$PQ" "$SENDER_EP" "$RECEIVER_EP" "sender"
fi

if [[ "$MODE" == "key" ]]; then
  echo "Waiting for final.key on both endpoints (pull only)..."
  if ! wait_stable "$SENDER_EP" "final.key"; then
    echo "Timeout waiting for final.key on sender" >&2
    exit 4
  fi
  if ! wait_stable "$RECEIVER_EP" "final.key"; then
    echo "Timeout waiting for final.key on receiver" >&2
    exit 5
  fi

  pull_to_local "$SENDER_EP" "final.key" "$TRANSFERS_DIR/sender/final.key"
  pull_to_local "$RECEIVER_EP" "final.key" "$TRANSFERS_DIR/receiver/final.key"

  echo "Done. Saved under: $TRANSFERS_DIR"
else
  echo "Done (data mode). Relayed 1.key, 2.key and the encrypted .pqrypt file; no final.key expected."
fi
#!/usr/bin/env zsh
set -euo pipefail

ADB=${ADB:-/Users/gkondampallikar/Library/Android/sdk/platform-tools/adb}
REMOTE_DIR="/sdcard/Documents/PQrypt"
POLL=1
STABLE=3

cd "${0:A:h}" # run from script folder

# Find two emulator devices
devs=("${(@f)$(command "$ADB" devices | command awk '/^emulator-/{print $1}')}")
if (( ${#devs[@]} < 2 )); then
  echo "Need two running emulators. Found: ${devs[*]:-none}" >&2
  exit 1
fi
A="${devs[1]}"
B="${devs[2]}"

echo "Devices: $A, $B"
command "$ADB" -s "$A" shell "mkdir -p \"$REMOTE_DIR\""
command "$ADB" -s "$B" shell "mkdir -p \"$REMOTE_DIR\""

exists() { command "$ADB" -s "$1" shell "test -f \"$2\"" >/dev/null 2>&1; }
size_of() { command "$ADB" -s "$1" shell "wc -c \"$2\" 2>/dev/null | awk '{print \$1}'" | /usr/bin/tr -d '\r'; }

wait_stable() {
  local dev="$1" path="$2" timeout="${3:-300}"
  local last="-1" stable=0
  local end=$(( $(/bin/date +%s) + timeout ))
  while (( $(/bin/date +%s) < end )); do
    if ! exists "$dev" "$path"; then
      stable=0; last="-1"; /bin/sleep "$POLL"; continue
    fi
    local sz="$(size_of "$dev" "$path")"
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

# Determine sender by first 1.key
echo "Waiting for 1.key on either device..."
sender="" receiver=""
while [[ -z "$sender" ]]; do
  for d in "$A" "$B"; do
    if exists "$d" "$REMOTE_DIR/1.key"; then
      if wait_stable "$d" "$REMOTE_DIR/1.key"; then
        sender="$d"; receiver="$([[ "$d" == "$A" ]] && echo "$B" || echo "$A")"
        break
      fi
    fi
  done
  /bin/sleep "$POLL"
done

echo "Sender: $sender | Receiver: $receiver"

# Relay 1.key sender -> receiver (keep local copy)
command "$ADB" -s "$sender" pull "$REMOTE_DIR/1.key" ./1.key
command "$ADB" -s "$receiver" push ./1.key "$REMOTE_DIR/1.key"
echo "Relayed 1.key"

# Wait and relay 2.key receiver -> sender (keep local copy)
echo "Waiting for 2.key on receiver..."
if ! wait_stable "$receiver" "$REMOTE_DIR/2.key"; then
  echo "Timeout waiting for 2.key on $receiver" >&2
  exit 2
fi
command "$ADB" -s "$receiver" pull "$REMOTE_DIR/2.key" ./2.key
command "$ADB" -s "$sender" push ./2.key "$REMOTE_DIR/2.key"
echo "Relayed 2.key"

# Wait and relay 3.key sender -> receiver (keep local copy)
echo "Waiting for 3.key on sender..."
if ! wait_stable "$sender" "$REMOTE_DIR/3.key"; then
  echo "Timeout waiting for 3.key on $sender" >&2
  exit 3
fi
command "$ADB" -s "$sender" pull "$REMOTE_DIR/3.key" ./3.key
command "$ADB" -s "$receiver" push ./3.key "$REMOTE_DIR/3.key"
echo "Relayed 3.key"

# Pull final.key from both, prefix names by role
echo "Waiting for final.key on both devices..."
if ! wait_stable "$sender" "$REMOTE_DIR/final.key"; then
  echo "Timeout waiting for final.key on sender $sender" >&2
  exit 4
fi
if ! wait_stable "$receiver" "$REMOTE_DIR/final.key"; then
  echo "Timeout waiting for final.key on receiver $receiver" >&2
  exit 5
fi

sender_tag="sender" receiver_tag="receiver"
command "$ADB" -s "$sender" pull "$REMOTE_DIR/final.key" "./${sender_tag}_final.key"
command "$ADB" -s "$receiver" pull "$REMOTE_DIR/final.key" "./${receiver_tag}_final.key"

echo "Done. Saved: 1.key 2.key 3.key ${sender_tag}_final.key ${receiver_tag}_final.key"
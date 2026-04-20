#!/usr/bin/env bash
set -euo pipefail

PI_USER="ezo"
PI_HOST="192.168.1.23"
PI_RUN="/home/$PI_USER/decryptor-run"
BIN_NAME="EloaneDecryptor"

ssh "$PI_USER@$PI_HOST" "
  export QT_QPA_PLATFORM=wayland
  export DISPLAY=:0
  '$PI_RUN/$BIN_NAME'
"

#!/usr/bin/env bash
set -euo pipefail

PI_USER="ezo"
PI_HOST="192.168.1.23"
PI_BUILD="/home/$PI_USER/decryptor-build"
PI_RUN="/home/$PI_USER/decryptor-run"
BIN_NAME="EloaneDecryptor"

ssh "$PI_USER@$PI_HOST" "
  set -e
  mkdir -p '$PI_RUN'
  cp -f '$PI_BUILD/$BIN_NAME' '$PI_RUN/$BIN_NAME'
  chmod +x '$PI_RUN/$BIN_NAME'
  echo 'Deployed to $PI_RUN/$BIN_NAME'
"

#!/usr/bin/env bash
set -euo pipefail

PI_USER="ezo"
PI_HOST="192.168.1.23"

PI_SRC="/home/$PI_USER/decryptor-src"
PI_BUILD="/home/$PI_USER/decryptor-build"

echo "Sync sources..."

rsync -az --delete \
  --exclude "build/" \
  --exclude "build-*" \
  --exclude ".git/" \
  --exclude "*.user" \
  --exclude "*.exe" \
  --exclude "CMakeFiles/" \
  --exclude "CMakeCache.txt" \
  --exclude ".ninja_*" \
  --exclude "*.o" \
  --exclude "*.obj" \
  "$(pwd)/" "$PI_USER@$PI_HOST:$PI_SRC/"

echo "Building on Raspberry..."

ssh "$PI_USER@$PI_HOST" "
set -e

mkdir -p '$PI_BUILD'
cd '$PI_BUILD'

rm -rf CMakeCache.txt CMakeFiles

cmake -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -S '$PI_SRC' \
  -B '$PI_BUILD'

ninja -C '$PI_BUILD'
"

echo "Build OK"

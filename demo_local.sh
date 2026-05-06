#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-6001}"
MESSAGE="${2:-Xin chao FIT4012 - Duy & Hai}"

echo "[*] Bat dau chay demo Lab 3 tai Port: $PORT"

# Đảm bảo khi script thoát thì receiver cũng bị kill
cleanup() {
    if [[ -n "${receiver_pid:-}" ]]; then
        kill "$receiver_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# 1. Chạy Receiver
PYTHONUNBUFFERED=1 \
RECEIVER_HOST=127.0.0.1 \
RECEIVER_PORT="$PORT" \
SOCKET_TIMEOUT=10 \
python receiver.py &

receiver_pid=$!

# Đợi receiver khởi động
sleep 2

# 2. Chạy Sender
echo "[*] Sender dang gui tin nhan..."
SERVER_IP=127.0.0.1 \
SERVER_PORT="$PORT" \
MESSAGE="$MESSAGE" \
python sender.py

# 3. Đợi xử lý xong
sleep 2

echo "[*] Ket thuc demo, dang dong Receiver (PID: $receiver_pid)..."

# Kill an toàn
kill "$receiver_pid" 2>/dev/null || true

echo "[+] Demo hoan tat ruc ro!"

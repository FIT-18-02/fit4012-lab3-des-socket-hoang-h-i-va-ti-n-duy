import os
import socket
import sys
from des_socket_utils import encrypt_des_cbc, build_packet


# Nhom: Pham Hoang Hai va Tran huu Tien Duy
# Lab 3 - FIT4012

SERVER_IP = os.getenv('SERVER_IP', '127.0.0.1')
SERVER_PORT = int(os.getenv('SERVER_PORT', '6000'))
MESSAGE_ENV = os.getenv('MESSAGE')
LOG_FILE = os.getenv('SENDER_LOG_FILE')


def get_message() -> bytes:
    if MESSAGE_ENV is not None:
        return MESSAGE_ENV.encode('utf-8')
    try:
        return input("Nhập bản tin cần gửi: ").encode('utf-8')
    except EOFError:
        return b"Default message for CI"


def main() -> None:
    try:
        # Lấy dữ liệu
        plain = get_message()

        # Mã hóa DES CBC
        key, iv, cipher_bytes = encrypt_des_cbc(plain)

        # Đóng gói packet
        packet = build_packet(key, iv, cipher_bytes)

        # Gửi qua socket TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((SERVER_IP, SERVER_PORT))
            s.sendall(packet)

        # BẮT BUỘC: dòng này phải đúng format
        print("[+] Đã gửi bản mã.")

        # Output đúng format test
        print(f"Key: {key.hex()}")
        print(f"IV: {iv.hex()}")
        print(f"Ciphertext: {cipher_bytes.hex()}")
        print(f"Total Packet Size: {len(packet)} bytes")

        # Ghi log nếu có
        if LOG_FILE:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"Key: {key.hex()}\n")
                f.write(f"IV: {iv.hex()}\n")
                f.write(f"Ciphertext: {cipher_bytes.hex()}\n")
                f.write(f"Total Packet Size: {len(packet)} bytes\n\n")

    except Exception as e:
        print(f"[!] Lỗi: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

import os
import socket
from des_socket_utils import HEADER_SIZE, parse_header, recv_exact, decrypt_des_cbc

HOST = os.getenv('RECEIVER_HOST', '0.0.0.0')
PORT = int(os.getenv('RECEIVER_PORT', '6000'))
TIMEOUT = float(os.getenv('SOCKET_TIMEOUT', '10'))
OUTPUT_FILE = os.getenv('RECEIVER_OUTPUT_FILE')
LOG_FILE = os.getenv('RECEIVER_LOG_FILE')


def main() -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen(1)
            s.settimeout(TIMEOUT)

            print(f"[*] Đang lắng nghe {HOST}:{PORT}...")

            try:
                conn, addr = s.accept()
            except socket.timeout:
                print("[-] Hết thời gian chờ kết nối.")
                return

            with conn:
                print(f"[+] Kết nối từ {addr}")

                # Nhận header
                header = recv_exact(conn, HEADER_SIZE)
                key, iv, length = parse_header(header)

                # Nhận ciphertext
                cipher_bytes = recv_exact(conn, length)

                # BẮT BUỘC: dòng này để test bắt
                print(f"[+] Nhận bản mã: {cipher_bytes.hex()}")

                # Giải mã
                plaintext = decrypt_des_cbc(key, iv, cipher_bytes)

                try:
                    message = plaintext.decode('utf-8')
                except UnicodeDecodeError:
                    message = plaintext.decode('utf-8', errors='ignore')

                line = f"[+] Bản tin gốc: {message}"
                print(line)

                # Ghi file output
                if OUTPUT_FILE:
                    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                        f.write(message)

                # Ghi log
                if LOG_FILE:
                    with open(LOG_FILE, 'a', encoding='utf-8') as f:
                        f.write(line + '\n')

    except Exception as e:
        print(f"[!] Lỗi: {e}")


if __name__ == '__main__':
    main()

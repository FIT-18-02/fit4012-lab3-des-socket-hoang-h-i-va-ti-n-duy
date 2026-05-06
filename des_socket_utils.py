import os
import struct
from typing import Tuple
from Crypto.Cipher import DES

BLOCK_SIZE = 8
HEADER_SIZE = 8 + 8 + 4  # Key (8) + IV (8) + Length (4)


def pad(data: bytes) -> bytes:
    """PKCS#7 padding"""
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    if pad_len == 0:
        pad_len = BLOCK_SIZE  # đảm bảo luôn có padding
    return data + bytes([pad_len]) * pad_len


def unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding (strict check)"""
    if not data:
        raise ValueError("Dữ liệu rỗng.")

    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("Dữ liệu không hợp lệ (không chia hết cho block size).")

    pad_len = data[-1]

    if not (1 <= pad_len <= BLOCK_SIZE):
        raise ValueError("Padding không hợp lệ.")

    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding bị lỗi hoặc dữ liệu bị sửa.")

    return data[:-pad_len]


def encrypt_des_cbc(
    plain: bytes,
    key: bytes | None = None,
    iv: bytes | None = None
) -> Tuple[bytes, bytes, bytes]:
    """Encrypt DES CBC"""

    key = key if key is not None else os.urandom(8)
    iv = iv if iv is not None else os.urandom(8)

    if len(key) != 8 or len(iv) != 8:
        raise ValueError("Key và IV phải đúng 8 byte.")

    cipher = DES.new(key, DES.MODE_CBC, iv)
    cipher_bytes = cipher.encrypt(pad(plain))

    return key, iv, cipher_bytes


def decrypt_des_cbc(key: bytes, iv: bytes, cipher_bytes: bytes) -> bytes:
    """Decrypt DES CBC"""

    if len(key) != 8 or len(iv) != 8:
        raise ValueError("Key và IV phải đúng 8 byte.")

    if len(cipher_bytes) == 0 or len(cipher_bytes) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext không hợp lệ.")

    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted = cipher.decrypt(cipher_bytes)

    return unpad(decrypted)


def build_packet(key: bytes, iv: bytes, cipher_bytes: bytes) -> bytes:
    """Packet = Key + IV + Length + Ciphertext"""

    if len(key) != 8 or len(iv) != 8:
        raise ValueError("Key/IV không hợp lệ.")

    length = len(cipher_bytes)

    return key + iv + struct.pack('!I', length) + cipher_bytes


def parse_header(header: bytes) -> tuple[bytes, bytes, int]:
    """Parse header 20 bytes"""

    if len(header) != HEADER_SIZE:
        raise ValueError(f"Header phải {HEADER_SIZE} byte.")

    key = header[:8]
    iv = header[8:16]
    length = struct.unpack('!I', header[16:20])[0]

    if length < 0:
        raise ValueError("Length không hợp lệ.")

    return key, iv, length


def recv_exact(conn, n: int) -> bytes:
    """Receive exactly n bytes"""

    if n <= 0:
        return b''

    data = b''
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket đóng sớm.")
        data += chunk

    return data

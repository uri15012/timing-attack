#!/usr/bin/env python3
"""
Mock authentication server with an intentional timing side-channel vulnerability.
For educational/portfolio use only — runs on localhost.
"""

import socket
import time
import threading
from datetime import datetime

HOST = "127.0.0.1"
PORT = 9999
TARGET_USER = "admin"
TARGET_PASSWORD = "f3a9k2z1"
CHAR_DELAY = 0.005  # seconds per matching character


def compare_password(candidate: str) -> bool:
    """Compare candidate against TARGET_PASSWORD character-by-character.
    Intentionally leaks timing information: each matching prefix character
    adds CHAR_DELAY seconds to the response time.
    """
    for i, char in enumerate(candidate):
        if i >= len(TARGET_PASSWORD) or char != TARGET_PASSWORD[i]:
            return False
        time.sleep(CHAR_DELAY)
    return len(candidate) == len(TARGET_PASSWORD)


def handle_client(conn: socket.socket, addr: tuple[str, int]) -> None:
    """Read one newline-terminated login attempt, authenticate it, and reply.

    Protocol: client sends ``user:password\n``; server replies ``OK\n`` or
    ``FAIL\n``.  The intentional timing leak lives in ``compare_password``.
    """
    with conn:
        try:
            data = b""
            while b"\n" not in data:
                chunk = conn.recv(256)
                if not chunk:
                    return
                data += chunk

            line = data.split(b"\n")[0].decode(errors="replace").strip()
            if ":" not in line:
                conn.sendall(b"FAIL\n")
                return

            user, _, password = line.partition(":")
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

            success = user == TARGET_USER and compare_password(password)
            result = "OK" if success else "FAIL"

            print(f"[{ts}] {addr[0]}:{addr[1]}  user={user!r}  pass={password!r}  -> {result}")
            conn.sendall(f"{result}\n".encode())
        except (ConnectionResetError, BrokenPipeError):
            pass


def main() -> None:
    """Bind to HOST:PORT and serve login attempts forever, one thread each."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(32)
        print(f"Auth server listening on {HOST}:{PORT}")
        print(f"Target: user={TARGET_USER!r}  password={'*' * len(TARGET_PASSWORD)} ({len(TARGET_PASSWORD)} chars)")
        print(f"Timing leak: {CHAR_DELAY*1000:.1f} ms per matching prefix character\n")

        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()

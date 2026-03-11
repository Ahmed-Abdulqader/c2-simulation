# C2 Framework Simulation — Educational Portfolio Project

> **Disclaimer:** This project is an educational simulation built as a final project for an Object-Oriented Programming course. All capabilities are restricted to a controlled local environment. No real-world attack infrastructure is included.

---

## Overview

This project simulates the architecture of a **Command and Control (C2) framework** — the network component that gives an attacker remote control over a compromised machine.

It was built to demonstrate practical understanding of:

- TCP socket programming in Python
- Object-Oriented design principles (encapsulation, single responsibility)
- Symmetric file encryption (Fernet / AES-128-CBC)
- Multi-threaded server architecture
- Cross-platform shell command execution
- File transfer with integrity verification (SHA-256)

---

## Architecture

```
┌────────────────────┐        TCP Socket        ┌────────────────────┐
│   server.py        │ ◄──────────────────────► │   client.py        │
│   (Operator side)  │                          │   (Implant side)   │
│                    │                          │                    │
│  - Accepts conns   │                          │  - Beacons to C2   │
│  - Runs commands   │                          │  - Executes modes  │
│  - Sends files     │                          │  - Rich CLI menu   │
│  - Encrypts files  │                          │                    │
└────────────────────┘                          └────────────────────┘
         │
         ├── tools.py          (Files, CommandRunner utilities)
         └── crypto_manager.py (Fernet encryption, safety guards)
```

### Module Breakdown

| File | Responsibility |
|------|---------------|
| `server.py` | Multi-threaded C2 server. Accepts connections and dispatches sessions to handler methods. |
| `client.py` | Implant simulation. Connects to the server and exposes three operation modes via a Rich TUI menu. |
| `tools.py` | Stateless utility classes: `Files` for filesystem search, `CommandRunner` for cross-platform shell execution. |
| `crypto_manager.py` | Fernet-based symmetric encryption. Includes path validation to restrict all operations to `dummy_targets/`. |

---

## Operation Modes

### Mode 0 — Remote Shell

Demonstrates the core capability of any C2 implant: remote command execution.

The server receives a shell command string from the operator, executes it via `subprocess.run()` on the OS (bash on Linux/macOS, PowerShell on Windows), and streams stdout + stderr back over the socket.

A configurable timeout prevents the server from hanging on interactive commands (e.g., `sudo -l` waiting for a password).

### Mode 1 — File Exfiltration

Simulates the data theft phase of an attack. The operator requests a file by name. The server:
1. Recursively searches a configured root directory for the file.
2. Computes its SHA-256 hash.
3. Sends a JSON metadata packet (name, size, hash).
4. Waits for client `"OK"` acknowledgement.
5. Streams the file in 4KB chunks.

The client verifies the received data against the hash to confirm integrity.

### Mode 2 — Ransomware Simulation (Safety-Restricted)

Demonstrates how ransomware uses symmetric encryption to lock victim files.

**How it works:**
- Uses **Fernet** (AES-128-CBC + HMAC-SHA256) from the `cryptography` library.
- Encrypts every file in `dummy_targets/` in-place.
- In a real attack, the key would be generated randomly and sent to the attacker's server — the victim never sees it. Here a static demo key is used.
- A second run with `decrypt` restores the files, simulating key delivery after ransom payment.

**Safety guard:** `CryptoManager._is_safe_path()` resolves symlinks with `os.path.realpath()` and rejects any path outside `dummy_targets/`. This prevents path traversal and accidental damage to real files.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/Ahmed-Abdulqader/c2-simulation
cd c2-simulation

# Install dependencies
pip install -r requirements.txt

# Create demo files for the ransomware simulation
mkdir dummy_targets
echo "Sensitive document content" > dummy_targets/document.txt
echo "Config data: password=hunter2" > dummy_targets/config.cfg
```

---

## Usage

```bash
# Terminal 1 — Start the server (operator side)
python server.py

# Terminal 2 — Start the client (implant side)
python client.py
```

Both default to `localhost:8080`. Custom host/port:

```bash
python server.py 0.0.0.0 9090
python client.py 127.0.0.1 9090
```

---

## Key Design Decisions

**Why threading instead of asyncio?**  
The `threading` module maps closely to real OS threads, making the multi-client behaviour concrete and debuggable (thread names appear in log output). For this scale, the GIL is not a bottleneck since sessions are I/O-bound, not CPU-bound.

**Why Fernet instead of raw AES?**  
Fernet provides authenticated encryption out of the box — it uses HMAC-SHA256 to detect tampering. Raw AES-CBC without authentication is vulnerable to padding oracle attacks. Using a high-level primitive demonstrates awareness of cryptographic best practices.

**Why `@staticmethod` on utility methods?**  
`Files` and `CommandRunner` hold no instance state. Making their methods static documents this fact explicitly and avoids forcing callers to instantiate objects just to call a function — a clean application of the Single Responsibility Principle.

---

## Dependencies

```
cryptography>=41.0
rich>=13.0
questionary>=2.0.1
```

---

## Security Notes

This project is for **educational and portfolio purposes only**:
- File operations are restricted to the project directory.
- Encryption only operates on `dummy_targets/`.
- No persistence, privilege escalation, or defense evasion is implemented.
- All socket communication is plaintext (no TLS) — a real implant would use encrypted channels.

---

*Built as a final project for the Object-Oriented Programming course, Sana'a University Department of Cybersecurity.*

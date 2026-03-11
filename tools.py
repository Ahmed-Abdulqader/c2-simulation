"""
tools.py — Utility classes for the C2 simulation framework.

Provides two core helpers used by both server and client:
  - Files: filesystem search and reading utilities
  - CommandRunner: cross-platform shell command execution

These classes are intentionally stateless (all @staticmethod) because they
represent pure functions with no shared state between calls — a clean example
of using classes purely for namespace grouping in Python.
"""

import os
import subprocess
import platform


class Files:
    """
    Filesystem utility class for locating and reading files.

    In a real C2 implant, the 'find_file' capability is used during the
    reconnaissance phase to locate sensitive files (configs, keys, documents)
    before exfiltration. Here we restrict the search root to safe directories.
    """

    @staticmethod
    def find_file(filename: str, starting_directory: str) -> tuple[str, int] | tuple[None, None]:
        """
        Recursively search for a file by name starting from a given directory.

        Args:
            filename:            The name of the file to locate (e.g. 'report.pdf').
            starting_directory:  Root path to begin the recursive walk.

        Returns:
            A tuple (full_path, file_size_in_bytes) if found, or (None, None).
        """
        try:
            for root, _dirs, files in os.walk(starting_directory):
                if filename in files:
                    full_path = os.path.join(root, filename)
                    return full_path, os.path.getsize(full_path)
        except PermissionError:
            pass  # Skip directories we cannot read
        except Exception:
            pass
        return None, None

    @staticmethod
    def read_bytes(path: str) -> bytes | None:
        """
        Read a file as raw bytes. Used before hashing or encrypting.

        Returns None if the file cannot be read.
        """
        try:
            with open(path, "rb") as f:
                return f.read()
        except (OSError, IOError):
            return None


class CommandRunner:
    """
    Cross-platform shell command executor.

    This is the core of the 'remote shell' feature in a C2 framework.
    On Linux/macOS it runs commands through bash; on Windows it delegates
    to PowerShell. The timeout prevents the server from hanging on
    interactive commands (e.g., 'sudo -l' waiting for a password).

    stderr is captured alongside stdout so the operator sees the full
    output — including error messages from failed commands.
    """

    DEFAULT_TIMEOUT = 10  # seconds

    @staticmethod
    def run(command: str, timeout: int = DEFAULT_TIMEOUT) -> str:
        """
        Execute a shell command and return its combined output.

        Args:
            command: The shell command string to run.
            timeout: Maximum seconds to wait before giving up.

        Returns:
            A string containing stdout + stderr, or an error message.
        """
        os_platform = platform.system()

        try:
            if os_platform == "Windows":
                result = subprocess.run(
                    ["powershell", "-Command", command],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
            else:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )

            # Combine stdout and stderr so errors are visible to the operator
            output = result.stdout
            if result.stderr:
                output += f"\n[stderr]: {result.stderr}"
            return output or "[No output]"

        except subprocess.TimeoutExpired:
            return f"[!] Command timed out after {timeout}s. The process was killed."
        except FileNotFoundError:
            return "[!] Shell not found. Cannot execute command."
        except Exception as e:
            return f"[!] Unexpected error: {e}"

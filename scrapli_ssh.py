"""
Collection of shared Cisco SSH utility functions for network automation.

Uses Scrapli to manage SSH connections, forced to run on Paramiko to support
Windows environments.
"""

from dotenv import load_dotenv

# Scrapli imports
from scrapli import Scrapli
from scrapli.exceptions import (
    ScrapliTimeout,
    ScrapliAuthenticationFailed,
    ScrapliConnectionError
    )

load_dotenv()

class CiscoSSH:
    """
    A wrapper class designed to simplify SSH interactions with Cisco devices.

    This class abstracts Scrapli operations to provide a clean, high-speed
    interface for connecting to Cisco switches. It supports Python's context manager
    ('with' blocks) for automatic connection handling and session cleanup, and enforces
    strict encryption algorithms to comply with enterprise security requirements.

    Attributes:
        instances (list): A registry of active CiscoSSH instances used for bulk teardowns.
    """
    instances = []

    def __init__(self, ip, username: str, password: str, end_with_write: bool = False):
        """Initializes the connection parameters and establishes the SSH session.
            Args:
            ip (str): The IP address or FQDN of the target network device.
            username (str): The SSH/NETCONF login username.
            password (str): The SSH/NETCONF login password.
            end_with_write (bool, optional): If True, automatically saves the running
            configuration to startup memory before disconnecting. Defaults to False.
            """

        self.device_params = {
            "platform": "cisco_iosxe",
            "host": ip,
            "auth_username": username,
            "auth_password": password,
            "auth_strict_key": False,   # Prevents stopping on unknown SSH host keys
            "transport": "paramiko",
            "transport_options": {
                "ciphers": ["aes256-ctr"],
                "macs": ["hmac-sha2-512"]
                }
            }

        self.ssh = Scrapli(**self.device_params)
        self.ssh.open()
        self.hostname = self.ssh.get_prompt().strip("#> \n")
        self.end_with_write = end_with_write

        # Append instance to class registry for global connection tracking
        CiscoSSH.instances.append(self)

    def __enter__(self):
        """
        Context manager entry point.

        Returns:
            CiscoSSH: The active and verified connection instance.
        """
        self._ensure_connection()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit point to gracefully terminate the SSH session.

        Saves configuration if 'end_with_write' is active and closes
        the underlying socket connection.
        """
        if self.end_with_write:
            self.ssh_write()

        if self.ssh:
            try:
                self.ssh.close()
                print(f"{self.hostname} Disconnected cleanly.")
            except Exception: # pylint: disable=broad-exception-caught
                pass

    def _ensure_connection(self):
        """
        Internal helper to verify, validate, or restore the SSH session.

        Raises:
            ConnectionError: If the remote device cannot be contacted, times out,
            or rejects credentials.
        """
        if not self.ssh or not self.ssh.isalive():
            try:
                if not self.ssh:
                    self.ssh = Scrapli(**self.device_params)
                self.ssh.open()
            except (ScrapliTimeout, ScrapliAuthenticationFailed, ScrapliConnectionError) as e:
                raise ConnectionError(
                    f"Could not connect to {self.device_params['host']}: {e}"
                    ) from e

    def ssh_write(self) -> str:
        """
        Executes a 'write memory' command to save the running configuration.

        Returns:
            str: A human-readable status message confirming save status or detailing
            connectivity failures.
        """
        try:
            self._ensure_connection()
            # timeout_ops replaces read_timeout
            response = self.ssh.send_command("write memory", timeout_ops=90)

            # Scrapli returns a Response object, .result holds the raw string output
            if "[OK]" in response.result:
                return f"SUCCESS: Configuration saved on {self.hostname}"
            return (
                f"FAILED: Save command rejected on {self.hostname}.\n"
                f"Output: {response.result.strip()}"
            )

        except (ScrapliTimeout, ScrapliAuthenticationFailed) as e:
            # These are expected network/credential issues
            return f"CONNECTIVITY ERROR: {self.hostname} could not be reached or timed out: {e}"
        except (EOFError, ConnectionResetError):
            # The switch might have dropped the connection during the write
            return f"CONNECTION LOST: {self.hostname} closed the session during the save."
        except Exception as e: # pylint: disable=broad-exception-caught
            # This handles truly unexpected logic bugs
            return f"UNEXPECTED ERROR on {self.hostname}: {type(e).__name__} - {e}"

    def get_version(self) -> list:
        """
        Retrieves system software information.

        Returns:
            list: A list of dictionaries containing parsed 'show version' details.
        """
        self._ensure_connection()
        response = self.ssh.send_command("show version")
        return response.textfsm_parse_output()

    def get_int_status(self) -> list:
        """
        Retrieves physical interface hardware status.

        Returns:
            list: A list of dictionaries containing parsed 'show interface status' details.
        """
        self._ensure_connection()
        response = self.ssh.send_command("show interface status")
        return response.textfsm_parse_output()

    def check_half_duplex(self) -> str:
        """
        Inspects all physical ports for duplex configuration mismatches.

        Returns:
            str: A summary string declaring if duplex issues were detected.
        """
        try:
            interface_data = self.get_int_status()
            found_half = False

            for entry in interface_data:
                if entry.get("duplex") in ("half", "a-half"):
                    print(f"{entry['port']} is HALF DUPLEX on {self.hostname}")
                    found_half = True

            status = "Issues found" if found_half else "Clean"
            return f"Completed check on {self.hostname}. Result: {status}."

        except (ConnectionError, TimeoutError, ScrapliConnectionError) as e:
            # Handle known network/connectivity issues gracefully
            return f"Network failure during duplex check on {self.hostname}: {e}"
        except KeyError as e:
            # Handle cases where TextFSM/parsing doesn't return the expected keys
            return f"Data parsing error on {self.hostname}: Missing field {e}"

    def manual_disconnect(self):
        """Disconnects from SSH session, if it exists"""
        if self.ssh:
            try:
                self.ssh.close()
                self.ssh = None
            except Exception: # pylint: disable=broad-exception-caught
                pass

    @classmethod
    def close_all_sessions(cls):
        """Global classmethod to loop through the active registry and close connections."""
        print(f"\n--- Closing {len(cls.instances)} active sessions ---")
        for instance in cls.instances:
            if instance.ssh:
                print(f"Disconnecting from {instance.hostname}...")
                instance.manual_disconnect()
        print("All sessions closed.")

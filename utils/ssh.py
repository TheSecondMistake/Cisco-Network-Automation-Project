"""Collection of shared Cisco SSH utility functions for network automation.
Uses Netmiko for all SSH connections

HOST KEY SECURITY:
- Host key verification is enforced via ConnectHandler's ssh_strict parameter
- Alternate known_hosts file configured via alt_host_keys / alt_key_file
- See ssh_config.txt header for architecture documentation
"""

import os
import logging
from pathlib import Path
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

import config as _

logger: logging.Logger = logging.getLogger(__name__)


def _get_known_hosts_path() -> str:
    """Return the path to the alternate known_hosts file.

    Reads from environment variable if set, otherwise defaults to project-local file.
    """
    env_known_hosts = os.getenv("ssh_known_hosts_path")
    if env_known_hosts:
        return env_known_hosts

    base_dir = Path(os.path.dirname(os.path.abspath(__file__)))
    default_path = base_dir / "known_hosts"
    return str(default_path)


class CiscoSSH:
    """
    Secure SSH wrapper class for Cisco network devices.

    Enforces:
    - Strict host key verification (rejects unknown/untrusted hosts)
    - FIPS-approved cryptography via ssh_config_file
    - Connection timeouts and keepalive
    - Automatic session cleanup via context manager
    """

    def __init__(
            self,
            ip: str,
            username: str,
            password: str,
            allow_new_host: bool = False
            ) -> None:
        """Initialize SSH connection parameters. The connection itself is
        established when entering a 'with' block.

        Args:
            ip: Device IP address or hostname
            username: SSH username
            password: SSH password
            allow_new_host: If True, accept unknown host keys (dangerous, use sparingly)
        """
        base_dir = os.path.dirname(os.path.abspath(__file__))
        ssh_config_file = os.path.join(base_dir, "ssh_config.txt")
        known_hosts_path = _get_known_hosts_path()

        self.device_params = {
            "device_type": "cisco_ios",
            "host": ip,
            "username": username,
            "password": password,

            "conn_timeout": 15,
            "session_timeout": 15,
            "timeout": 90,
            "read_timeout_override": 90,
            "keepalive": 30,

            "allow_agent": False,
            "ssh_strict": not allow_new_host,
            "alt_host_keys": True,
            "alt_key_file": known_hosts_path,

            "ssh_config_file": ssh_config_file,
        }
        self.ip = ip
        self.ssh = None
        self.hostname = None

    def __enter__(self) -> "CiscoSSH":
        """Establishes the SSH session and verifies it before returning."""
        self.ssh = ConnectHandler(**self.device_params)
        self.hostname = self.ssh.find_prompt()[:-1]
        logger.info("Connected to %s (%s)", self.hostname, self.ip)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Closes SSH session cleanly."""
        if self.ssh:
            try:
                self.ssh.disconnect()
                logger.info("%s Disconnected cleanly.", self.hostname)
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.warning("Error disconnecting %s: %s", self.hostname, e)

    def _ensure_connection(self) -> None:
        """Check for active SSH session and reconnect if needed."""
        if not self.ssh or not self.ssh.is_alive():
            try:
                logger.info("Reconnecting to %s...", self.ip)
                self.ssh = ConnectHandler(**self.device_params)
                self.hostname = self.ssh.find_prompt()[:-1]
            except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
                logger.error("Could not connect to %s: %s", self.ip, e)
                raise ConnectionError(
                    f"Could not connect to {self.ip}: {e}"
                ) from e

    def ssh_write(self) -> None:
        """Saves the running configuration to startup."""
        self._ensure_connection()

        output = self.ssh.send_command(
            "write memory",
            read_timeout=90
        )

        if "[OK]" not in output:
            raise RuntimeError(
                f"Configuration save failed on {self.hostname}: {output.strip()}"
            )

        logger.info("Configuration saved on %s", self.hostname)

    def get_version(self) -> list[dict]:
        """Returns 'show version' output in an iteratable format."""
        self._ensure_connection()
        return self.ssh.send_command("show version", use_textfsm=True)

    def get_int_status(self) -> list[dict]:
        """Returns 'show interface status' output in an iteratable format."""
        self._ensure_connection()
        return self.ssh.send_command("show interface status", use_textfsm=True)

    def check_half_duplex(self) -> list[dict]:
        """Returns a list of interfaces operating in half-duplex."""
        interface_data = self.get_int_status()
        return [
            entry
            for entry in interface_data
            if entry.get("duplex") in ("half", "a-half")
        ]

    def manual_disconnect(self) -> None:
        """Manually disconnect from SSH session before context manager exits."""
        if self.ssh:
            try:
                self.ssh.disconnect()
                logger.info("Manual disconnect from %s", self.hostname)
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.warning("Error during manual disconnect %s: %s", self.hostname, e)
            finally:
                self.ssh = None

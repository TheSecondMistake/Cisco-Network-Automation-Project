"""
Collection of shared Cisco SSH utility functions for network automation.
Uses Netmiko for all SSH connections
"""

import os
from dotenv import load_dotenv
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

load_dotenv()

class CiscoSSH:
    """
    Class meant to simply SSH actions ('with' blocks supported)
    """
    instances = []

    def __init__(self, ip, username: str, password: str, end_with_write:bool = False) -> None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        ssh_config_file = os.path.join(base_dir, "ssh_config.txt")
        self.device_params = {
            "device_type": "cisco_ios",
            "host": ip,
            "username": username,
            "password": password,
            "ssh_config_file": ssh_config_file
        }
        self.ip = ip
        self.ssh = ConnectHandler(**self.device_params)
        self.hostname = self.ssh.find_prompt()[:-1]
        self.end_with_write = end_with_write
        CiscoSSH.instances.append(self)

    def __enter__(self) -> "CiscoSSH":
        """
        Runs automatically when you open a 'with' block.
        
        SSH session should be established in __init__, but will be verified again here
        """
        self._ensure_connection()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Runs automatically when the 'with' block ends (even on errors).
        
        Closes SSH session
        Does not save switch config before exit unless 'end_with_write' set to True.
        """
        if self.end_with_write:
            self.ssh_write()
        if self.ssh:
            try:
                self.ssh.disconnect()
                print(f"{self.hostname} Disconnected cleanly.")
            except Exception: # pylint: disable=broad-exception-caught
                pass

    def _ensure_connection(self) -> None:
        """Internal helper to check for an active SSH session."""
        if not self.ssh or not self.ssh.is_alive():
            try:
                self.ssh = ConnectHandler(**self.device_params)
            except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
                raise ConnectionError(f"Could not connect to {self.ip}: {e}") from e

    def ssh_write(self) -> str:
        """Writes a device configuration and returns a status message."""
        try:
            self._ensure_connection()
            output = self.ssh.send_command("write memory", read_timeout=90)
            if "[OK]" in output:
                return f"SUCCESS: Configuration saved on {self.hostname}"
            return f"FAILED: Save command rejected on {self.hostname}. Output: {output.strip()}"

        except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
            # These are expected network/credential issues
            return f"CONNECTIVITY ERROR: {self.hostname} could not be reached or timed out: {e}"

        except (EOFError, ConnectionResetError):
            # The switch might have dropped the connection during the write
            return f"CONNECTION LOST: {self.hostname} closed the session during the save."

        except Exception as e: # pylint: disable=broad-exception-caught
            # This handles truly unexpected logic bugs
            return f"UNEXPECTED ERROR on {self.hostname}: {type(e).__name__} - {e}"

    def get_version(self) -> dict:
        """Returns 'show version' output in an iteratable format"""
        self._ensure_connection()
        return self.ssh.send_command("show version", use_textfsm=True)

    def get_int_status(self) -> dict:
        """Returns 'show interface status' output in an iteratable format"""
        self._ensure_connection()
        return self.ssh.send_command("show interface status", use_textfsm=True)

    def check_half_duplex(self) -> str:
        """Checks for half-duplex ports and returns a status summary."""
        try:
            interface_data = self.get_int_status()

            found_half = False
            for entry in interface_data:
                if entry.get("duplex") in ("half", "a-half"):
                    print(f"{entry['port']} is HALF DUPLEX on {self.hostname}")
                    found_half = True

            status = "Issues found" if found_half else "Clean"
            return f"Completed check on {self.hostname}. Result: {status}."

        except (ConnectionError, TimeoutError) as e:
            # Handle known network/connectivity issues gracefully
            return f"Network failure during duplex check on {self.hostname}: {e}"

        except KeyError as e:
            # Handle cases where TextFSM/parsing doesn't return the expected keys
            return f"Data parsing error on {self.hostname}: Missing field {e}"

    def manual_disconnect(self) -> None:
        """
        This class should acutomatiically close ssh sessions but this 
        function to allow a more granular disconnect option if needed.
        """
        if self.ssh:
            try:
                self.ssh.disconnect()
                self.ssh = None
            except Exception: # pylint: disable=broad-exception-caught
                pass

    @classmethod
    def close_all_sessions(cls) -> None:
        """
        Loops through the registry and closes all connections.
        Can be run at the end of a script to make sure all SSH sessions are closed
        """
        print(f"\n--- Closing {len(cls.instances)} active sessions ---")
        for instance in cls.instances:
            if instance.ssh:
                print(f"Disconnecting from {instance.hostname}...")
                instance.manual_disconnect()
        print("All sessions closed.")

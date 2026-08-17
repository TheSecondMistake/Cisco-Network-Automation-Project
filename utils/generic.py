"""
Collection of shared utility functions for network automation.
"""

from typing import Literal
import getpass
import ipaddress
import re

import config


def get_login() -> tuple[str, str]:
    """
    Gets user input for a username and password
    Used for TACACS authentication
    
    Returns:
        tuple: (username, password)
    """
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    return username, password


def create_filtered_device_dict(raw_network_devices: dict) -> dict[str, dict]:
    """Takes raw JSON from the DNAC network devices API and returns a custom dict.
    
    Args:
        raw_network_devices: List of device dictionaries from Catalyst Center API
        
    Returns:
        dict[str, dict]: Cleaned device dictionary keyed by hostname"""
    network_devices: dict[str, dict] = {}

    for device in raw_network_devices:
        try:
            hostname = device.get("hostname", "Unknown")
            clean_name = (
                hostname.removesuffix(config.DOMAIN_SUFFIX)
                if config.DOMAIN_SUFFIX
                else hostname
            )
            network_devices[clean_name] = {
                "dnac_id": device.get("id"),
                "ip": device.get("managementIpAddress"),
                "role": device.get("role")
            }
        except (KeyError, TypeError) as e:
            print(f"Warning: Skipping a device due to missing field: {e}")
            continue

    return network_devices


def create_distrolist(network_devices: dict[str, dict]) -> dict[str, dict]:
    """
    Return a dictionary of distribution switches based on 'network devices'.
    Site specific distribution switches are identified by having a role of 
    'DISTRIBUTION' in Catalyst Center and containing 'DN' in their hostname.
    
    Args:
        network_devices: Dict of devices keyed by hostname
        
    Returns:
        dict: Filtered dictionary containing only distribution switches
    """
    distro_devices: dict[str, dict] = {}
    for device in network_devices:
        if network_devices[device]["role"] == "DISTRIBUTION" and "DN" in device:
            distro_devices[device] = network_devices[device]
    return distro_devices


def is_ip(ip: str) -> bool:
    """Checks if an IP is valid IPv4 or IPv6.
    
    Args:
        ip: String representation of IP address
        
    Returns:
        bool: True if valid IP, False otherwise"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def normalize_mac(raw_mac: str) -> str:
    """
    Standardizes a MAC address string to the xx:xx:xx:xx:xx:xx format.
    Raises ValueError if the input is not a valid 12-digit MAC address.
    
    Args:
        raw_mac: Raw MAC address string (any format)
        
    Returns:
        str: Normalized MAC address in aa:bb:cc:dd:ee:ff format
        
    Raises:
        ValueError: If MAC address is invalid length
    """
    # 1. Remove all non-hexadecimal characters (0-9, a-f, A-F)
    # This strips colons, dots, hyphens, and spaces.
    clean_mac = re.sub(r'[^0-9a-fA-F]', '', str(raw_mac))

    # 2. Validate that we have exactly 12 hex characters
    if len(clean_mac) != 12:
        raise ValueError(
            f"Invalid MAC length: expected 12 hex digits, got {len(clean_mac)} for input: {raw_mac}"
            )

    # 3. Insert colons every two characters and convert to lowercase
    # This transforms 'aabbccddeeff' into 'aa:bb:cc:dd:ee:ff'
    formatted_mac = ":".join(
        clean_mac[i:i+2] for i in range(0, 12, 2)
    ).lower()

    return formatted_mac

def parse_authentication_servers(
        config_str: str,
        auth_type: Literal["radius", "tacacs"]
        ) -> dict[str, dict]:
    """Parses a Radius or TACACS+ server configuration string into a structured dictionary.

    Args:
        config_str: A multi-line string containing the Cisco {auth_type} configuration.
        auth_type: The type of authentication server to parse ("radius" or "tacacs").

    Returns:
        A dictionary where the keys are the {auth_type} server names (str) and values
        are dictionaries containing 'address' and/or 'key' configuration strings.
    """
    if auth_type not in ("radius", "tacacs"):
        raise ValueError(
            f"Invalid authentication server type: {auth_type}. Must be 'radius' or 'tacacs'"
            )
    result: dict[str, dict] = {}
    current_server: str | None = None
    prefix = f"{auth_type} server "

    for line in config_str.splitlines():
        clean_line = line.strip()

        if clean_line.startswith(prefix):
            current_server = clean_line[len(prefix):]
            result[current_server] = {}

        elif current_server is not None:
            if clean_line.startswith("address "):
                result[current_server]["address"] = clean_line
            elif clean_line.startswith("key "):
                result[current_server]["key"] = clean_line

    return result

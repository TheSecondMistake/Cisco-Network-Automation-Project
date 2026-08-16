"""
Collection of shared utility functions for network automation.
"""

import getpass
import os
import ipaddress
import re

from dotenv import load_dotenv

load_dotenv()


def get_login():
    """
    Gets user input for a username and password
    Used for TACACS authentication
    """
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    return username, password


def create_filtered_device_dict(raw_network_devices: dict) -> dict:
    """Takes raw JSON from the DNAC network devices API and returns a custom dict"""
    env_domain_suffix = os.getenv("domain_suffix", "") # Default to empty string if missing
    network_devices = {}

    for device in raw_network_devices:
        try:
            hostname = device.get("hostname", "Unknown")
            clean_name = hostname.removesuffix(env_domain_suffix)
            network_devices[clean_name] = {
                "dnac_id": device.get("id"),
                "ip": device.get("managementIpAddress"),
                "role": device.get("role")
            }
        except KeyError as e:
            print(f"Warning: Skipping a device due to missing field: {e}")
            continue

    return network_devices


def create_distrolist(network_devices: dict) -> dict:
    """
    Return a dictionary of distribution switches based on 'network devices' from module get_devices
    """
    distro_devices = {}
    for device in network_devices:
        if network_devices[device]["role"] == "DISTRIBUTION" and "DN" in device:
            distro_devices[device] = network_devices[device]
    return distro_devices


def is_ip(ip: str) -> bool:
    """Checks if an IP is an IP."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def normalize_mac(raw_mac):
    """
    Standardizes a MAC address string to the xx:xx:xx:xx:xx:xx format.
    Returns None if the input is not a valid 12-digit MAC address.
    """
    # 1. Remove all non-hexadecimal characters (0-9, a-f, A-F)
    # This strips colons, dots, hyphens, and spaces.
    clean_mac = re.sub(r'[^0-9a-fA-F]', '', str(raw_mac))

    # 2. Validate that we have exactly 12 hex characters
    if len(clean_mac) != 12:
        print("[WARNING] Invalid MAC length for: " + str(raw_mac))
        return None

    # 3. Insert colons every two characters and convert to lowercase
    # This transforms 'aabbccddeeff' into 'aa:bb:cc:dd:ee:ff'
    formatted_mac = ":".join(
        clean_mac[i:i+2] for i in range(0, 12, 2)
    ).lower()

    return formatted_mac

def parse_radius_servers(config_str: str) -> dict:
    """Parses a RADIUS server configuration string into a structured dictionary.

    Args:
        config_str: A multi-line string containing the Cisco RADIUS configuration.

    Returns:
        A dictionary where the keys are the RADIUS server names (str) and values
        are dictionaries containing 'address' and/or 'key' configuration strings.
    """
    result = {}
    current_server = None
    config_list = config_str.splitlines()

    for line in config_list:
        clean_line = line.strip()

        if clean_line.startswith("radius server "):
            current_server = clean_line.split("radius server ")[1]
            result[current_server] = {}

        elif current_server is not None:
            if clean_line.startswith("address "):
                result[current_server]["address"] = clean_line
            elif clean_line.startswith("key "):
                result[current_server]["key"] = clean_line

    return result

def parse_tacacs_servers(config_str: str) -> dict:
    """Parses a TACACS+ server configuration string into a structured dictionary.

    Args:
        config_str: A multi-line string containing the Cisco TACACS+ configuration.

    Returns:
        A dictionary where the keys are the TACACS+ server names (str) and values
        are dictionaries containing 'address' and/or 'key' configuration strings.
    """
    result = {}
    current_server = None
    config_list = config_str.splitlines()

    for line in config_list:
        clean_line = line.strip()

        if clean_line.startswith("tacacs server "):
            current_server = clean_line.split("tacacs server ")[1]
            result[current_server] = {}

        elif current_server is not None:
            if clean_line.startswith("address "):
                result[current_server]["address"] = clean_line
            elif clean_line.startswith("key "):
                result[current_server]["key"] = clean_line

    return result
"""
Collection of shared ISE utility functions for network automation.
"""

import json
import os
import ssl
import hashlib
import socket
import requests

import config

class ISE:
    """Provides a secure interface for interacting with ISE ERS APIs."""
    def __init__(self, username: str, password: str) -> None: #pylint: disable=redefined-outer-name
        self.username = username
        self.password = password
        self.session = None  # Placeholder for the session object
        self.env_ers_base_url = os.getenv("ers_primary_url")
        config.require_env({
            "ers_primary_url": self.env_ers_base_url,
            "ers_primary_hostname": os.getenv("ers_primary_hostname"),
            "ers_primary_cert_path": os.getenv("ers_primary_cert_path"),
            "ers_primary_cert_name": os.getenv("ers_primary_cert_name"),
            "ers_primary_sha512_hash": os.getenv("ers_primary_sha512_hash"),
        })
        self.full_cert_path = self._validate_or_get_certificate()


    def __enter__(self) -> "ISE":
        """Opens the session and validates connectivity/cert trust before returning."""
        self.session = requests.Session()
        self.session.verify = self.full_cert_path
        self.session.auth = (self.username, self.password)
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json"
        })

        try:
            # Cheap, low-impact endpoint just to force the TLS handshake + auth check
            response = self.session.get(
                self.env_ers_base_url + "/ers/config/networkdevice?size=1",
                timeout=10
            )
            if response.status_code == 401:
                self.session.close()
                raise RuntimeError("ISE authentication failed. Check username/password.")
            response.raise_for_status()
            return self

        except requests.exceptions.SSLError as e:
            self.session.close()
            raise RuntimeError(
                f"ISE TLS/certificate verification failed: {e}"
            ) from e

        except requests.exceptions.RequestException as e:
            self.session.close()
            raise RuntimeError(
                f"Unable to connect to ISE: {e}"
            ) from e

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Ensures the session is closed when exiting the context."""
        if self.session:
            try:
                self.session.close()
                print("ISE session closed.")
            except Exception as e:  # pylint: disable=broad-exception-caught
                # We catch all exceptions here to ensure the cleanup phase
                print("An error occurred while closing the ISE session: " + str(e))

    def _validate_or_get_certificate(self) -> str:
        """Makes sure the ISE public cert is valid and on the local machine."""
        ers_primary_cert_path = os.getenv("ers_primary_cert_path")
        ers_primary_cert_name = os.getenv("ers_primary_cert_name")
        env_expected_ers_primary_cert_hash = os.getenv("ers_primary_sha512_hash")

        #Checks if the file exists
        if not os.path.exists(ers_primary_cert_path):
            print(f"""
Standard ISE requirements path does not exist.
Creating directory in {ers_primary_cert_path}
""")
            os.makedirs(ers_primary_cert_path)
        self.full_cert_path = os.path.join(ers_primary_cert_path, ers_primary_cert_name)

        #If file exists, convert to pem, hash, and compare to hash stored in .env
        if os.path.isfile(self.full_cert_path):
            try:
                with open(self.full_cert_path, "r", encoding="utf-8") as file:
                    pem_data = file.read()
                der_data = ssl.PEM_cert_to_DER_cert(pem_data)
                final_hash = hashlib.sha512(der_data).hexdigest()

                if final_hash != env_expected_ers_primary_cert_hash:
                    raise RuntimeError("ISE cert hash is invalid.")
                return self.full_cert_path

            except ValueError as exc:
                raise RuntimeError(
                    "ERROR: Local certificate file is corrupted or not a valid PEM. Exiting."
                ) from exc

        #If file does not exist, download and verify hash
        else:
            print(f"""
Missing ISE 1 certificate
Placing ISE 1 certificate in following directory: {ers_primary_cert_path}\n\n
""")
            self._get_server_certificate(self.full_cert_path)
            return self.full_cert_path

    def _get_server_certificate(self, full_cert_path) -> str:
        """Retrieves, verfies, and stores ISE 1 public cert on local machine.
        This module uses certificate pinning because there is no CA to reference.
        Ensures the script only communicates with the verified ISE hardware.
        """
        env_ers_primary_hostname = os.getenv("ers_primary_hostname")
        env_expected_ers_primary_cert_hash = os.getenv("ers_primary_sha512_hash")
        port = 443
        context = ssl.create_default_context()
        try:
            with socket.create_connection((env_ers_primary_hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=env_ers_primary_hostname) as sslsock:
                    print("Connection successful. Retrieving certificate...")
                    cert_der = sslsock.getpeercert(binary_form=True)

                    if not cert_der:
                        raise RuntimeError("Could not retrieve certificate from ISE server.")

                cert_hash = hashlib.sha512(cert_der).hexdigest()
                if cert_hash.lower() != env_expected_ers_primary_cert_hash.lower():
                    raise RuntimeError(f"""
                    SECURITY ALERT: Certificate hash mismatch!
                    Expected: {env_expected_ers_primary_cert_hash}
                    Received: {cert_hash}
                    """)

                pem_cert = ssl.DER_cert_to_PEM_cert(cert_der)

            with open(full_cert_path, "w", encoding="utf-8") as write_path:
                print("Writing certificate to file...\n")
                write_path.write(pem_cert)

            return full_cert_path

        except (socket.gaierror, socket.timeout, ConnectionRefusedError) as net_err:
            raise RuntimeError(
                f"Network Error connecting to {env_ers_primary_hostname}\n{net_err}"
                ) from net_err
        except ssl.SSLError as e:
            raise RuntimeError(
                f"SSL ERROR: {e}. The server may have a misconfigured certificate."
                ) from e
        except Exception as e: # pylint: disable=broad-exception-caught
            raise RuntimeError(f"An unexpected error occurred: {e}") from e

    def apply_anc_policy(self, mac_address, policy_name) -> None:
        """
        Makes a PUT request to the ISE ERS API to apply an ANC policy to a MAC address.
        """
        payload = {
            "OperationAdditionalData": {
                "additionalData": [
                    {
                        "name": "macAddress",
                        "value": mac_address
                    },
                    {
                        "name": "policyName",
                        "value": policy_name
                    }
                ]
            }
        }

        anc_url = "/ers/config/ancendpoint/apply"

        try:
            response = self.session.put(
                self.env_ers_base_url + anc_url,
                data=json.dumps(payload)
            )

            if response.status_code == 204:
                print("Applied ANC Policy to " + mac_address)
            elif response.status_code == 401:
                raise RuntimeError("Authentication failed. Exiting.")
            else:
                print("Status " + str(response.status_code) + " for " + mac_address)

        except requests.exceptions.RequestException as e:
            print("Network exception: " + str(e))

    def remove_anc_policy(self, mac_address, policy_name) -> None:
        """
        Makes a PUT request to the ISE ERS API to clear/remove an ANC policy from a MAC address.
        """
        payload = {
            "OperationAdditionalData": {
                "additionalData": [
                    {
                        "name": "macAddress",
                        "value": mac_address
                    },
                    {
                        "name": "policyName",
                        "value": policy_name
                    }
                ]
            }
        }

        anc_clear_url = "/ers/config/ancendpoint/clear"

        try:
            response = self.session.put(
                self.env_ers_base_url + anc_clear_url,
                data=json.dumps(payload)
            )

            if response.status_code == 204:
                print(f"Cleared ANC Policy '{policy_name}' from {mac_address}")
            elif response.status_code == 401:
                raise RuntimeError("Authentication failed. Exiting.")
            else:
                print(f"Could not clear policy. Status Code: {response.status_code}")

        except requests.exceptions.RequestException as e:
            print(f"Network exception during clear operation: {e}")

    def get_network_device_id(self, ip: str) -> str:
        """Retrives the id of a network device in ISE"""

        search_path = f"/ers/config/networkdevice/?filter=ipaddress.EQ.{ip}"
        try:
            response = self.session.get(self.env_ers_base_url + search_path)

            if response.status_code == 401:
                raise RuntimeError(
                    "[ERROR] Authentication failed against ISE during device search. Exiting."
                    )

            response.raise_for_status()
            search_results = response.json()

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Failed to query device by IP {ip}: {e}")
            return ""

        search_result_obj = search_results.get("SearchResult", {})
        resources = search_result_obj.get("resources", [])

        if not resources:
            print(f"[WARNING] No network device found with IP address: {ip}")
            return ""

        device_id = resources[0].get("id")
        if not device_id:
            print(f"[ERROR] Found matching record for {ip}, but resource ID is missing.")
            return ""
        return device_id

    def get_network_device_config(self, ip: str) -> dict:
        """Retrieves the full configuration of an ISE network device by its IP address.

        Args:
            ip (str): The target IP address of the network device.

        Returns:
            dict: The JSON configuration data of the device, or an empty dict if not found/error.
        """

        device_id = self.get_network_device_id(ip)

        if not device_id:
            return {}

        device_detail_path = f"/ers/config/networkdevice/{device_id}"

        try:
            response = self.session.get(self.env_ers_base_url + device_detail_path)

            if response.status_code == 401:
                raise RuntimeError(
                    "[ERROR] Authentication failed against ISE during configuration retrieval."
                    )

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Failed to fetch config for device ID {device_id}: {e}")
            return {}

    def patch_network_device(self, ip: str, radius_key: str, tacacs_key: str) -> dict:
        """Patches the RADIUS and TACACS+ shared secrets of an ISE network device by its IP address.

        Args:
            ip (str): The target IP address of the network device.

        Returns:
            dict: A status summary containing success/error indicators and the updated config 
                (if returned by the server). Returns an empty dict on critical failures.
        """
        device_id = self.get_network_device_id(ip)

        if not device_id:
            return {"status": "error", "message": "Device not found"}

        device_detail_path = f"/ers/config/networkdevice/{device_id}"

        payload = {
            "NetworkDevice": {
                "authenticationSettings": {"radiusSharedSecret": radius_key},
                "tacacsSettings": {"sharedSecret": tacacs_key}
                }
            }

        try:
            response = self.session.patch(
                self.env_ers_base_url + device_detail_path, 
                json=payload
            )

            if response.status_code == 401:
                raise RuntimeError(
                    "[ERROR] Authentication failed against ISE during patch operation. Exiting."
                )

            response.raise_for_status()
            print(f"Successfully updated RADIUS and TACACS keys for {ip} (ID: {device_id})")

            if response.status_code == 204 or not response.text.strip():
                return {
                    "status": "success",
                    "message": "Configuration updated successfully (No body returned)."
                    }

            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Failed to patch config for device ID {device_id}: {e}")
            return {"status": "error", "message": "Failed to update configuration"}

"""
Cisco Catalyst Center (formerly DNA Center) API Integration Module.

This module provides a structured, object-oriented framework for interacting with
the Cisco Catalyst Center REST API. 

The module is divided into three primary components:
    1. Connection/Authentication Management (CatalystCenterClient)
    2. Read-Only API Operations (CatalystCenterGetAPIs)
    3. State-Changing API Operations (CatalystCenterPostAPIs)
"""

import os
import getpass
import ssl
import hashlib
import socket
import ipaddress

import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException
from dotenv import load_dotenv

load_dotenv()


def _chunk_devices(device_list, chunk_size=20):
    """Helper generator to yield successive chunk-sized lists."""
    for i in range(0, len(device_list), chunk_size):
        yield device_list[i:i + chunk_size]

def is_ip(ip: str) -> bool:
    """Checks if an IP is an IP."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


class CatalystCenterClient:
    """
    Manages the authenticated HTTP session for Catalyst Center.

    Handles:
        - Certificate validation/pinning
        - API authentication
        - Session configuration
        - Authenticated API requests
    """

    def __init__(self, username: str, password: str) -> None:
        self.env_base_url = os.getenv("base_dnac_url")
        self.username = username
        self.password = password

        self.full_cert_path = None
        self.session = requests.Session()

        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json"
        })

    def __enter__(self) -> "CatalystCenterClient":
        """Establishes an authenticated Catalyst Center session."""
        try:
            self._validate_config()
            self.full_cert_path = self._check_dnac_cert()
            self.session.verify = self.full_cert_path
            self._get_dnactoken()
            self.username = None #Dumps username and password from memory after use for security
            self.password = None
        except Exception:
            self.session.close()
            raise
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Closes the HTTP session."""
        self.session.close()

    def _validate_config(self) -> None:
        """Validate required Catalyst Center configuration."""
        required = {
            "base_dnac_url": self.env_base_url,
            "dnac_host": os.getenv("dnac_host"),
            "dnac_cert_name": os.getenv("dnac_cert_name"),
            "dnac_cert_sha512_hash": os.getenv("dnac_cert_sha512_hash"),
            "dnac_cert_path": os.getenv("dnac_cert_path")
        }

        missing = [name for name, value in required.items() if not value]

        if missing:
            raise RuntimeError(
                f"Missing required Catalyst Center configuration: {', '.join(missing)}"
            )

    def _check_dnac_cert(self) -> str:
        """Validate the local DNAC certificate or retrieve it if missing."""

        cert_path = os.getenv("dnac_cert_path")
        dnac_cert = os.getenv("dnac_cert_name")
        expected_hash = os.getenv("dnac_cert_sha512_hash")

        if not os.path.exists(cert_path):
            print(f"""
Standard DNAC requirements path does not exist.
Creating directory in {cert_path}
""")
            os.makedirs(cert_path)

        full_cert_path = os.path.join(cert_path, dnac_cert)

        if os.path.isfile(full_cert_path):
            try:
                with open(full_cert_path, "r", encoding="utf-8") as file:
                    pem_data = file.read()

                der_data = ssl.PEM_cert_to_DER_cert(pem_data)
                actual_hash = hashlib.sha512(der_data).hexdigest()

            except ValueError as exc:
                raise RuntimeError(
                    "Local DNAC certificate is corrupted or not valid PEM."
                ) from exc

            if actual_hash.lower() != expected_hash.lower():
                raise RuntimeError(
                    "DNAC certificate hash does not match the expected hash."
                )

            return full_cert_path

        print(f"""
            !!! Missing DNAC certificate !!!
            Placing DNAC certificate in:
            {cert_path}
            """)

        return self._get_server_certificate(full_cert_path)

    def _get_server_certificate(self, full_cert_path) -> str:
        """Retrieves, verfies, and stores DNAC public cert on local machine.
        This module uses certificate pinning because there is no easy CA to reference.
        Ensures the script only communicates with the verified DNAC hardware.
        """
        env_dnac_hostname = os.getenv("dnac_host")
        env_expected_dnac_cert_hash = os.getenv("dnac_cert_sha512_hash")

        # Certificate validation is intentionally disabled during initial retrieval.
        # Trust is established by comparing the server certificate's SHA-512 fingerprint
        # against the independently configured expected fingerprint.

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection(
                (env_dnac_hostname, 443),
                timeout=15
                ) as sock:
                with context.wrap_socket(
                    sock,
                    server_hostname=env_dnac_hostname
                    ) as sslsock:

                    print("Connection successful. Retrieving certificate...")

                    cert_der = sslsock.getpeercert(binary_form=True)
                    if not cert_der:
                        raise RuntimeError("Could not retrieve certificate.")

                cert_hash = hashlib.sha512(cert_der).hexdigest()
                if cert_hash.lower() != env_expected_dnac_cert_hash.lower():
                    raise RuntimeError(f"""
Certificate hash mismatch!
Expected: {env_expected_dnac_cert_hash}
Received: {cert_hash}
                    """)

                pem_cert = ssl.DER_cert_to_PEM_cert(cert_der)

            with open(full_cert_path, "w", encoding="utf-8") as write_path:
                print("Writing certificate to file...\n")
                write_path.write(pem_cert)

            return full_cert_path

        except (socket.gaierror, socket.timeout, ConnectionRefusedError) as net_err:
            raise RuntimeError(
                f"Network Error connecting to {env_dnac_hostname}\n{net_err}"
                ) from net_err
        except ssl.SSLError as e:
            raise RuntimeError(
                f"SSL ERROR: {e}. The server may have a misconfigured certificate."
                ) from e

    def _get_dnactoken(self) -> None:
        """Authenticates to Catalyst Center and stores the API token."""

        login_counter = 0
        current_password = self.password
        auth_url = "/dna/system/api/v1/auth/token"

        while login_counter < 2:
            try:
                response = self.session.post(
                    self.env_base_url + auth_url,
                    auth=HTTPBasicAuth(
                        self.username,
                        current_password
                    ),
                    timeout=15
                )

                if response.status_code == 401:
                    login_counter += 1

                    print("\nAuthentication failed. HTTP 401 Unauthorized.")
                    print(f"Warning: Attempt {login_counter} of 2.")

                    if login_counter >= 2:
                        raise RuntimeError(
                            "Max safe attempts reached to prevent TACACS "
                            "lockout. Please verify your credentials."
                        )

                    current_password = getpass.getpass(
                        prompt="Password: "
                    )
                    continue

                response.raise_for_status()

                try:
                    token = response.json()["Token"]
                except KeyError as exc:
                    raise RuntimeError(
                        "Authentication succeeded but 'Token' was missing "
                        "from the response."
                    ) from exc

                self.session.headers["X-Auth-Token"] = token

                return

            except RequestException as exc:
                raise RuntimeError(
                    f"Network or HTTP error while contacting DNAC: {exc}"
                ) from exc

        raise RuntimeError("Catalyst Center authentication failed unexpectedly.")

    def _refresh_token(self) -> None:
        """Refreshes the Catalyst Center authentication token."""
        if not self.username or not self.password:
            print("Username and password were cleared from memory. "
            "Please enter your credentials again to refresh the token.")
            self.username = input("Username: ")
            self.password = getpass.getpass("Password: ")

        try:
            self.session.headers.pop("X-Auth-Token", None)
            self._get_dnactoken()
        finally:
            # Clear credentials from memory after use for security.
            self.username = None
            self.password = None

    def request(
            self,
            method: str,
            endpoint: str,
            **kwargs
            ) -> requests.Response:
        """Makes an authenticated Catalyst Center API request."""

        try:
            response = self.session.request(
                method,
                self.env_base_url + endpoint,
                timeout=15,
                **kwargs
            )

        except RequestException as exc:
            raise RuntimeError(
                f"Network or HTTP error while contacting DNAC: {exc}"
            ) from exc

        if response.status_code == 401:
            print("Catalyst Center token expired. Refreshing token...")

            self._refresh_token()

            try:
                response = self.session.request(
                    method,
                    self.env_base_url + endpoint,
                    timeout=15,
                    **kwargs
                )
            except RequestException as exc:
                raise RuntimeError(
                    f"Network or HTTP error while retrying DNAC request: {exc}"
                ) from exc

            if response.status_code == 401:
                raise RuntimeError(
                    "Catalyst Center authentication failed after token refresh."
                )

        try:
            response.raise_for_status()
        except RequestException as exc:
            raise RuntimeError(
                f"Catalyst Center returned an error response: {exc}"
            ) from exc

        return response

    def request_json(self, method: str, endpoint: str, **kwargs) -> dict:
        """Make an authenticated request and return the JSON response.
        
        Args:
            method: HTTP method (GET, POST, PUT, PATCH, DELETE)
            endpoint: API endpoint path
            **kwargs: Additional arguments passed to requests.request()
            
        Returns:
            dict: Parsed JSON response
            
        Raises:
            RuntimeError: If request fails or response cannot be parsed as JSON
            ValueError: If response contains malformed or invalid JSON
        """
        response = self.request(method, endpoint, **kwargs)

        try:
            return response.json()
        except ValueError as exc:
            raise ValueError(
                f"Catalyst Center returned malformed JSON for {endpoint}. "
                f"Status: {response.status_code}, Content preview: {response.text[:200]}"
            ) from exc


class CatalystCenterGetAPIs:
    """
    Executes read-only operations (HTTP GET requests) against the Catalyst Center API.

    This class operates as a data retrieval layer. It relies on dependency injection,
    expecting to be initialized with active authentication headers and a valid 
    certificate path provided by the ConnectionHandler. Using this class guarantees 
    that no state changes or configurations are applied to the controller or network.
    """

    def __init__(self, client: CatalystCenterClient) -> None:
        self.client = client


    def get_devices_raw(self) -> dict:
        """Retrieves complete, raw JSON object of network devices from DNAC, handling pagination."""

        all_devices = []
        pagination_params = {"offset": 1, "limit": 500}

        while True:
            response = self.client.request(
                "GET",
                "/dna/intent/api/v1/network-device",
                params = pagination_params
            )

            try:
                current_batch = response.json().get("response", [])
            except ValueError as exc:
                raise RuntimeError(
                    "Catalyst Center returned malformed JSON "
                    "during device retrieval."
                ) from exc

            if not current_batch:
                break

            all_devices.extend(current_batch)
            pagination_params["offset"] += pagination_params["limit"]

        print(f"Successfully retrieved {len(all_devices)} total devices.")

        return all_devices

    def get_device_by_hostname(self, hostname_search=None) -> dict:
        """Retrieves JSON object of network device from DNAC by hostname"""

        if not hostname_search:
            hostname_search = input("""
What is the hostname of the device you'd like to pull from DNAC?
Type here: """)

        hostname = hostname_search + os.getenv("domain_suffix")

        response = self.client.request(
            "GET",
            "/dna/intent/api/v1/network-device",
            params={"hostname": hostname}
        )
        try:
            return response.json().get("response", [])
        except ValueError as exc:
            raise RuntimeError(
                "Catalyst Center returned malformed JSON "
            ) from exc

    def get_device_by_ip(self, ip_search=None) -> dict:
        """Retrieves JSON object of network device from DNAC by IP address"""

        while not ip_search or not is_ip(ip_search):
            ip_search = input("""
What is the IP address of the device you'd like to pull from DNAC?
Type here: """)

        try:
            response = self.client.request(
                "GET",
                "/dna/intent/api/v1/network-device",
                params={"managementIpAddress": ip_search}
            )
            return response.json().get("response", [])
        except ValueError as exc:
            raise RuntimeError(
                "Catalyst Center returned malformed JSON "
            ) from exc

    def get_client_detail(self, mac) -> dict:
        """Gets client detail from Catalyst Center based on MAC Address"""

        try:
            response = self.client.request_json(
                "GET",
                "/dna/intent/api/v1/client-detail",
                params={"macAddress": mac}
            )
            return response

        except ValueError as exc:
            raise RuntimeError(
                "Catalyst Center returned malformed JSON "
            ) from exc

    def get_task_status(self, task_id: str) -> tuple[str, str | None]:
        """Get the task status and returns the id, progress, and if there is an error.
        If there is an error, also returns the error reason.

        Args:
            task_id: The Catalyst Center task identifier

        Returns:
            tuple: (formatted_status_string, failure_reason_or_None)
        """

        task_data = self.client.request_json(
            "GET",
            f"/dna/intent/api/v1/task/{task_id}"
        ).get("response", {})

        # Parse the task response
        progress = task_data.get("progress", "Unknown")
        is_error = task_data.get("isError", False)

        # Print a summarized row for each task
        error_flag = "YES" if is_error else "No"
        return_value = f"{task_id:<40} | {progress:<15} | {error_flag:<6}"

        # If there is an error, print the exact failure reason below it
        failure_reason = None
        if is_error:
            failure_reason = task_data.get("failureReason", "No reason provided by API.")

        return return_value, failure_reason


class CatalystCenterPostAPIs:
    """
    Executes state-changing operations (HTTP POST/PUT requests) against the Catalyst Center API.

    This class serves as the command-and-control layer for making modifications,
    executing actions, or pushing configurations (e.g., bulk telemetry updates). 
    It expects to be initialized with active authentication headers and a valid 
    certificate path provided by the ConnectionHandler.
    """
    def __init__(self, client: CatalystCenterClient) -> None:
        self.client = client

    def update_telemetry_settings(self, uuids: list, force_push: bool = False) -> dict:
        """Pushes telemetry settings to sync/conform a list of network devices.
        
        Args:
            uuids (list): A list of network-device UUID strings.
            force_push (bool): Force configuration push to the devices.
        """

        # Ensure uuids is treated as a list even if a single string is passed
        if isinstance(uuids, str):
            uuids = [uuids]

        payload = {
            "deviceIds": uuids,
            "forceConfigurationPush": force_push
        }

        return self.client.request_json(
            "POST",
            "/dna/intent/api/v1/telemetrySettings/apply",
            json=payload
        )


    def bulk_update_telemetry(
            self,
            uuids: list,
            chunk_size: int = 20,
            force_push: bool = True
            ) -> dict:
        """Splits a large list of UUIDs into safe batches and executes them.

        A failure in one batch does not abort the remaining batches — each
        chunk is attempted independently so a transient failure on one batch
        doesn't erase task IDs already registered for earlier successful batches.

        Args:
            uuids (list): Complete list of target device UUIDs.
            chunk_size (int): Max devices to process per API call.
            force_push (bool): Force configuration push on the hardware.

        Returns:
            dict: {
                "succeeded": list of {"devices_targeted": [...], "taskId": ...},
                "failed": list of {"devices_targeted": [...], "error": str},
            }
        """
        succeeded = []
        failed = []
        total_devices = len(uuids)
        print(
            f"Initiating bulk telemetry update for {total_devices} "
            f"devices in chunks of {chunk_size}..."
        )

        for chunk in _chunk_devices(uuids, chunk_size):
            print(f"Sending batch of {len(chunk)} devices to Catalyst Center...")

            try:
                result = self.update_telemetry_settings(chunk, force_push=force_push)
            except RuntimeError as exc:
                print(f"Batch failed to register. Devices: {chunk}\nReason: {exc}")
                failed.append({"devices_targeted": chunk, "error": str(exc)})
                continue

            task_id = result.get("response", {}).get("taskId")
            if task_id:
                succeeded.append({"devices_targeted": chunk, "taskId": task_id})
                print(f"Batch accepted. Task ID registered: {task_id}")
            else:
                print(f"Batch accepted but no taskId returned. Devices: {chunk}")
                failed.append({
                    "devices_targeted": chunk,
                    "error": "No taskId in response."
                })

        if failed:
            print(
                f"\n{len(failed)} of {len(succeeded) + len(failed)} batches "
                "failed to register. See 'failed' in the return value for details."
            )

        return {"succeeded": succeeded, "failed": failed}

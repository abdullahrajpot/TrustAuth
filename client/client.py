import json
import os
from pathlib import Path

import requests

from tpm_manager.tpm_handler import TPMManager

STATE_PATH = Path(os.getenv("TRUSTAUTH_STATE_FILE", "trustauth_client_state.json"))
TPM_KEY_PATH = Path(os.getenv("TRUSTAUTH_TPM_KEY_FILE", "trustauth_tpm_key.pem"))


class TrustAuthClient:
    def __init__(self, server_url: str = "http://localhost:8000") -> None:
        self.server_url = server_url
        self.tpm = TPMManager()
        self.device_id: int | None = None
        self.token: str | None = None
        self._load_state()
        self._try_load_saved_tpm_key()

    def _load_state(self) -> None:
        if not STATE_PATH.is_file():
            return
        try:
            data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            self.device_id = int(data["device_id"]) if data.get("device_id") is not None else None
        except (OSError, ValueError, KeyError, TypeError):
            pass

    def _save_state(self, username: str) -> None:
        if self.device_id is None:
            return
        payload = {"device_id": self.device_id, "username": username}
        STATE_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _try_load_saved_tpm_key(self) -> None:
        if not TPM_KEY_PATH.is_file():
            return
        try:
            self.tpm.load_tpm_key_pem(TPM_KEY_PATH.read_bytes())
        except RuntimeError:
            pass
        except Exception:
            pass

    def register(self, username: str, password: str, device_name: str, email: str = "") -> bool:
        """Register user and device. With real TPM, the key is saved to TPM_KEY_PATH for later logins."""
        if not self.tpm.is_available:
            print("TPM not available.")
            return False

        public_key = self.tpm.create_attestation_key()
        try:
            TPM_KEY_PATH.write_bytes(self.tpm.export_tpm_key_pem())
        except RuntimeError:
            pass

        payload = {
            "username": username,
            "password": password,
            "email": email or None,
            "device_name": device_name,
            "device_type": "laptop",
            "tpm_public_key": public_key,
            "pcr_values": self.tpm.get_pcr_values(),
            "attach_to_existing": True,
        }
        response = requests.post(f"{self.server_url}/api/register", json=payload, timeout=15)
        if response.ok:
            self.device_id = response.json()["device_id"]
            self._save_state(username)
            print("Registration successful.")
            return True
        print("Registration failed:", response.text)
        return False

    def login(self, username: str, password: str) -> bool:
        if not self.device_id:
            print("No device is registered on this client. Register first (or restore trustauth_client_state.json).")
            return False
        challenge_resp = requests.post(
            f"{self.server_url}/api/challenge",
            json={"device_id": self.device_id},
            timeout=15,
        )
        if not challenge_resp.ok:
            print("Challenge failed:", challenge_resp.text)
            return False

        challenge = challenge_resp.json()["challenge"]
        signature = self.tpm.sign_challenge(challenge)
        if not signature:
            print("Signing failed (TPM key missing?).")
            return False
        login_resp = requests.post(
            f"{self.server_url}/api/login",
            json={
                "username": username,
                "password": password,
                "device_id": self.device_id,
                "challenge_nonce": challenge,
                "signature": signature,
            },
            timeout=15,
        )
        if login_resp.ok:
            self.token = login_resp.json()["token"]
            print("Login successful.")
            return True
        print("Login failed:", login_resp.text)
        return False

    def list_devices(self):
        if not self.token:
            print("Please login first.")
            return
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.get(f"{self.server_url}/api/devices", headers=headers, timeout=15)
        print(response.json() if response.ok else response.text)

    def revoke_device(self, device_id: int):
        if not self.token:
            print("Please login first.")
            return
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.delete(
            f"{self.server_url}/api/devices/{device_id}",
            headers=headers,
            timeout=15,
        )
        print(response.json() if response.ok else response.text)

    def logout(self):
        if not self.token:
            return
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.post(f"{self.server_url}/api/logout", headers=headers, timeout=15)
        if response.ok:
            self.token = None
            print("Logged out.")

    def interactive_mode(self):
        while True:
            print("\n1) Register 2) Login 3) Devices 4) Revoke 5) Logout 6) Exit")
            choice = input("Choose: ").strip()
            if choice == "1":
                self.register(
                    input("Username: ").strip(),
                    input("Password: ").strip(),
                    input("Device name: ").strip(),
                    input("Email (optional): ").strip(),
                )
            elif choice == "2":
                self.login(input("Username: ").strip(), input("Password: ").strip())
            elif choice == "3":
                self.list_devices()
            elif choice == "4":
                self.revoke_device(int(input("Device id: ").strip()))
            elif choice == "5":
                self.logout()
            elif choice == "6":
                break
            else:
                print("Invalid choice.")


if __name__ == "__main__":
    TrustAuthClient().interactive_mode()

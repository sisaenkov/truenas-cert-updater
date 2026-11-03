#!/usr/bin/env python3
"""
Upload a locally stored certificate + private key to TrueNAS (SCALE 24.10+ / 25.x)
and make it the web UI certificate.

Based on renew_update_cert.py, with the Tailscale generation step replaced by
reading PEM files from disk. Designed to run from a remote machine.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
import urllib3

logger = logging.getLogger("upload_local_cert")


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Config:
    api_base_url: str
    api_key: str
    cert_file_path: Path
    key_file_path: Path
    certificate_name_prefix: str = "cert"
    verify_ssl: bool | str = False
    delete_old: bool = True
    delete_only_prefixed: bool = True
    force: bool = False


# Old update_cert.py (.config.json) keys -> new keys
LEGACY_KEYS = {
    "API_BASE_URL": "api_base_url",
    "API_KEY": "api_key",
    "CERT_FILE_PATH": "cert_file_path",
    "CERT_KEY_PATH": "key_file_path",
    "CERT_NAME_PREFIX": "certificate_name_prefix",
}


def _read_raw_config(path: Path) -> dict[str, Any]:
    with open(path, "rt", encoding="utf-8") as f:
        if path.suffix.lower() == ".json":
            return json.load(f) or {}
        if path.suffix.lower() in {".yaml", ".yml"}:
            import yaml  # only needed for YAML configs
            return yaml.safe_load(f) or {}
    raise ValueError("Config file must be .json, .yaml or .yml")


def _as_bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def load_config(path: Path) -> Config:
    raw = _read_raw_config(path)
    for old, new in LEGACY_KEYS.items():
        if old in raw and new not in raw:
            raw[new] = raw[old]

    missing = [k for k in ("api_base_url", "api_key", "cert_file_path", "key_file_path") if not raw.get(k)]
    if missing:
        raise ValueError(f"Missing required config keys: {', '.join(missing)}")

    base = Path(path).resolve().parent

    def resolve(p: str) -> Path:
        p = Path(os.path.expanduser(p))
        return p if p.is_absolute() else (base / p)

    verify = raw.get("verify_ssl", False)
    # verify_ssl may be a bool or a path to a CA bundle
    if not (isinstance(verify, str) and Path(os.path.expanduser(verify)).exists()):
        verify = _as_bool(verify)
    else:
        verify = os.path.expanduser(verify)

    return Config(
        api_base_url=str(raw["api_base_url"]).rstrip("/"),
        api_key=str(raw["api_key"]),
        cert_file_path=resolve(raw["cert_file_path"]),
        key_file_path=resolve(raw["key_file_path"]),
        certificate_name_prefix=str(raw.get("certificate_name_prefix", "cert")),
        verify_ssl=verify,
        delete_old=_as_bool(raw.get("delete_old", True)),
        delete_only_prefixed=_as_bool(raw.get("delete_only_prefixed", True)),
        force=_as_bool(raw.get("force", False)),
    )


def find_config_path() -> Path:
    env = os.environ.get("TRUENAS_CERT_CONFIG")
    if len(sys.argv) > 1:
        return Path(sys.argv[1])
    if env:
        return Path(env)
    here = Path(__file__).resolve().parent
    for name in (".config.yaml", ".config.yml", ".config.json"):
        if (here / name).exists():
            return here / name
    raise FileNotFoundError(
        "No config found. Pass a path as the first argument, set TRUENAS_CERT_CONFIG, "
        "or create .config.yaml / .config.json next to the script."
    )


# --------------------------------------------------------------------------- #
# TrueNAS REST client
# --------------------------------------------------------------------------- #

class TrueNAS:
    def __init__(self, base_url: str, api_key: str, verify: bool | str):
        self.base = base_url
        self.s = requests.Session()
        self.s.headers["Authorization"] = f"Bearer {api_key}"
        self.s.verify = verify
        if verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _req(self, method: str, path: str, **kw: Any) -> Any:
        r = self.s.request(method, f"{self.base}{path}", timeout=60, **kw)
        if not r.ok:
            raise RuntimeError(f"{method} {path} -> HTTP {r.status_code}: {r.text[:500]}")
        return r.json() if r.content else None

    def get(self, path: str, **kw: Any) -> Any:
        return self._req("GET", path, **kw)

    def post(self, path: str, payload: Any) -> Any:
        return self._req("POST", path, json=payload)

    def put(self, path: str, payload: Any) -> Any:
        return self._req("PUT", path, json=payload)

    def delete(self, path: str) -> Any:
        return self._req("DELETE", path)

    # --- jobs ---------------------------------------------------------------

    def wait_job(self, job_id: int, timeout: float = 120) -> Any:
        """Poll core/get_jobs until the job finishes; raise on failure."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            jobs = self.get("/core/get_jobs", params={"id": job_id})
            job = jobs[0] if isinstance(jobs, list) and jobs else None
            if job:
                state = job.get("state")
                if state == "SUCCESS":
                    return job.get("result")
                if state in {"FAILED", "ABORTED"}:
                    raise RuntimeError(f"Job {job_id} {state}: {job.get('error') or job.get('exception')}")
            time.sleep(1)
        raise TimeoutError(f"Job {job_id} did not finish in {timeout}s")

    # --- certificates -------------------------------------------------------

    def list_certificates(self) -> list[dict[str, Any]]:
        return self.get("/certificate")

    def get_certificate(self, cert_id: int) -> dict[str, Any] | None:
        return next((c for c in self.list_certificates() if c.get("id") == cert_id), None)

    def get_certificate_by_name(self, name: str) -> dict[str, Any] | None:
        return next((c for c in self.list_certificates() if c.get("name") == name), None)

    def import_certificate(self, name: str, certificate: str, private_key: str) -> dict[str, Any]:
        result = self.post("/certificate", {
            "name": name,
            "certificate": certificate,
            "privatekey": private_key,
            "create_type": "CERTIFICATE_CREATE_IMPORTED",
        })
        # certificate.create is a job: REST returns a job id, not the object
        if isinstance(result, int) and not isinstance(result, bool):
            logger.info("Certificate import job started: %s", result)
            try:
                self.wait_job(result)
            except RuntimeError:
                raise  # job reported FAILED/ABORTED
            except Exception as exc:  # get_jobs unavailable etc. -> fall back to polling by name
                logger.warning("Could not poll job %s (%s), polling by name instead", result, exc)
        for _ in range(30):
            cert = self.get_certificate_by_name(name)
            if cert:
                return cert
            time.sleep(1)
        raise RuntimeError(f"Certificate {name!r} not found after import")

    # --- UI -----------------------------------------------------------------

    def get_ui_certificate_id(self) -> int | None:
        ui = self.get("/system/general").get("ui_certificate")
        if isinstance(ui, dict):
            return ui.get("id")
        return int(ui) if ui is not None else None

    def set_ui_certificate(self, cert_id: int) -> None:
        self.put("/system/general", {"ui_certificate": int(cert_id)})

    def restart_ui(self, delay: int = 3) -> None:
        self.post("/system/general/ui_restart", delay)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def normalize_pem(pem: str) -> str:
    return "\n".join(line.strip() for line in pem.strip().splitlines() if line.strip())


def first_cert_block(pem: str) -> str:
    """Return the leaf certificate block (first one) of a PEM chain, normalized."""
    norm = normalize_pem(pem)
    end = "-----END CERTIFICATE-----"
    idx = norm.find(end)
    return norm[: idx + len(end)] if idx != -1 else norm


def read_pem_files(cert_path: Path, key_path: Path) -> tuple[str, str]:
    for p in (cert_path, key_path):
        if not p.is_file():
            raise FileNotFoundError(f"File not found: {p}")
    cert = cert_path.read_text(encoding="utf-8")
    key = key_path.read_text(encoding="utf-8")
    if "BEGIN CERTIFICATE" not in cert:
        raise ValueError(f"{cert_path} does not look like a PEM certificate")
    if "PRIVATE KEY" not in key:
        raise ValueError(f"{key_path} does not look like a PEM private key")
    check_key_matches(cert, key)
    return cert, key


def check_key_matches(cert_pem: str, key_pem: str) -> None:
    """Verify key/cert pair if `cryptography` is installed; otherwise skip silently."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        logger.debug("cryptography not installed, skipping key/cert match check")
        return
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    fmt = (serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    if cert.public_key().public_bytes(*fmt) != key.public_key().public_bytes(*fmt):
        raise ValueError("Private key does not match the certificate")
    logger.info("Certificate: subject=%s, expires=%s",
                cert.subject.rfc4514_string(),
                getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main() -> int:
    config = load_config(find_config_path())
    api = TrueNAS(config.api_base_url, config.api_key, config.verify_ssl)

    certificate, private_key = read_pem_files(config.cert_file_path, config.key_file_path)

    logger.info("Checking TrueNAS connectivity at %s ...", config.api_base_url)
    api.get("/system/state")
    logger.info("TrueNAS version: %s", api.get("/system/version"))

    previous_id = api.get_ui_certificate_id()
    previous = api.get_certificate(previous_id) if previous_id else None

    if previous and not config.force and \
            first_cert_block(previous.get("certificate") or "") == first_cert_block(certificate):
        logger.info("UI already uses this certificate (%s, id=%s). Nothing to do.",
                    previous.get("name"), previous_id)
        return 0

    # Reuse an already imported identical cert if present (e.g. a previous run failed midway)
    leaf = first_cert_block(certificate)
    cert_record = next(
        (c for c in api.list_certificates()
         if first_cert_block(c.get("certificate") or "") == leaf and c.get("privatekey") is not False),
        None,
    )
    if cert_record and not config.force:
        logger.info("Identical certificate already imported: %s (id=%s)", cert_record["name"], cert_record["id"])
    else:
        name = f"{config.certificate_name_prefix}_{datetime.datetime.now():%Y%m%d_%H%M%S}"
        logger.info("Importing certificate as %s", name)
        cert_record = api.import_certificate(name, certificate, private_key)

    cert_id = int(cert_record["id"])
    logger.info("Setting UI certificate to id=%s", cert_id)
    api.set_ui_certificate(cert_id)

    logger.info("Restarting TrueNAS UI ...")
    api.restart_ui()

    if not (config.delete_old and previous_id and previous_id != cert_id):
        logger.info("No previous UI certificate to delete.")
        logger.info("Done.")
        return 0

    prev_name = (previous or {}).get("name", "")
    if config.delete_only_prefixed and not prev_name.startswith(config.certificate_name_prefix):
        logger.info("Keeping previous UI certificate %r (id=%s): name does not start with %r",
                    prev_name, previous_id, config.certificate_name_prefix)
        logger.info("Done.")
        return 0

    # The UI (nginx) restarts after the delay above; wait and retry while it comes back.
    time.sleep(10)
    for attempt in range(1, 7):
        try:
            if api.get_certificate(previous_id) is None:
                logger.info("Previous certificate id=%s is gone.", previous_id)
                break
            logger.info("Deleting previous UI certificate %r (id=%s)", prev_name, previous_id)
            result = api.delete(f"/certificate/id/{previous_id}")
            if isinstance(result, int) and not isinstance(result, bool):
                api.wait_job(result)
            break
        except Exception as exc:
            if attempt == 6:
                logger.warning("Could not delete previous certificate id=%s: %s", previous_id, exc)
            else:
                time.sleep(5)

    logger.info("Done.")
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        sys.exit(main())
    except Exception as exc:
        logger.error("%s", exc)
        sys.exit(1)

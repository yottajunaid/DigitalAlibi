#!/usr/bin/env python3
"""Digital Alibi: portable ambient-environment evidence capture.

All application-created artifacts are confined to the directory from which this
program is started.  It deliberately writes no host-profile, temporary, or
system log files.  The executable should be distributed as a PyInstaller
``--onedir`` bundle, not ``--onefile``, because onefile extraction uses a host
temporary directory.

This tool preserves identifiers and cryptographic evidence, not audio
recordings.  It is intended for authorised forensic triage only.
"""
from __future__ import print_function

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import platform
import re
import secrets
import sqlite3
import subprocess
import sys
import time
import uuid
import zlib
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

__version__ = "1.0.0"
SCHEMA = "digital-alibi.evidence/v1"
DEFAULT_TSA_URL = "https://freetsa.org/tsr"
DB_NAME = "digital_alibi.sqlite"
KEY_NAME = "digital_alibi_ed25519_private.pem"
PUBLIC_KEY_NAME = "digital_alibi_ed25519_public.pem"
TSR_DIR_NAME = "tsr"
MAX_SUBPROCESS_OUTPUT = 1_000_000
MAC_RE = re.compile(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}")


class DigitalAlibiError(Exception):
    """Expected application error suitable for an investigator-facing message."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> bytes:
    """Return unambiguous UTF-8 JSON used by every evidence hash."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)


class EvidenceStore(object):
    """Owns all persistent files and refuses to escape the acquisition root."""

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = (root or Path.cwd()).resolve()
        if not self.root.is_dir():
            raise DigitalAlibiError("The current working directory is not a directory: %s" % self.root)
        if not os.access(str(self.root), os.W_OK):
            raise DigitalAlibiError("The current working directory is not writable: %s" % self.root)

    def path(self, *parts: str) -> Path:
        candidate = self.root.joinpath(*parts).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError:
            raise DigitalAlibiError("Refusing to write outside the acquisition directory")
        return candidate

    @property
    def database_path(self) -> Path:
        return self.path(DB_NAME)

    def tsr_path(self, capture_id: str) -> Path:
        directory = self.path(TSR_DIR_NAME)
        directory.mkdir(mode=0o700, exist_ok=True)
        return self.path(TSR_DIR_NAME, safe_filename(capture_id) + ".tsr")

    def connect(self) -> sqlite3.Connection:
        # sqlite creates the database only under self.root. WAL is intentionally
        # disabled so no -wal/-shm files remain if a USB is unplugged abruptly.
        conn = sqlite3.connect(str(self.database_path), timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        self.initialize(conn)
        return conn

    @staticmethod
    def initialize(conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS captures (
                capture_id TEXT PRIMARY KEY NOT NULL,
                captured_at_utc TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                compressed_payload_b64 TEXT NOT NULL,
                compressed_sha256 TEXT NOT NULL,
                compressed_size INTEGER NOT NULL,
                source_summary_json TEXT NOT NULL,
                tsa_status TEXT NOT NULL,
                tsr_path TEXT,
                tsa_url TEXT,
                tsa_message_imprint TEXT NOT NULL,
                tsa_error TEXT,
                local_signature_b64 TEXT,
                local_key_fingerprint TEXT,
                merkle_batch_id TEXT,
                created_at_utc TEXT NOT NULL,
                sealed_at_utc TEXT
            );
            CREATE TABLE IF NOT EXISTS merkle_batches (
                batch_id TEXT PRIMARY KEY NOT NULL,
                created_at_utc TEXT NOT NULL,
                leaf_count INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                leaf_hashes_json TEXT NOT NULL,
                signature_b64 TEXT NOT NULL,
                public_key_b64 TEXT NOT NULL,
                key_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at_utc TEXT NOT NULL,
                capture_id TEXT,
                action TEXT NOT NULL,
                details_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_captures_tsa_status ON captures(tsa_status);
            """
        )
        conn.execute("INSERT OR IGNORE INTO metadata(key, value) VALUES (?, ?)", ("schema_version", "1"))
        conn.execute("INSERT OR IGNORE INTO metadata(key, value) VALUES (?, ?)", ("created_at_utc", utc_now()))
        # A v1 development database may predate the exact compressed byte
        # representation. Retain read compatibility, but newly created
        # records always include it for cross-platform verification.
        columns = {row[1] for row in conn.execute("PRAGMA table_info(captures)")}
        if "compressed_payload_b64" not in columns:
            conn.execute("ALTER TABLE captures ADD COLUMN compressed_payload_b64 TEXT")
        conn.commit()

    @staticmethod
    def audit(conn: sqlite3.Connection, action: str, details: Dict[str, Any], capture_id: Optional[str] = None) -> None:
        conn.execute(
            "INSERT INTO audit_events(occurred_at_utc, capture_id, action, details_json) VALUES (?, ?, ?, ?)",
            (utc_now(), capture_id, action, canonical_json(details).decode("utf-8")),
        )


class LocalSigner(object):
    """Ed25519 signer retained only on the evidence USB for offline sealing."""

    def __init__(self, store: EvidenceStore) -> None:
        self.store = store
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError as exc:
            raise DigitalAlibiError("Local offline sealing requires bundled dependency 'cryptography': %s" % exc)
        self.serialization = serialization
        self.Ed25519PrivateKey = Ed25519PrivateKey
        self.private_path = store.path(KEY_NAME)
        self.public_path = store.path(PUBLIC_KEY_NAME)
        self.private_key = self._load_or_create()

    def _load_or_create(self) -> Any:
        if self.private_path.exists():
            data = self.private_path.read_bytes()
            try:
                return self.serialization.load_pem_private_key(data, password=None)
            except (ValueError, TypeError) as exc:
                raise DigitalAlibiError("Cannot load local evidence signing key: %s" % exc)
        key = self.Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=self.serialization.Encoding.PEM,
            format=self.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=self.serialization.NoEncryption(),
        )
        self.private_path.write_bytes(pem)
        try:
            os.chmod(str(self.private_path), 0o600)
        except OSError:
            # Windows ACLs cannot be expressed with chmod. The key remains USB-local.
            pass
        public_pem = key.public_key().public_bytes(
            encoding=self.serialization.Encoding.PEM,
            format=self.serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_path.write_bytes(public_pem)
        return key

    def public_der(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=self.serialization.Encoding.DER,
            format=self.serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def fingerprint(self) -> str:
        return sha256_hex(self.public_der())

    def sign(self, message: bytes) -> str:
        return base64.b64encode(self.private_key.sign(message)).decode("ascii")


def command_environment() -> Dict[str, str]:
    """Stable parsing locale, retaining only enough host environment to execute tools."""
    env = dict(os.environ)
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    return env


def run_command(command: Sequence[str], cwd: Path, timeout: int = 12) -> Tuple[int, str, str]:
    """Run a fixed OS command without a shell and cap returned text."""
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(cwd),
            env=command_environment(),
            shell=False,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return 127, "", "command unavailable"
    except subprocess.TimeoutExpired:
        return 124, "", "command timed out"
    except OSError as exc:
        return 126, "", "command failed: %s" % exc
    stdout = completed.stdout[:MAX_SUBPROCESS_OUTPUT].decode("utf-8", errors="replace")
    stderr = completed.stderr[:MAX_SUBPROCESS_OUTPUT].decode("utf-8", errors="replace")
    return completed.returncode, stdout, stderr


def normalize_mac(value: str) -> str:
    return value.strip().upper().replace("-", ":")


def extract_macs(text: str) -> List[str]:
    return sorted(set(normalize_mac(match.group(0)) for match in MAC_RE.finditer(text)))


def scan_wifi(store: EvidenceStore) -> Tuple[List[str], Dict[str, Any]]:
    """Collect BSSIDs using native utilities only, never monitor mode or drivers."""
    system = platform.system()
    if system == "Windows":
        command = ["netsh", "wlan", "show", "networks", "mode=bssid"]
    elif system == "Darwin":
        command = ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"]
    elif system == "Linux":
        # --rescan no avoids explicitly requesting a radio scan through NetworkManager.
        command = ["nmcli", "--terse", "--escape", "no", "--fields", "BSSID", "device", "wifi", "list", "--rescan", "no"]
    else:
        return [], {"method": "unsupported-platform", "platform": system, "return_code": None}
    code, output, error = run_command(command, store.root)
    return extract_macs(output), {
        "method": "native:%s" % command[0],
        "platform": system,
        "return_code": code,
        "error": error[:512] if code else None,
    }


async def _ble_discover(seconds: float) -> List[Any]:
    from bleak import BleakScanner
    return await BleakScanner.discover(timeout=seconds)


def _device_address(device: Any) -> Optional[str]:
    address = getattr(device, "address", None)
    if not address:
        return None
    address = str(address).strip()
    # CoreBluetooth does not reveal real MAC addresses. Its UUIDs can still be
    # stable inside a scan, but are excluded to avoid mislabelling them as MACs.
    if not MAC_RE.fullmatch(address):
        return None
    return normalize_mac(address)


def scan_ble(seconds: float) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Perform two scans and retain MACs observed in both, filtering transient IDs."""
    if seconds <= 0:
        return [], {"method": "disabled", "scan_count": 0}
    try:
        import asyncio
        try:
            first = asyncio.run(_ble_discover(seconds))
            second = asyncio.run(_ble_discover(seconds))
        except RuntimeError:
            # A hostile embedding event loop should not break the CLI. It is
            # safer to report BLE unavailable than to hijack its event loop.
            return [], {"method": "bleak", "error": "active event loop prevents isolated BLE scan", "scan_count": 0}
    except ImportError:
        return [], {"method": "bleak", "error": "bleak is not bundled", "scan_count": 0}
    except Exception as exc:  # Hardware permissions/adapter errors vary by OS.
        return [], {"method": "bleak", "error": "%s: %s" % (type(exc).__name__, exc), "scan_count": 0}

    def index(devices: Iterable[Any]) -> Dict[str, Any]:
        result = {}
        for device in devices:
            addr = _device_address(device)
            if addr:
                result[addr] = device
        return result

    left, right = index(first), index(second)
    stable = []
    for address in sorted(set(left).intersection(right)):
        rssi = getattr(right[address], "rssi", None)
        record: Dict[str, Any] = {"address": address}
        if isinstance(rssi, (int, float)):
            record["rssi"] = int(rssi)
        stable.append(record)
    return stable, {"method": "bleak:two-pass", "scan_count": 2, "seconds_per_scan": seconds, "stable_count": len(stable)}


def scan_arp() -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    """Capture physical MAC addresses of wired/local network neighbors."""
    records = []
    try:
        out = subprocess.check_output(["arp", "-a"], stderr=subprocess.STDOUT, timeout=5).decode("utf-8", "ignore")
        mac_pattern = re.compile(r'([0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2})')
        seen = set()
        for line in out.splitlines():
            match = mac_pattern.search(line)
            if match:
                mac = match.group(1).replace('-', ':').upper()
                mac = ':'.join([p.zfill(2) for p in mac.split(':')])
                if mac not in seen and mac != "FF:FF:FF:FF:FF:FF":
                    seen.add(mac)
                    records.append({"mac": mac})
        return records, {"method": "arp -a", "error": None}
    except Exception as exc:
        return records, {"method": "arp -a", "error": str(exc)}


def scan_monitors() -> Tuple[List[Dict[str, Optional[str]]], Dict[str, Any]]:
    """Capture EDID serials and names of physically connected displays."""
    sys_name = platform.system()
    monitors = []
    meta = {"method": "unknown", "error": None}
    
    if sys_name == "Windows":
        meta["method"] = "wmi:WmiMonitorID"
        try:
            cmd = [
                "powershell", "-NoProfile", "-Command",
                r"Get-WmiObject WmiMonitorID -Namespace root\wmi -ErrorAction Stop | ForEach-Object { "
                r"$man = [System.Text.Encoding]::ASCII.GetString($_.ManufacturerName) -replace '\0', ''; "
                r"$ser = [System.Text.Encoding]::ASCII.GetString($_.SerialNumberID) -replace '\0', ''; "
                r"$name = [System.Text.Encoding]::ASCII.GetString($_.UserFriendlyName) -replace '\0', ''; "
                r"[PSCustomObject]@{ Manufacturer = $man; Serial = $ser; Name = $name } } | ConvertTo-Json -Compress"
            ]
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=10).decode("utf-8", "ignore").strip()
            if out:
                parsed = json.loads(out)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                for item in parsed:
                    monitors.append({
                        "manufacturer": item.get("Manufacturer", "").strip() or None,
                        "serial": item.get("Serial", "").strip() or None,
                        "name": item.get("Name", "").strip() or None
                    })
        except Exception as exc:
            meta["error"] = str(exc)
            
    elif sys_name == "Linux":
        meta["method"] = "sysfs:drm/edid"
        try:
            drm_path = "/sys/class/drm"
            if os.path.exists(drm_path):
                for card in os.listdir(drm_path):
                    status_path = os.path.join(drm_path, card, "status")
                    edid_path = os.path.join(drm_path, card, "edid")
                    if os.path.exists(status_path) and os.path.exists(edid_path):
                        with open(status_path, "r") as f:
                            if "connected" in f.read():
                                with open(edid_path, "rb") as f2:
                                    edid = f2.read()
                                    if len(edid) >= 128:
                                        serial = None
                                        name = None
                                        for offset in (54, 72, 90, 108):
                                            if edid[offset:offset+3] == b'\x00\x00\x00':
                                                tag = edid[offset+3]
                                                text = edid[offset+5:offset+18].split(b'\n')[0].strip().decode('ascii', 'ignore')
                                                if tag == 0xFF:
                                                    serial = text
                                                elif tag == 0xFC:
                                                    name = text
                                        mfg = None
                                        if len(edid) >= 10:
                                            raw_mfg = (edid[8] << 8) | edid[9]
                                            c1 = chr(((raw_mfg >> 10) & 0x1F) + 64)
                                            c2 = chr(((raw_mfg >> 5) & 0x1F) + 64)
                                            c3 = chr((raw_mfg & 0x1F) + 64)
                                            mfg = c1 + c2 + c3
                                        monitors.append({"manufacturer": mfg, "serial": serial, "name": name, "interface": card})
        except Exception as exc:
            meta["error"] = str(exc)

    elif sys_name == "Darwin":
        meta["method"] = "system_profiler:displays"
        try:
            out = subprocess.check_output(["system_profiler", "SPDisplaysDataType", "-json"], stderr=subprocess.STDOUT, timeout=10).decode("utf-8", "ignore")
            parsed = json.loads(out)
            displays = parsed.get("SPDisplaysDataType", [])
            for gpu in displays:
                for monitor in gpu.get("spdisplays_ndrvs", []):
                    monitors.append({
                        "name": monitor.get("_name", ""),
                        "resolution": monitor.get("_spdisplays_resolution", ""),
                    })
        except Exception as exc:
            meta["error"] = str(exc)
            
    return monitors, meta


def capture_audio_digest(seconds: float) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """Record an in-memory mono sample and immediately discard it after hashing."""
    if seconds <= 0:
        return None, {"method": "disabled"}
    try:
        import numpy as np
        import sounddevice as sd
    except ImportError:
        return None, {"method": "sounddevice", "error": "sounddevice/numpy is not bundled"}
    try:
        samplerate = 16000
        frames = int(seconds * samplerate)
        recording = sd.rec(frames, samplerate=samplerate, channels=1, dtype="int16", blocking=True)
        # Force a deterministic little-endian byte stream across host architectures.
        samples = np.asarray(recording, dtype="<i2").tobytes(order="C")
        result = {
            "sha256": sha256_hex(samples),
            "seconds": seconds,
            "sample_rate_hz": samplerate,
            "channels": 1,
            "sample_format": "pcm_s16le",
            "byte_count": len(samples),
        }
        return result, {"method": "sounddevice:in-memory", "error": None}
    except Exception as exc:
        return None, {"method": "sounddevice", "error": "%s: %s" % (type(exc).__name__, exc)}


def build_payload(capture_id: str, wifi: List[str], ble: List[Dict[str, Any]], arp: List[Dict[str, str]], monitors: List[Dict[str, Optional[str]]], audio: Optional[Dict[str, Any]], acquisition: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema": SCHEMA,
        "capture_id": capture_id,
        "captured_at_utc": utc_now(),
        "platform": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "sources": {
            "wifi_bssids": sorted(set(wifi)),
            "ble_beacons": sorted(ble, key=lambda item: item["address"]),
            "arp_neighbors": sorted(arp, key=lambda item: item["mac"]),
            "monitors": monitors,
            "audio_fingerprint": audio,
        },
        "acquisition": acquisition,
    }


def compressed_evidence(payload: Dict[str, Any]) -> Tuple[bytes, bytes, str]:
    raw = canonical_json(payload)
    compressed = zlib.compress(raw, level=9)
    return raw, compressed, sha256_hex(compressed)


def merkle_root(leaves: Sequence[str]) -> str:
    """Hex SHA-256 binary Merkle root, duplicating odd leaves at each level."""
    if not leaves:
        raise DigitalAlibiError("Cannot calculate a Merkle root with no leaves")
    try:
        level = [bytes.fromhex(leaf) for leaf in sorted(leaves)]
    except ValueError as exc:
        raise DigitalAlibiError("Invalid SHA-256 leaf: %s" % exc)
    if any(len(node) != 32 for node in level):
        raise DigitalAlibiError("Merkle leaves must be SHA-256 digests")
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


# Minimal DER encoder for RFC 3161 TimeStampReq. The code never interprets an
# untrusted token cryptographically; independent verification is performed by
# Autopsy/OpenSSL with the TSA trust chain.
def der_length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + der_length(len(content)) + content


def der_integer(number: int) -> bytes:
    if number < 0:
        raise ValueError("negative DER integers are not needed")
    raw = number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return der(0x02, raw)


def der_oid(oid: str) -> bytes:
    parts = [int(part) for part in oid.split(".")]
    if len(parts) < 2 or parts[0] > 2 or parts[1] < 0:
        raise ValueError("invalid OID")
    values = [40 * parts[0] + parts[1]] + parts[2:]
    encoded = bytearray()
    for value in values:
        if value < 0:
            raise ValueError("invalid OID component")
        chunks = [value & 0x7F]
        value >>= 7
        while value:
            chunks.append(0x80 | (value & 0x7F))
            value >>= 7
        encoded.extend(reversed(chunks))
    return der(0x06, bytes(encoded))


def build_timestamp_request(digest_hex: str, nonce: Optional[int] = None) -> bytes:
    digest = bytes.fromhex(digest_hex)
    if len(digest) != 32:
        raise DigitalAlibiError("RFC 3161 SHA-256 imprint must be 32 bytes")
    algorithm = der(0x30, der_oid("2.16.840.1.101.3.4.2.1") + der(0x05, b""))
    imprint = der(0x30, algorithm + der(0x04, digest))
    content = der_integer(1) + imprint
    # A unique nonce makes it possible for a full verifier to bind a reply to
    # this request. The nonce is not needed to derive the stored evidence hash.
    content += der_integer(nonce if nonce is not None else secrets.randbits(128))
    content += der(0x01, b"\xff")  # certReq = TRUE
    return der(0x30, content)


def _read_der_element(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated DER")
    tag = data[offset]
    first_len = data[offset + 1]
    pos = offset + 2
    if first_len & 0x80:
        count = first_len & 0x7F
        if not count or count > 4 or pos + count > len(data):
            raise ValueError("invalid DER length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    else:
        length = first_len
    end = pos + length
    if end > len(data):
        raise ValueError("truncated DER payload")
    return tag, data[pos:end], end


def timestamp_response_status(response: bytes) -> int:
    """Check that a response is DER TimeStampResp with a granted status."""
    outer_tag, outer, end = _read_der_element(response)
    if outer_tag != 0x30 or end != len(response):
        raise DigitalAlibiError("TSA response is not a complete DER SEQUENCE")
    status_tag, status_info, _ = _read_der_element(outer)
    if status_tag != 0x30:
        raise DigitalAlibiError("TSA response has no PKIStatusInfo")
    integer_tag, encoded_status, _ = _read_der_element(status_info)
    if integer_tag != 0x02 or not encoded_status:
        raise DigitalAlibiError("TSA response has invalid PKIStatus")
    status = int.from_bytes(encoded_status, "big", signed=False)
    if status not in (0, 1):
        raise DigitalAlibiError("TSA rejected timestamp request (PKIStatus %d)" % status)
    # Status 0/1 must include a TimeStampToken under RFC 3161.
    _, _, cursor = _read_der_element(outer)
    if cursor >= len(outer):
        raise DigitalAlibiError("TSA granted request but supplied no timestamp token")
    token_tag, _, _ = _read_der_element(outer, cursor)
    if token_tag != 0x30:
        raise DigitalAlibiError("TSA timestamp token is not CMS ContentInfo")
    return status


def obtain_timestamp(tsa_url: str, digest_hex: str, timeout: int = 20) -> bytes:
    parsed = urlparse(tsa_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise DigitalAlibiError("TSA URL must be an HTTPS URL")
    query = build_timestamp_request(digest_hex)
    request = Request(
        tsa_url,
        data=query,
        headers={
            "Content-Type": "application/timestamp-query",
            "Accept": "application/timestamp-reply",
            "User-Agent": "Digital-Alibi/%s" % __version__,
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_SUBPROCESS_OUTPUT + 1)
            content_type = response.headers.get("Content-Type", "").lower()
    except HTTPError as exc:
        raise DigitalAlibiError("TSA HTTP error %s" % exc.code)
    except URLError as exc:
        raise DigitalAlibiError("TSA connection error: %s" % exc.reason)
    except OSError as exc:
        raise DigitalAlibiError("TSA transport error: %s" % exc)
    if len(raw) > MAX_SUBPROCESS_OUTPUT:
        raise DigitalAlibiError("TSA response exceeded safe size limit")
    if "application/timestamp-reply" not in content_type and "application/timestamp-response" not in content_type:
        raise DigitalAlibiError("TSA returned unexpected content type: %s" % (content_type or "none"))
    timestamp_response_status(raw)
    return raw


def insert_capture(conn: sqlite3.Connection, payload: Dict[str, Any], compressed: bytes, digest: str, tsa_url: str, summary: Dict[str, Any]) -> None:
    conn.execute(
        """INSERT INTO captures(
            capture_id,captured_at_utc,payload_json,compressed_payload_b64,compressed_sha256,compressed_size,
            source_summary_json,tsa_status,tsa_url,tsa_message_imprint,created_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?)""",
        (
            payload["capture_id"],
            payload["captured_at_utc"],
            canonical_json(payload).decode("utf-8"),
            base64.b64encode(compressed).decode("ascii"),
            digest,
            len(compressed),
            canonical_json(summary).decode("utf-8"),
            tsa_url,
            digest,
            utc_now(),
        ),
    )
    EvidenceStore.audit(conn, "capture_created", {"compressed_sha256": digest, "compressed_size": len(compressed)}, payload["capture_id"])
    conn.commit()


def locally_seal_pending(conn: sqlite3.Connection, signer: LocalSigner) -> Optional[str]:
    rows = conn.execute("SELECT capture_id, compressed_sha256 FROM captures WHERE tsa_status = 'PENDING' ORDER BY capture_id").fetchall()
    if not rows:
        return None
    leaves = [row["compressed_sha256"] for row in rows]
    root = merkle_root(leaves)
    batch_id = "batch-" + uuid.uuid4().hex
    created = utc_now()
    envelope = {
        "purpose": "digital-alibi.merkle-root/v1",
        "batch_id": batch_id,
        "created_at_utc": created,
        "leaf_count": len(leaves),
        "merkle_root": root,
    }
    signature = signer.sign(canonical_json(envelope))
    public_der = signer.public_der()
    conn.execute(
        """INSERT INTO merkle_batches(
             batch_id,created_at_utc,leaf_count,merkle_root,leaf_hashes_json,
             signature_b64,public_key_b64,key_fingerprint,status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'LOCAL_SEALED')""",
        (batch_id, created, len(leaves), root, canonical_json(sorted(leaves)).decode("utf-8"), signature, base64.b64encode(public_der).decode("ascii"), signer.fingerprint()),
    )
    for row in rows:
        conn.execute(
            """UPDATE captures SET tsa_status='LOCAL_SEALED', local_signature_b64=?, local_key_fingerprint=?,
               merkle_batch_id=?, sealed_at_utc=? WHERE capture_id=?""",
            (signature, signer.fingerprint(), batch_id, created, row["capture_id"]),
        )
        EvidenceStore.audit(conn, "local_merkle_sealed", {"batch_id": batch_id, "merkle_root": root}, row["capture_id"])
    conn.commit()
    return batch_id


def write_tsr_and_mark(conn: sqlite3.Connection, store: EvidenceStore, row: sqlite3.Row, token: bytes) -> None:
    destination = store.tsr_path(row["capture_id"])
    # Atomic replacement entirely inside the USB directory. No tempfile module,
    # because its system default can violate the zero-footprint requirement.
    temporary = store.path(TSR_DIR_NAME, ".%s.tsr.new" % safe_filename(row["capture_id"]))
    temporary.write_bytes(token)
    os.replace(str(temporary), str(destination))
    conn.execute(
        """UPDATE captures SET tsa_status='TSA_SEALED', tsr_path=?, tsa_error=NULL,
           sealed_at_utc=? WHERE capture_id=?""",
        (str(destination.relative_to(store.root)), utc_now(), row["capture_id"]),
    )
    EvidenceStore.audit(conn, "tsa_sealed", {"tsr_path": str(destination.relative_to(store.root))}, row["capture_id"])
    conn.commit()


def submit_pending_timestamps(conn: sqlite3.Connection, store: EvidenceStore, tsa_url: str, limit: Optional[int] = None) -> Dict[str, int]:
    query = "SELECT * FROM captures WHERE tsa_status IN ('PENDING','LOCAL_SEALED') ORDER BY created_at_utc"
    if limit:
        query += " LIMIT %d" % int(limit)
    rows = conn.execute(query).fetchall()
    result = {"submitted": 0, "sealed": 0, "failed": 0}
    for row in rows:
        result["submitted"] += 1
        # An explicitly supplied flush/watch URL overrides the endpoint stored
        # at collection. Without an override, retain the original endpoint so
        # the queue has a reproducible acquisition-time configuration.
        url = tsa_url or row["tsa_url"] or DEFAULT_TSA_URL
        try:
            token = obtain_timestamp(url, row["tsa_message_imprint"])
            write_tsr_and_mark(conn, store, row, token)
            result["sealed"] += 1
        except DigitalAlibiError as exc:
            conn.execute("UPDATE captures SET tsa_error=? WHERE capture_id=?", (str(exc)[:1000], row["capture_id"]))
            EvidenceStore.audit(conn, "tsa_submission_failed", {"error": str(exc)[:1000]}, row["capture_id"])
            conn.commit()
            result["failed"] += 1
    return result


def do_capture(args: argparse.Namespace, store: EvidenceStore) -> int:
    conn = store.connect()
    try:
        # Network reconnection is checked before acquiring new material, so a
        # queue persists in a verifiable local state while offline.
        if not args.no_tsa:
            previous = submit_pending_timestamps(conn, store, args.tsa_url)
            if previous["sealed"] or previous["failed"]:
                print("Pending TSA submissions: %(sealed)d sealed, %(failed)d deferred" % previous)
        wifi, wifi_meta = scan_wifi(store)
        ble, ble_meta = scan_ble(args.ble_seconds)
        arp, arp_meta = scan_arp()
        monitors, monitors_meta = scan_monitors()
        
        audio = None
        audio_meta: Dict[str, Any] = {"method": "not-needed"}
        if not wifi and not ble and not arp and not monitors:
            audio, audio_meta = capture_audio_digest(args.audio_seconds)
            
        acquisition = {
            "wifi": wifi_meta, 
            "ble": ble_meta, 
            "arp": arp_meta,
            "monitors": monitors_meta,
            "audio": audio_meta, 
            "operator_note": args.note or None
        }
        capture_id = args.capture_id or ("capture-" + uuid.uuid4().hex)
        payload = build_payload(capture_id, wifi, ble, arp, monitors, audio, acquisition)
        _, compressed, digest = compressed_evidence(payload)
        summary = {
            "wifi_bssid_count": len(wifi), 
            "ble_stable_count": len(ble), 
            "arp_mac_count": len(arp),
            "monitor_count": len(monitors),
            "audio_fallback": audio is not None
        }
        insert_capture(conn, payload, compressed, digest, args.tsa_url, summary)
        if args.no_tsa:
            signer = LocalSigner(store)
            batch_id = locally_seal_pending(conn, signer)
            status = "LOCAL_SEALED"
            detail = "offline batch %s" % batch_id
        else:
            result = submit_pending_timestamps(conn, store, args.tsa_url)
            current = conn.execute("SELECT tsa_status FROM captures WHERE capture_id=?", (capture_id,)).fetchone()
            status = current["tsa_status"]
            if status != "TSA_SEALED":
                signer = LocalSigner(store)
                batch_id = locally_seal_pending(conn, signer)
                status = "LOCAL_SEALED"
                detail = "TSA deferred, offline batch %s" % batch_id
            else:
                detail = "RFC 3161 token written"
        print(json.dumps({"capture_id": capture_id, "sha256": digest, "status": status, "detail": detail, "output_dir": str(store.root)}, sort_keys=True))
        return 0
    finally:
        conn.close()


def do_flush(args: argparse.Namespace, store: EvidenceStore) -> int:
    conn = store.connect()
    try:
        result = submit_pending_timestamps(conn, store, args.tsa_url)
        if result["failed"]:
            signer = LocalSigner(store)
            locally_seal_pending(conn, signer)
        print(json.dumps(result, sort_keys=True))
        return 0 if not result["failed"] else 2
    finally:
        conn.close()


def do_watch(args: argparse.Namespace, store: EvidenceStore) -> int:
    """Keep a USB-launched process alive to submit evidence after reconnection.

    This intentionally is not installed as a host service or scheduler. The
    investigator must keep the USB process running, which preserves the
    zero-footprint model while still allowing automatic retry on reconnection.
    """
    conn = store.connect()
    try:
        print("Watching pending Digital Alibi evidence every %d seconds. Press Ctrl-C to stop." % args.interval)
        while True:
            result = submit_pending_timestamps(conn, store, args.tsa_url)
            if result["failed"]:
                signer = LocalSigner(store)
                locally_seal_pending(conn, signer)
            print(json.dumps({"checked_at_utc": utc_now(), **result}, sort_keys=True))
            time.sleep(args.interval)
    finally:
        conn.close()


def verify_capture_row(row: sqlite3.Row) -> Tuple[bool, str]:
    try:
        payload = json.loads(row["payload_json"])
        if payload.get("schema") != SCHEMA:
            return False, "unsupported schema"
        encoded_compressed = row["compressed_payload_b64"]
        if not encoded_compressed:
            return False, "missing exact compressed evidence bytes"
        compressed = base64.b64decode(encoded_compressed, validate=True)
        actual = sha256_hex(compressed)
        if actual != row["compressed_sha256"]:
            return False, "compressed SHA-256 mismatch"
        if len(compressed) != row["compressed_size"]:
            return False, "compressed size mismatch"
        if zlib.decompress(compressed) != canonical_json(payload):
            return False, "compressed payload does not decode to canonical evidence"
        return True, "hash verified"
    except (ValueError, TypeError, KeyError, zlib.error) as exc:
        return False, "invalid payload: %s" % exc


def do_verify(args: argparse.Namespace, store: EvidenceStore) -> int:
    conn = store.connect()
    try:
        where, values = ("", [])
        if args.capture_id:
            where, values = (" WHERE capture_id=?", [args.capture_id])
        rows = conn.execute("SELECT * FROM captures" + where + " ORDER BY created_at_utc", values).fetchall()
        if not rows:
            print("No matching captures found", file=sys.stderr)
            return 1
        failures = 0
        report = []
        for row in rows:
            valid, reason = verify_capture_row(row)
            tsr_present = bool(row["tsr_path"] and store.path(*Path(row["tsr_path"]).parts).is_file())
            report.append({"capture_id": row["capture_id"], "hash_valid": valid, "reason": reason, "tsa_status": row["tsa_status"], "tsr_present": tsr_present})
            if not valid or (row["tsa_status"] == "TSA_SEALED" and not tsr_present):
                failures += 1
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if failures == 0 else 3
    finally:
        conn.close()


def do_status(store: EvidenceStore) -> int:
    conn = store.connect()
    try:
        counts = {row["tsa_status"]: row["count"] for row in conn.execute("SELECT tsa_status, COUNT(*) AS count FROM captures GROUP BY tsa_status")}
        print(json.dumps({"database": str(store.database_path), "captures": counts, "root": str(store.root)}, sort_keys=True))
        return 0
    finally:
        conn.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Digital Alibi portable environmental evidence capture")
    parser.add_argument("--version", action="version", version="Digital Alibi %s" % __version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture = subparsers.add_parser("capture", help="Acquire identifiers, hash them, and timestamp or locally seal them")
    capture.add_argument("--tsa-url", default=DEFAULT_TSA_URL, help="HTTPS RFC 3161 endpoint (default: %(default)s)")
    capture.add_argument("--no-tsa", action="store_true", help="Do not contact a TSA, seal immediately with USB-local Ed25519 key")
    capture.add_argument("--ble-seconds", type=float, default=3.0, help="Seconds per each of two BLE scans (default: %(default)s)")
    capture.add_argument("--audio-seconds", type=float, default=10.0, help="In-memory audio fallback duration if no radios (default: %(default)s)")
    capture.add_argument("--capture-id", help="Optional unique evidence ID. Default is random UUID.")
    capture.add_argument("--note", help="Optional operator note, included in the signed evidence payload")

    flush = subparsers.add_parser("flush", help="Submit locally sealed and pending evidence to the TSA")
    flush.add_argument("--tsa-url", default=None, help="Optional HTTPS RFC 3161 endpoint override for queued records")
    flush.add_argument("--limit", type=int, default=None, help="Maximum pending captures to submit")

    verify = subparsers.add_parser("verify", help="Recalculate locally stored compressed evidence hashes")
    verify.add_argument("--capture-id", help="Verify only one capture ID")
    watch = subparsers.add_parser("watch", help="Retry pending TSA submissions while this USB-launched process remains running")
    watch.add_argument("--tsa-url", default=None, help="Optional HTTPS RFC 3161 endpoint override for queued records")
    watch.add_argument("--interval", type=int, default=60, help="Seconds between reconnection checks (default: %(default)s)")
    subparsers.add_parser("status", help="Show capture state from the USB database")
    return parser


def validate_args(args: argparse.Namespace) -> None:
    if getattr(args, "ble_seconds", 0) < 0 or getattr(args, "audio_seconds", 0) < 0:
        raise DigitalAlibiError("Scan durations must not be negative")
    if getattr(args, "limit", None) is not None and args.limit <= 0:
        raise DigitalAlibiError("--limit must be positive")
    if getattr(args, "interval", None) is not None and args.interval <= 0:
        raise DigitalAlibiError("--interval must be positive")
    if getattr(args, "tsa_url", None) is not None:
        parsed = urlparse(args.tsa_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise DigitalAlibiError("--tsa-url must be a complete HTTPS URL")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        validate_args(args)
        store = EvidenceStore()
        if args.command == "capture":
            return do_capture(args, store)
        if args.command == "flush":
            return do_flush(args, store)
        if args.command == "watch":
            return do_watch(args, store)
        if args.command == "verify":
            return do_verify(args, store)
        if args.command == "status":
            return do_status(store)
        raise DigitalAlibiError("Unknown command")
    except DigitalAlibiError as exc:
        print("Digital Alibi error: %s" % exc, file=sys.stderr)
        return 2
    except sqlite3.Error as exc:
        print("Digital Alibi database error: %s" % exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print("Digital Alibi file or device error: %s" % exc, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Digital Alibi interrupted. Existing committed records remain on the acquisition USB.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import mimetypes
import os
import sys
import time
import uuid
import zlib
from dataclasses import dataclass
from decimal import Decimal, getcontext
from pathlib import Path
from typing import Iterable, Iterator, Sequence

try:
    import qrcode
    import requests
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from eth_account import Account
    from web3 import Web3
except ImportError as exc:
    raise SystemExit(
        "Dipendenze mancanti. Installa con:\n"
        "  python -m pip install web3 eth-account requests cryptography coincurve qrcode"
    ) from exc


NETWORK_NAME = "Sepolia ETH Testnet"
CHAIN_ID = 11155111
DEFAULT_RPC_URLS = [
    "https://ethereum-sepolia-rpc.publicnode.com",
]

SCRIPT_DIR = Path(__file__).resolve().parent
KEY_FILE = SCRIPT_DIR / "wallet_sepolia.key.txt"
STATE_FILE = SCRIPT_DIR / "sfs_root.txt"

MAGIC_V1 = b"SFS1"
MAGIC_V2 = b"SFS2"
MAGIC = b"SFS3"
PAYLOAD_VERSION = 3
TYPE_MANIFEST = 1
TYPE_CHUNK = 2
TYPE_CATALOG_ENTRY = 3

AUTO_CHUNK_MIN = 1024
AUTO_CHUNK_DEFAULT = 2048
AUTO_CHUNK_LARGE = 4096
AUTO_CHUNK_MAX = 8192
CHUNK_SIZE_ROUND = 256
REQUEST_TIMEOUT_SECONDS = 20
MAX_RETRIES_PER_TX = 3
MAX_TOTAL_TRANSACTIONS = 5000
MIN_FUNDING_BUFFER_WEI = 10**14  # 0.0001 ETH
FUNDING_BUFFER_PCT = 15
DATA_TX_GAS_BUFFER = 5000
SWEEP_GAS_LIMIT = 21000
DEFAULT_PARALLELISM = 2
MAX_PARALLELISM = 4
TX_WAIT_TIMEOUT_SECONDS = 180
DEFAULT_CATALOG_PAGE_SIZE = 20
MAX_INTERACTIVE_SCAN = 100000

getcontext().prec = 50


class StoreError(Exception):
    pass


@dataclass
class PreparedUpload:
    file_path: Path
    file_id: str
    file_name: str
    mime_type: str
    original_size: int
    original_sha256: str
    compressed: bool
    stored_size: int
    stored_sha256: str
    chunk_size: int
    total_chunks: int
    nonce_prefix: bytes
    wrapped_master_key: bytes
    manifest: dict
    manifest_payload: bytes
    chunk_payloads: list[bytes]


@dataclass
class LocalState:
    root_catalog_tx_hash: str | None = None
    pending_file: str | None = None
    pending_manifest_tx_hash: str | None = None
    pending_catalog_tx_hash: str | None = None


@dataclass
class CatalogEntry:
    index: int
    catalog_tx_hash: str
    manifest_tx_hash: str
    prev_catalog_tx_hash: str | None
    file_name: str
    mime_type: str
    original_size: int
    original_sha256: str
    created_at: int
    file_id: str


# --------------------
# Utility generiche
# --------------------

def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + ("=" * (-len(text) % 4)))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unique_preserve_order(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        value = value.strip()
        if value and value not in seen:
            out.append(value)
            seen.add(value)
    return out


def format_eth(wei: int) -> str:
    eth_value = Decimal(int(wei)) / Decimal(10**18)
    text = f"{eth_value:.18f}".rstrip("0").rstrip(".")
    return text or "0"


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def short_hash(value: str, size: int = 10) -> str:
    value = value.strip()
    if len(value) <= size + 4:
        return value
    return f"{value[:size]}…{value[-4:]}"


def format_size(num: int) -> str:
    value = float(num)
    for unit in ["B", "KB", "MB", "GB"]:
        if value < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{num} B"


# --------------------
# Stato locale minimo
# --------------------

def read_local_state() -> LocalState:
    if not STATE_FILE.is_file():
        return LocalState()

    state = LocalState()
    for raw_line in STATE_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if key == "ROOT":
            state.root_catalog_tx_hash = value or None
        elif key == "PENDING_FILE":
            state.pending_file = value or None
        elif key == "PENDING_MANIFEST":
            state.pending_manifest_tx_hash = value or None
        elif key == "PENDING_CATALOG":
            state.pending_catalog_tx_hash = value or None
    return state


def write_local_state(state: LocalState) -> None:
    lines: list[str] = []
    if state.root_catalog_tx_hash:
        lines.append(f"ROOT={state.root_catalog_tx_hash}")
    if state.pending_file:
        lines.append(f"PENDING_FILE={state.pending_file}")
    if state.pending_manifest_tx_hash:
        lines.append(f"PENDING_MANIFEST={state.pending_manifest_tx_hash}")
    if state.pending_catalog_tx_hash:
        lines.append(f"PENDING_CATALOG={state.pending_catalog_tx_hash}")

    if not lines:
        STATE_FILE.unlink(missing_ok=True)
        return

    atomic_write_text(STATE_FILE, "\n".join(lines) + "\n")


def update_state_pending(file_path: Path, manifest_tx_hash: str) -> LocalState:
    state = read_local_state()
    state.pending_file = str(file_path.resolve())
    state.pending_manifest_tx_hash = normalize_hex_hash(manifest_tx_hash)
    state.pending_catalog_tx_hash = None
    write_local_state(state)
    return state


def update_state_pending_catalog(catalog_tx_hash: str) -> LocalState:
    state = read_local_state()
    state.pending_catalog_tx_hash = normalize_hex_hash(catalog_tx_hash)
    write_local_state(state)
    return state


def commit_root_catalog(catalog_tx_hash: str) -> LocalState:
    state = read_local_state()
    state.root_catalog_tx_hash = normalize_hex_hash(catalog_tx_hash)
    state.pending_file = None
    state.pending_manifest_tx_hash = None
    state.pending_catalog_tx_hash = None
    write_local_state(state)
    return state


def clear_pending_state() -> LocalState:
    state = read_local_state()
    state.pending_file = None
    state.pending_manifest_tx_hash = None
    state.pending_catalog_tx_hash = None
    write_local_state(state)
    return state


# --------------------
# HTTP / RPC
# --------------------

def build_http_session() -> requests.Session:
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    retry = Retry(
        total=3,
        connect=3,
        read=3,
        status=3,
        status_forcelist=(429, 500, 502, 503, 504),
        backoff_factor=0.5,
        allowed_methods=None,
        raise_on_status=False,
    )

    adapter = HTTPAdapter(max_retries=retry, pool_connections=8, pool_maxsize=8)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": "sepolia-file-store/5.0"})
    return session


def get_rpc_urls() -> list[str]:
    urls: list[str] = []
    env_one = os.getenv("SEPOLIA_RPC_URL", "").strip()
    env_many = os.getenv("SEPOLIA_RPC_URLS", "").strip()
    if env_one:
        urls.append(env_one)
    if env_many:
        urls.extend(part.strip() for part in env_many.split(",") if part.strip())
    urls.extend(DEFAULT_RPC_URLS)
    return unique_preserve_order(urls)


def connect_web3() -> tuple[Web3, str]:
    errors: list[str] = []
    for rpc_url in get_rpc_urls():
        try:
            provider = Web3.HTTPProvider(
                rpc_url,
                request_kwargs={"timeout": REQUEST_TIMEOUT_SECONDS},
                session=build_http_session(),
            )
            w3 = Web3(provider)
            if not w3.is_connected():
                raise StoreError("provider non connesso")
            chain_id = int(w3.eth.chain_id)
            if chain_id != CHAIN_ID:
                raise StoreError(f"chain id errato: {chain_id}")
            _ = w3.eth.block_number
            return w3, rpc_url
        except Exception as exc:
            errors.append(f"- {rpc_url}: {exc}")
    raise SystemExit("Impossibile connettersi a Sepolia.\n" + "\n".join(errors))


# --------------------
# Wallet
# --------------------

def load_or_create_wallet() -> tuple[object, bytes]:

    if KEY_FILE.exists():
        key_hex = KEY_FILE.read_text(encoding="utf-8").strip()
        if key_hex.startswith("0x"):
            key_hex = key_hex[2:]
        try:
            private_key = bytes.fromhex(key_hex)
        except ValueError as exc:
            raise SystemExit(f"Private key non valida in {KEY_FILE}") from exc
        account = Account.from_key(private_key)
    else:
        account = Account.create()
        private_key = bytes(account.key)
        atomic_write_text(KEY_FILE, private_key.hex())
        print(f"[OK] Nuovo wallet creato: {KEY_FILE}")

    return account, private_key


def _coincurve_private_key(secret: bytes):
    try:
        from coincurve import PrivateKey
    except ImportError as exc:
        raise SystemExit(
            "Dipendenza mancante: coincurve\n"
            "Installa con:\n"
            "  python -m pip install coincurve"
        ) from exc
    return PrivateKey(secret)


def _coincurve_public_key(raw_public_key: bytes):
    try:
        from coincurve import PublicKey
    except ImportError as exc:
        raise SystemExit(
            "Dipendenza mancante: coincurve\n"
            "Installa con:\n"
            "  python -m pip install coincurve"
        ) from exc
    return PublicKey(raw_public_key)


def derive_public_key_hex(private_key: bytes) -> str:
    return _coincurve_private_key(private_key).public_key.format(compressed=False).hex()


# --------------------
# Crypto / chunking
# --------------------

def _hkdf_32(secret: bytes, salt: bytes, info: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return hkdf.derive(secret)


def derive_chunk_key(master_key: bytes, file_id_bytes: bytes) -> bytes:
    return _hkdf_32(master_key, salt=file_id_bytes, info=b"SFS-CHUNK-KEY-v1")


def seal_with_public_key(public_key_hex: str, plaintext: bytes) -> bytes:
    recipient_public_key = _coincurve_public_key(bytes.fromhex(public_key_hex.removeprefix("0x")))
    ephemeral_private_key = _coincurve_private_key(os.urandom(32))
    shared_secret = ephemeral_private_key.ecdh(recipient_public_key.format(compressed=True))
    nonce = os.urandom(12)
    kek = _hkdf_32(shared_secret, salt=nonce, info=b"SFS-ECIES-v2")
    ciphertext = AESGCM(kek).encrypt(nonce, plaintext, b"SFS-WRAP-MASTER-KEY")
    return b"\x02" + ephemeral_private_key.public_key.format(compressed=True) + nonce + ciphertext


def open_with_private_key(private_key: bytes, payload: bytes) -> bytes:
    if len(payload) < 46:
        raise StoreError("wrapped key non valida")

    prefix = payload[0]
    ephemeral_public_key = payload[1:34]
    nonce = payload[34:46]
    ciphertext = payload[46:]

    if prefix == 1:
        info = b"SFS-ECIES-v1"
        aad = b"SFS-DEK"
    elif prefix == 2:
        info = b"SFS-ECIES-v2"
        aad = b"SFS-WRAP-MASTER-KEY"
    else:
        raise StoreError("wrapped key con versione non supportata")

    try:
        shared_secret = _coincurve_private_key(private_key).ecdh(ephemeral_public_key)
        kek = _hkdf_32(shared_secret, salt=nonce, info=info)
        return AESGCM(kek).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise StoreError("Impossibile decifrare la chiave dati: wallet errato o payload corrotto") from exc


def compress_if_useful(data: bytes) -> tuple[bytes, bool]:
    compressed = zlib.compress(data, level=9)
    if len(compressed) < len(data):
        return compressed, True
    return data, False


def split_bytes(data: bytes, chunk_size: int) -> list[bytes]:
    if chunk_size <= 0:
        raise StoreError("chunk_size deve essere > 0")
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
    return chunks or [b""]


def round_up(value: int, step: int) -> int:
    if value <= 0:
        return step
    return ((value + step - 1) // step) * step


def choose_chunk_size(stored_size: int, requested_chunk_size: int | None) -> int:
    if requested_chunk_size is not None:
        if requested_chunk_size <= 0:
            raise StoreError("--chunk-size deve essere > 0")
        return requested_chunk_size

    if stored_size <= 256 * 1024:
        return AUTO_CHUNK_MIN
    if stored_size <= 2 * 1024 * 1024:
        return AUTO_CHUNK_DEFAULT
    if stored_size <= 16 * 1024 * 1024:
        return AUTO_CHUNK_LARGE

    max_chunk_txs = MAX_TOTAL_TRANSACTIONS - 2  # manifest + catalog entry
    required = max(AUTO_CHUNK_LARGE, round_up((stored_size + max_chunk_txs - 1) // max_chunk_txs, CHUNK_SIZE_ROUND))
    return min(max(required, AUTO_CHUNK_LARGE), AUTO_CHUNK_MAX)


def build_chunk_aad_v3(file_id_bytes: bytes, index: int, total_chunks: int, plaintext_len: int) -> bytes:
    return (
        MAGIC
        + bytes([PAYLOAD_VERSION, TYPE_CHUNK])
        + file_id_bytes
        + total_chunks.to_bytes(4, "big")
        + index.to_bytes(4, "big")
        + plaintext_len.to_bytes(4, "big")
    )


def encrypt_chunks_v3(data: bytes, chunk_size: int, chunk_key: bytes, nonce_prefix: bytes, file_id_bytes: bytes) -> list[bytes]:
    aes = AESGCM(chunk_key)
    ciphertexts: list[bytes] = []
    chunks = split_bytes(data, chunk_size)
    total_chunks = len(chunks)
    for index, plain in enumerate(chunks):
        nonce = nonce_prefix + index.to_bytes(4, "big")
        aad = build_chunk_aad_v3(file_id_bytes, index, total_chunks, len(plain))
        ciphertexts.append(aes.encrypt(nonce, plain, aad))
    return ciphertexts


def build_chunk_payload(file_id_bytes: bytes, index: int, total_chunks: int, ciphertext: bytes) -> bytes:
    return (
        MAGIC
        + bytes([PAYLOAD_VERSION])
        + bytes([TYPE_CHUNK])
        + file_id_bytes
        + index.to_bytes(4, "big")
        + total_chunks.to_bytes(4, "big")
        + ciphertext
    )


def build_manifest_payload(manifest: dict) -> bytes:
    encoded = json.dumps(manifest, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return MAGIC + bytes([PAYLOAD_VERSION]) + bytes([TYPE_MANIFEST]) + encoded


def build_catalog_payload(entry: dict) -> bytes:
    encoded = json.dumps(entry, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return MAGIC + bytes([PAYLOAD_VERSION]) + bytes([TYPE_CATALOG_ENTRY]) + encoded


def build_manifest_dict(
    *,
    file_path: Path,
    file_id: str,
    mime_type: str,
    compressed: bool,
    original_bytes: bytes,
    stored_bytes: bytes,
    chunk_size: int,
    total_chunks: int,
    nonce_prefix: bytes,
    wrapped_master_key: bytes,
) -> dict:
    return {
        "kind": "sepolia-file-store-manifest",
        "version": 5,
        "file_id": file_id,
        "file_name": file_path.name,
        "mime_type": mime_type,
        "algorithm": "ECIES-secp256k1 + HKDF-SHA256 + AES-256-GCM-per-chunk",
        "compressed": compressed,
        "original_size": len(original_bytes),
        "original_sha256": sha256_hex(original_bytes),
        "stored_size": len(stored_bytes),
        "stored_sha256": sha256_hex(stored_bytes),
        "plain_chunk_size": chunk_size,
        "total_chunks": total_chunks,
        "nonce_prefix_b64": b64e(nonce_prefix),
        "wrapped_master_key_b64": b64e(wrapped_master_key),
    }


def build_catalog_entry_dict(manifest_tx_hash: str, manifest: dict, prev_catalog_tx_hash: str | None) -> dict:
    return {
        "kind": "sepolia-file-store-catalog-entry",
        "version": 1,
        "file_id": manifest["file_id"],
        "file_name": manifest["file_name"],
        "mime_type": manifest["mime_type"],
        "original_size": int(manifest["original_size"]),
        "original_sha256": manifest["original_sha256"],
        "manifest_tx_hash": normalize_hex_hash(manifest_tx_hash),
        "prev_catalog_tx_hash": normalize_hex_hash(prev_catalog_tx_hash) if prev_catalog_tx_hash else None,
        "created_at": int(time.time()),
    }


def prepare_new_upload(file_path: Path, recipient_public_key_hex: str, requested_chunk_size: int | None) -> PreparedUpload:
    original_bytes = file_path.read_bytes()
    stored_bytes, compressed = compress_if_useful(original_bytes)
    chunk_size = choose_chunk_size(len(stored_bytes), requested_chunk_size)

    file_id = uuid.uuid4().hex
    file_id_bytes = bytes.fromhex(file_id)
    nonce_prefix = os.urandom(8)
    master_key = os.urandom(32)
    wrapped_master_key = seal_with_public_key(recipient_public_key_hex, master_key)
    chunk_key = derive_chunk_key(master_key, file_id_bytes)

    ciphertexts = encrypt_chunks_v3(stored_bytes, chunk_size, chunk_key, nonce_prefix, file_id_bytes)
    chunk_payloads = [
        build_chunk_payload(file_id_bytes, index, len(ciphertexts), ciphertext)
        for index, ciphertext in enumerate(ciphertexts)
    ]

    payload_count = 2 + len(chunk_payloads)  # manifest + chunk + catalog entry
    if payload_count > MAX_TOTAL_TRANSACTIONS:
        raise StoreError(
            f"Il file richiede {payload_count} transazioni, sopra il limite di sicurezza di {MAX_TOTAL_TRANSACTIONS}. "
            f"Riduci il file o aumenta --chunk-size."
        )

    mime_type, _ = mimetypes.guess_type(file_path.name)
    manifest = build_manifest_dict(
        file_path=file_path,
        file_id=file_id,
        mime_type=mime_type or "application/octet-stream",
        compressed=compressed,
        original_bytes=original_bytes,
        stored_bytes=stored_bytes,
        chunk_size=chunk_size,
        total_chunks=len(ciphertexts),
        nonce_prefix=nonce_prefix,
        wrapped_master_key=wrapped_master_key,
    )

    return PreparedUpload(
        file_path=file_path,
        file_id=file_id,
        file_name=file_path.name,
        mime_type=manifest["mime_type"],
        original_size=len(original_bytes),
        original_sha256=manifest["original_sha256"],
        compressed=compressed,
        stored_size=len(stored_bytes),
        stored_sha256=manifest["stored_sha256"],
        chunk_size=chunk_size,
        total_chunks=len(ciphertexts),
        nonce_prefix=nonce_prefix,
        wrapped_master_key=wrapped_master_key,
        manifest=manifest,
        manifest_payload=build_manifest_payload(manifest),
        chunk_payloads=chunk_payloads,
    )


def prepare_upload_from_manifest(file_path: Path, manifest: dict, private_key: bytes) -> PreparedUpload:
    original_bytes = file_path.read_bytes()
    original_sha256 = sha256_hex(original_bytes)
    if original_sha256 != manifest["original_sha256"]:
        raise StoreError("Il file locale non corrisponde al manifest: SHA-256 diversa")
    if len(original_bytes) != int(manifest["original_size"]):
        raise StoreError("Il file locale non corrisponde al manifest: dimensione diversa")

    stored_bytes, compressed = compress_if_useful(original_bytes)
    if bool(compressed) != bool(manifest["compressed"]):
        if bool(manifest["compressed"]):
            raise StoreError("Il manifest richiede dati compressi, ma il file locale non produce lo stesso output")
        stored_bytes = original_bytes
        compressed = False

    if sha256_hex(stored_bytes) != manifest["stored_sha256"]:
        raise StoreError("I dati compressi/locali non corrispondono al manifest")
    if len(stored_bytes) != int(manifest["stored_size"]):
        raise StoreError("Dimensione dati memorizzati non coerente con il manifest")

    file_id = manifest["file_id"]
    file_id_bytes = bytes.fromhex(file_id)
    nonce_prefix = b64d(manifest["nonce_prefix_b64"])

    if "wrapped_master_key_b64" in manifest:
        wrapped_master_key = b64d(manifest["wrapped_master_key_b64"])
        master_key = open_with_private_key(private_key, wrapped_master_key)
        chunk_key = derive_chunk_key(master_key, file_id_bytes)
        ciphertexts = encrypt_chunks_v3(stored_bytes, int(manifest["plain_chunk_size"]), chunk_key, nonce_prefix, file_id_bytes)
    elif "wrapped_dek_b64" in manifest:
        wrapped_master_key = b64d(manifest["wrapped_dek_b64"])
        dek = open_with_private_key(private_key, wrapped_master_key)
        aes = AESGCM(dek)
        ciphertexts = []
        for index, plain in enumerate(split_bytes(stored_bytes, int(manifest["plain_chunk_size"]))):
            nonce = nonce_prefix + index.to_bytes(4, "big")
            aad = index.to_bytes(4, "big") + len(plain).to_bytes(4, "big")
            ciphertexts.append(aes.encrypt(nonce, plain, aad))
    else:
        raise StoreError("Manifest con chiave cifrata non riconosciuta")

    if len(ciphertexts) != int(manifest["total_chunks"]):
        raise StoreError("Numero di chunk ricostruito non coerente con il manifest")

    chunk_payloads = [
        build_chunk_payload(file_id_bytes, index, len(ciphertexts), ciphertext)
        for index, ciphertext in enumerate(ciphertexts)
    ]

    return PreparedUpload(
        file_path=file_path,
        file_id=file_id,
        file_name=manifest["file_name"],
        mime_type=manifest["mime_type"],
        original_size=len(original_bytes),
        original_sha256=manifest["original_sha256"],
        compressed=compressed,
        stored_size=len(stored_bytes),
        stored_sha256=manifest["stored_sha256"],
        chunk_size=int(manifest["plain_chunk_size"]),
        total_chunks=len(ciphertexts),
        nonce_prefix=nonce_prefix,
        wrapped_master_key=wrapped_master_key,
        manifest=manifest,
        manifest_payload=build_manifest_payload(manifest),
        chunk_payloads=chunk_payloads,
    )


# --------------------
# Parsing payload on-chain
# --------------------

def raw_bytes_from_data_field(data_field) -> bytes:
    if isinstance(data_field, str):
        if not data_field.startswith("0x"):
            raise StoreError("campo data/input non valido")
        return bytes.fromhex(data_field[2:])
    if isinstance(data_field, (bytes, bytearray)):
        return bytes(data_field)
    try:
        return bytes(data_field)
    except Exception as exc:
        raise StoreError("campo data/input non convertibile in bytes") from exc


def parse_payload(data_field) -> dict:
    raw = raw_bytes_from_data_field(data_field)
    if len(raw) < 6:
        raise StoreError("payload troppo corto")

    magic = raw[:4]
    if magic not in {MAGIC_V1, MAGIC_V2, MAGIC}:
        raise StoreError("payload non riconosciuto")

    version = raw[4]
    kind = raw[5]

    if kind == TYPE_MANIFEST:
        manifest = json.loads(raw[6:].decode("utf-8"))
        return {
            "magic": magic,
            "payload_version": version,
            "payload_kind": "manifest",
            "manifest": manifest,
        }

    if kind == TYPE_CHUNK:
        if len(raw) < 30:
            raise StoreError("chunk troppo corto")
        return {
            "magic": magic,
            "payload_version": version,
            "payload_kind": "chunk",
            "file_id": raw[6:22].hex(),
            "index": int.from_bytes(raw[22:26], "big"),
            "total_chunks": int.from_bytes(raw[26:30], "big"),
            "chunk_bytes": raw[30:],
        }

    if kind == TYPE_CATALOG_ENTRY:
        entry = json.loads(raw[6:].decode("utf-8"))
        return {
            "magic": magic,
            "payload_version": version,
            "payload_kind": "catalog",
            "entry": entry,
        }

    raise StoreError(f"tipo payload sconosciuto: {kind}")


# --------------------
# Gas / fees
# --------------------

def calldata_tokens(data_bytes: bytes) -> int:
    non_zero = sum(1 for b in data_bytes if b != 0)
    zero = len(data_bytes) - non_zero
    return zero + (4 * non_zero)


def min_gas_limit_for_data_tx(data_bytes: bytes) -> int:
    tokens = calldata_tokens(data_bytes)
    return 21000 + (10 * tokens)


def estimate_payload_costs(w3: Web3, payloads: Sequence[bytes]) -> dict:
    gas_by_tx = [min_gas_limit_for_data_tx(payload) + DATA_TX_GAS_BUFFER for payload in payloads]
    total_gas = sum(gas_by_tx)

    latest = w3.eth.get_block("latest")
    base_fee = int(latest.get("baseFeePerGas", 0) or 0)
    try:
        priority_fee = int(w3.eth.max_priority_fee)
    except Exception:
        priority_fee = int(w3.to_wei(1, "gwei"))

    if base_fee > 0:
        fee_style = "eip1559"
        suggested_fee_per_gas = (base_fee * 2) + priority_fee
    else:
        fee_style = "legacy"
        suggested_fee_per_gas = int(w3.eth.gas_price)

    estimated_cost_wei = total_gas * suggested_fee_per_gas
    funding_buffer_wei = max((estimated_cost_wei * FUNDING_BUFFER_PCT) // 100, MIN_FUNDING_BUFFER_WEI)
    recommended_total_wei = estimated_cost_wei + funding_buffer_wei

    return {
        "payload_count": len(payloads),
        "gas_by_tx": gas_by_tx,
        "total_gas": total_gas,
        "fee_style": fee_style,
        "base_fee_per_gas": base_fee,
        "max_priority_fee_per_gas": priority_fee,
        "suggested_fee_per_gas": suggested_fee_per_gas,
        "estimated_cost_wei": estimated_cost_wei,
        "recommended_total_wei": recommended_total_wei,
        "funding_buffer_wei": funding_buffer_wei,
    }


def estimate_upload_cost(w3: Web3, prepared: PreparedUpload) -> dict:
    dummy_catalog = build_catalog_payload(build_catalog_entry_dict("0x" + ("0" * 64), prepared.manifest, None))
    return estimate_payload_costs(w3, [prepared.manifest_payload] + prepared.chunk_payloads + [dummy_catalog])


def build_type2_tx(
    *,
    from_address: str,
    to_address: str,
    nonce: int,
    value_wei: int,
    gas_limit: int,
    max_fee_per_gas: int,
    max_priority_fee_per_gas: int,
    data_bytes: bytes = b"",
) -> dict:
    return {
        "type": 2,
        "chainId": CHAIN_ID,
        "from": from_address,
        "to": to_address,
        "value": int(value_wei),
        "nonce": int(nonce),
        "data": data_bytes,
        "gas": int(gas_limit),
        "maxFeePerGas": int(max_fee_per_gas),
        "maxPriorityFeePerGas": int(max_priority_fee_per_gas),
    }


def suggested_eip1559_fees(w3: Web3, attempt: int = 0, fallback_priority_gwei: int = 1) -> tuple[int, int]:
    latest = w3.eth.get_block("latest")
    base_fee = int(latest.get("baseFeePerGas", 0) or 0)
    try:
        priority_fee = int(w3.eth.max_priority_fee)
    except Exception:
        priority_fee = int(w3.to_wei(fallback_priority_gwei, "gwei"))

    if base_fee > 0:
        max_fee = (base_fee * 2) + priority_fee
        if attempt > 0:
            bump = 100 + (attempt * 15)
            max_fee = (max_fee * bump) // 100
            priority_fee = (priority_fee * bump) // 100 or priority_fee
        return max_fee, priority_fee

    gas_price = int(w3.eth.gas_price)
    if attempt > 0:
        gas_price = (gas_price * (100 + (attempt * 15))) // 100
    return gas_price, 0


def get_raw_signed_tx(signed) -> bytes:
    raw_tx = getattr(signed, "raw_transaction", None)
    if raw_tx is None:
        raw_tx = getattr(signed, "rawTransaction", None)
    if raw_tx is None:
        raise StoreError("oggetto SignedTransaction senza raw_transaction/rawTransaction")
    return bytes(raw_tx)


def wait_for_receipt(w3: Web3, tx_hash: bytes, timeout: int = TX_WAIT_TIMEOUT_SECONDS):
    return w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout, poll_latency=2)


# --------------------
# Tx helpers
# --------------------

def normalize_hex_hash(value: str | None) -> str:
    if value is None:
        raise StoreError("tx hash mancante")
    value = value.strip()
    candidate_path = Path(value).expanduser()
    if candidate_path.is_file():
        value = candidate_path.read_text(encoding="utf-8").strip()
    if not value.startswith("0x"):
        value = "0x" + value
    if len(value) != 66:
        raise StoreError("tx hash non valido")
    int(value[2:], 16)
    return value.lower()


def fetch_transaction(w3: Web3, tx_hash: str):
    try:
        return w3.eth.get_transaction(tx_hash)
    except Exception as exc:
        raise StoreError(f"Transazione non trovata: {tx_hash}") from exc


def fetch_receipt(w3: Web3, tx_hash: str):
    try:
        return w3.eth.get_transaction_receipt(tx_hash)
    except Exception:
        return None


def transaction_input_hex(tx) -> str:
    raw_input = tx["input"]
    if isinstance(raw_input, str):
        return raw_input
    return "0x" + bytes(raw_input).hex()


def load_manifest_from_chain(w3: Web3, manifest_tx_hash: str) -> tuple[dict, dict, dict]:
    tx = fetch_transaction(w3, manifest_tx_hash)
    if tx.get("blockNumber") is None:
        raise StoreError("La manifest tx non è ancora minata")
    payload = parse_payload(transaction_input_hex(tx))
    if payload["payload_kind"] != "manifest":
        raise StoreError("La tx indicata non contiene un manifest valido")
    manifest = payload["manifest"]
    if manifest.get("kind") != "sepolia-file-store-manifest":
        raise StoreError("Manifest non riconosciuto")
    return tx, manifest, payload


def load_catalog_entry_from_chain(w3: Web3, catalog_tx_hash: str, index: int) -> CatalogEntry:
    tx = fetch_transaction(w3, catalog_tx_hash)
    if tx.get("blockNumber") is None:
        raise StoreError("La catalog tx non è ancora minata")
    payload = parse_payload(transaction_input_hex(tx))
    if payload["payload_kind"] != "catalog":
        raise StoreError("La tx indicata non contiene una catalog entry valida")
    entry = payload["entry"]
    if entry.get("kind") != "sepolia-file-store-catalog-entry":
        raise StoreError("Catalog entry non riconosciuta")
    return CatalogEntry(
        index=index,
        catalog_tx_hash=normalize_hex_hash(catalog_tx_hash),
        manifest_tx_hash=normalize_hex_hash(entry["manifest_tx_hash"]),
        prev_catalog_tx_hash=normalize_hex_hash(entry["prev_catalog_tx_hash"]) if entry.get("prev_catalog_tx_hash") else None,
        file_name=entry["file_name"],
        mime_type=entry["mime_type"],
        original_size=int(entry["original_size"]),
        original_sha256=entry["original_sha256"],
        created_at=int(entry.get("created_at", 0)),
        file_id=entry.get("file_id", ""),
    )


def maybe_finalize_pending_catalog(w3: Web3) -> LocalState:
    state = read_local_state()
    if not state.pending_catalog_tx_hash:
        return state

    receipt = fetch_receipt(w3, state.pending_catalog_tx_hash)
    if receipt is None:
        return state
    if int(receipt.status) != 1:
        raise StoreError(
            "È presente una catalog tx pendente ma risulta fallita. "
            "Controlla manualmente e poi rimuovi le righe PENDING_* da sfs_root.txt se necessario."
        )

    _ = load_catalog_entry_from_chain(w3, state.pending_catalog_tx_hash, 0)
    state.root_catalog_tx_hash = normalize_hex_hash(state.pending_catalog_tx_hash)
    state.pending_file = None
    state.pending_manifest_tx_hash = None
    state.pending_catalog_tx_hash = None
    write_local_state(state)
    return state


# --------------------
# Scansione manifest/chunk
# --------------------

def scan_chunks_from_manifest(w3: Web3, manifest_tx_hash: str) -> tuple[dict, dict[int, bytes]]:
    manifest_tx, manifest, _payload = load_manifest_from_chain(w3, manifest_tx_hash)
    sender = manifest_tx["from"].lower()
    manifest_nonce = int(manifest_tx["nonce"])
    manifest_block = int(manifest_tx["blockNumber"])
    total_chunks = int(manifest["total_chunks"])
    expected_file_id = manifest["file_id"]

    needed_nonces = {manifest_nonce + 1 + i for i in range(total_chunks)}
    chunk_map: dict[int, bytes] = {}

    latest_block = int(w3.eth.block_number)
    for block_number in range(manifest_block, latest_block + 1):
        block = w3.eth.get_block(block_number, full_transactions=True)
        for tx in block["transactions"]:
            tx_from = tx.get("from")
            if not tx_from or tx_from.lower() != sender:
                continue
            tx_nonce = int(tx["nonce"])
            if tx_nonce not in needed_nonces:
                continue
            try:
                payload = parse_payload(transaction_input_hex(tx))
            except StoreError:
                continue
            if payload["payload_kind"] != "chunk":
                continue
            if payload["file_id"] != expected_file_id:
                continue
            if int(payload["total_chunks"]) != total_chunks:
                raise StoreError(f"Chunk con total_chunks incoerente nel blocco {block_number}")
            chunk_map[int(payload["index"])] = payload["chunk_bytes"]
        if len(chunk_map) == total_chunks:
            break

    return manifest, chunk_map


# --------------------
# Decrypt / reconstruct
# --------------------

def decrypt_and_reassemble_to_file(
    private_key: bytes,
    manifest: dict,
    chunk_map: dict[int, bytes],
    out_path: Path,
) -> None:
    total_chunks = int(manifest["total_chunks"])
    missing = [index for index in range(total_chunks) if index not in chunk_map]
    if missing:
        preview = ", ".join(str(i) for i in missing[:10])
        raise StoreError(f"Mancano {len(missing)} chunk. Primi mancanti: {preview}")

    file_id_bytes = bytes.fromhex(manifest["file_id"])
    nonce_prefix = b64d(manifest["nonce_prefix_b64"])

    if "wrapped_master_key_b64" in manifest:
        wrapped_key = b64d(manifest["wrapped_master_key_b64"])
        master_key = open_with_private_key(private_key, wrapped_key)
        chunk_key = derive_chunk_key(master_key, file_id_bytes)
        aes = AESGCM(chunk_key)
        aad_mode = "v3"
    elif "wrapped_dek_b64" in manifest:
        wrapped_key = b64d(manifest["wrapped_dek_b64"])
        dek = open_with_private_key(private_key, wrapped_key)
        aes = AESGCM(dek)
        aad_mode = "v1"
    else:
        raise StoreError("Manifest non supportato: chiave cifrata assente")

    stored_hash = hashlib.sha256()
    original_hash = hashlib.sha256()
    stored_total = 0
    written_original = 0

    decompressor = zlib.decompressobj() if manifest.get("compressed") else None
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(out_path.suffix + ".tmp")

    with tmp_path.open("wb") as fh:
        for index in range(total_chunks):
            ciphertext = chunk_map[index]
            nonce = nonce_prefix + index.to_bytes(4, "big")
            plaintext_len = max(0, len(ciphertext) - 16)
            if aad_mode == "v3":
                aad = build_chunk_aad_v3(file_id_bytes, index, total_chunks, plaintext_len)
            else:
                aad = index.to_bytes(4, "big") + plaintext_len.to_bytes(4, "big")
            try:
                stored_part = aes.decrypt(nonce, ciphertext, aad)
            except Exception as exc:
                raise StoreError(f"Decifrazione chunk fallita all'indice {index}") from exc

            stored_hash.update(stored_part)
            stored_total += len(stored_part)

            if decompressor is not None:
                original_part = decompressor.decompress(stored_part)
            else:
                original_part = stored_part

            if original_part:
                fh.write(original_part)
                original_hash.update(original_part)
                written_original += len(original_part)

        if decompressor is not None:
            tail = decompressor.flush()
            if tail:
                fh.write(tail)
                original_hash.update(tail)
                written_original += len(tail)

    if stored_hash.hexdigest() != manifest["stored_sha256"]:
        tmp_path.unlink(missing_ok=True)
        raise StoreError("SHA-256 dei dati ricostruiti non coerente")
    if stored_total != int(manifest["stored_size"]):
        tmp_path.unlink(missing_ok=True)
        raise StoreError("Dimensione dati memorizzati non coerente")
    if written_original != int(manifest["original_size"]):
        tmp_path.unlink(missing_ok=True)
        raise StoreError("Dimensione file ricostruito non coerente")
    if original_hash.hexdigest() != manifest["original_sha256"]:
        tmp_path.unlink(missing_ok=True)
        raise StoreError("SHA-256 finale del file non coerente")

    os.replace(tmp_path, out_path)


def manifest_summary(manifest: dict) -> dict:
    return {
        "file_name": manifest["file_name"],
        "mime_type": manifest["mime_type"],
        "compressed": bool(manifest["compressed"]),
        "original_size": int(manifest["original_size"]),
        "stored_size": int(manifest["stored_size"]),
        "plain_chunk_size": int(manifest["plain_chunk_size"]),
        "total_chunks": int(manifest["total_chunks"]),
        "file_id": manifest["file_id"],
    }


# --------------------
# Catalogo flat append-only
# --------------------

def iter_catalog_entries(w3: Web3, root_catalog_tx_hash: str) -> Iterator[CatalogEntry]:
    current = normalize_hex_hash(root_catalog_tx_hash)
    seen: set[str] = set()
    index = 1
    while current:
        if current in seen:
            raise StoreError("Ciclo rilevato nel catalogo")
        seen.add(current)
        entry = load_catalog_entry_from_chain(w3, current, index)
        yield entry
        current = entry.prev_catalog_tx_hash or ""
        index += 1
        if index > MAX_INTERACTIVE_SCAN:
            raise StoreError(f"Catalogo oltre il limite di scansione di sicurezza ({MAX_INTERACTIVE_SCAN})")


def select_catalog_entry_by_index(w3: Web3, root_catalog_tx_hash: str, wanted_index: int) -> CatalogEntry:
    if wanted_index <= 0:
        raise StoreError("L'indice catalogo deve essere >= 1")
    for entry in iter_catalog_entries(w3, root_catalog_tx_hash):
        if entry.index == wanted_index:
            return entry
    raise StoreError(f"Indice catalogo non trovato: {wanted_index}")


def collect_catalog_page(
    w3: Web3,
    root_catalog_tx_hash: str,
    *,
    start_index: int,
    page_size: int,
    search_term: str | None = None,
) -> list[CatalogEntry]:
    search_lc = (search_term or "").lower()
    matches: list[CatalogEntry] = []
    for entry in iter_catalog_entries(w3, root_catalog_tx_hash):
        if entry.index < start_index:
            continue
        if search_lc and search_lc not in entry.file_name.lower():
            continue
        matches.append(entry)
        if len(matches) >= page_size:
            break
    return matches


def fetch_catalog_page_from_cursor(
    w3: Web3,
    current_hash: str | None,
    current_index: int,
    *,
    page_size: int,
    search_term: str | None = None,
) -> tuple[list[CatalogEntry], str | None, int]:
    entries: list[CatalogEntry] = []
    next_hash = current_hash
    next_index = current_index
    search_lc = (search_term or "").lower()

    while next_hash and len(entries) < page_size:
        entry = load_catalog_entry_from_chain(w3, next_hash, next_index)
        next_hash = entry.prev_catalog_tx_hash
        next_index = entry.index + 1
        if search_lc and search_lc not in entry.file_name.lower():
            continue
        entries.append(entry)

    return entries, next_hash, next_index


def print_catalog_entries(entries: Sequence[CatalogEntry], *, title: str | None = None) -> None:
    if title:
        print(title)
    if not entries:
        print("Nessuna entry trovata.")
        return
    print(f"{'Idx':>6}  {'Size':>10}  {'Nome'}")
    print("-" * 72)
    for entry in entries:
        print(f"{entry.index:>6}  {format_size(entry.original_size):>10}  {entry.file_name}")
        print(f"        manifest={short_hash(entry.manifest_tx_hash)} catalog={short_hash(entry.catalog_tx_hash)}")


def interactive_pick_catalog_entry(
    w3: Web3,
    root_catalog_tx_hash: str,
    *,
    action_label: str,
    initial_search: str | None = None,
) -> CatalogEntry:
    page_size = DEFAULT_CATALOG_PAGE_SIZE
    search_term = initial_search
    current_hash: str | None = root_catalog_tx_hash
    current_index = 1
    cache: dict[int, CatalogEntry] = {}

    while True:
        entries, next_hash, next_index = fetch_catalog_page_from_cursor(
            w3,
            current_hash,
            current_index,
            page_size=page_size,
            search_term=search_term,
        )
        title = "\n=== Catalogo ===" if not search_term else f"\n=== Catalogo / ricerca: {search_term!r} ==="
        print_catalog_entries(entries, title=title)
        for entry in entries:
            cache[entry.index] = entry

        prompt = (
            f"\nScegli indice per {action_label}, Invio/n per prossima pagina, "
            f"/testo per cercare, r per reset, q per uscire: "
        )
        try:
            answer = input(prompt).strip()
        except EOFError:
            raise StoreError("Input interattivo non disponibile")

        if answer == "":
            answer = "n"
        if answer.lower() == "q":
            raise StoreError("Operazione annullata")
        if answer.lower() == "r":
            search_term = None
            current_hash = root_catalog_tx_hash
            current_index = 1
            cache.clear()
            continue
        if answer.startswith("/"):
            search_term = answer[1:].strip() or None
            current_hash = root_catalog_tx_hash
            current_index = 1
            cache.clear()
            continue
        if answer.lower() == "n":
            if entries:
                current_hash = next_hash
                current_index = next_index
            else:
                print("Nessun'altra entry.")
                current_hash = root_catalog_tx_hash
                current_index = 1
            continue
        if answer.isdigit():
            index = int(answer)
            if index in cache:
                return cache[index]
            return select_catalog_entry_by_index(w3, root_catalog_tx_hash, index)

        print("Input non riconosciuto.")


def resolve_manifest_tx_hash(
    w3: Web3,
    selector: str | None,
    *,
    search_term: str | None = None,
    interactive_action_label: str,
) -> str:
    state = read_local_state()
    root_hash = state.root_catalog_tx_hash

    if selector:
        selector = selector.strip()
        if selector.isdigit():
            if not root_hash:
                raise StoreError("sfs_root.txt non contiene un catalogo ROOT")
            return select_catalog_entry_by_index(w3, root_hash, int(selector)).manifest_tx_hash
        candidate_hash = normalize_hex_hash(selector)
        try:
            payload = parse_payload(transaction_input_hex(fetch_transaction(w3, candidate_hash)))
            if payload["payload_kind"] == "catalog":
                entry = payload["entry"]
                return normalize_hex_hash(entry["manifest_tx_hash"])
        except Exception:
            pass
        return candidate_hash

    if not root_hash:
        raise StoreError("Nessun ROOT presente in sfs_root.txt. Fai prima almeno un upload.")

    chosen = interactive_pick_catalog_entry(
        w3,
        root_hash,
        action_label=interactive_action_label,
        initial_search=search_term,
    )
    return chosen.manifest_tx_hash


# --------------------
# Upload / resume / catalog update
# --------------------

def build_resume_prepared_or_new(
    w3: Web3,
    file_path: Path,
    private_key: bytes,
    public_key_hex: str,
    requested_chunk_size: int | None,
) -> tuple[str | None, PreparedUpload, dict[int, bytes] | None, dict | None]:
    state = read_local_state()
    pending_file = Path(state.pending_file).resolve() if state.pending_file else None

    if state.pending_manifest_tx_hash:
        if pending_file is None:
            raise StoreError("sfs_root.txt contiene PENDING_MANIFEST ma non PENDING_FILE")
        if pending_file != file_path.resolve():
            raise StoreError(
                "C'è già un upload pendente per un altro file. "
                f"Completa prima: {pending_file}"
            )
        manifest_tx_hash = normalize_hex_hash(state.pending_manifest_tx_hash)
        manifest_tx, manifest, _payload = load_manifest_from_chain(w3, manifest_tx_hash)
        prepared = prepare_upload_from_manifest(file_path, manifest, private_key)
        existing_chunk_map = scan_chunks_from_manifest(w3, manifest_tx_hash)[1]
        return manifest_tx_hash, prepared, existing_chunk_map, manifest_tx

    return None, prepare_new_upload(file_path, public_key_hex, requested_chunk_size), None, None


def send_manifest_tx(w3: Web3, account, prepared: PreparedUpload) -> tuple[str, dict]:
    nonce = int(w3.eth.get_transaction_count(account.address, "pending"))
    max_fee_per_gas, max_priority_fee_per_gas = suggested_eip1559_fees(w3)
    tx = build_type2_tx(
        from_address=account.address,
        to_address=account.address,
        nonce=nonce,
        value_wei=0,
        gas_limit=min_gas_limit_for_data_tx(prepared.manifest_payload) + DATA_TX_GAS_BUFFER,
        max_fee_per_gas=max_fee_per_gas,
        max_priority_fee_per_gas=max_priority_fee_per_gas,
        data_bytes=prepared.manifest_payload,
    )

    last_error: Exception | None = None
    for attempt in range(MAX_RETRIES_PER_TX):
        try:
            tx["maxFeePerGas"], tx["maxPriorityFeePerGas"] = suggested_eip1559_fees(w3, attempt=attempt)
            signed = account.sign_transaction(tx)
            tx_hash_bytes = w3.eth.send_raw_transaction(get_raw_signed_tx(signed))
            manifest_tx_hash = tx_hash_bytes.hex()
            update_state_pending(prepared.file_path, manifest_tx_hash)
            receipt = wait_for_receipt(w3, tx_hash_bytes)
            if int(receipt.status) != 1:
                clear_pending_state()
                raise StoreError(f"manifest tx fallita: {manifest_tx_hash}")
            return manifest_tx_hash, receipt
        except Exception as exc:
            last_error = exc
            if attempt == MAX_RETRIES_PER_TX - 1:
                break
            time.sleep(2 * (attempt + 1))
    raise StoreError(f"Invio manifest fallito: {last_error}")


def chunked(seq: Sequence[int], size: int) -> Iterable[list[int]]:
    for i in range(0, len(seq), size):
        yield list(seq[i:i + size])


def send_missing_chunks(
    w3: Web3,
    account,
    prepared: PreparedUpload,
    manifest_tx: dict,
    existing_chunk_map: dict[int, bytes],
    parallelism: int,
) -> dict:
    total_chunks = prepared.total_chunks
    missing_indexes = [index for index in range(total_chunks) if index not in existing_chunk_map]
    if not missing_indexes:
        return {
            "uploaded_chunk_count": 0,
            "already_present_chunk_count": total_chunks,
        }

    manifest_nonce = int(manifest_tx["nonce"])
    parallelism = max(1, min(int(parallelism), MAX_PARALLELISM))

    uploaded_now = 0
    for batch in chunked(missing_indexes, parallelism):
        sent: list[tuple[int, bytes]] = []
        for index in batch:
            payload = prepared.chunk_payloads[index]
            max_fee_per_gas, max_priority_fee_per_gas = suggested_eip1559_fees(w3)
            tx = build_type2_tx(
                from_address=account.address,
                to_address=account.address,
                nonce=manifest_nonce + 1 + index,
                value_wei=0,
                gas_limit=min_gas_limit_for_data_tx(payload) + DATA_TX_GAS_BUFFER,
                max_fee_per_gas=max_fee_per_gas,
                max_priority_fee_per_gas=max_priority_fee_per_gas,
                data_bytes=payload,
            )

            last_error: Exception | None = None
            for attempt in range(MAX_RETRIES_PER_TX):
                try:
                    tx["maxFeePerGas"], tx["maxPriorityFeePerGas"] = suggested_eip1559_fees(w3, attempt=attempt)
                    signed = account.sign_transaction(tx)
                    tx_hash = w3.eth.send_raw_transaction(get_raw_signed_tx(signed))
                    sent.append((index, tx_hash))
                    print(f"[queue {index + 1}/{total_chunks}] {tx_hash.hex()}")
                    break
                except Exception as exc:
                    last_error = exc
                    if "nonce too low" in str(exc).lower():
                        print(f"[skip  {index + 1}/{total_chunks}] già presente on-chain")
                        break
                    if attempt == MAX_RETRIES_PER_TX - 1:
                        raise StoreError(f"Invio chunk {index} fallito: {exc}") from exc
                    time.sleep(2 * (attempt + 1))
            if last_error is not None and not sent and "nonce too low" not in str(last_error).lower():
                raise StoreError(f"Invio chunk {index} fallito: {last_error}")

        for index, tx_hash in sent:
            receipt = wait_for_receipt(w3, tx_hash)
            if int(receipt.status) != 1:
                raise StoreError(f"Chunk {index} fallito: {tx_hash.hex()}")
            uploaded_now += 1
            print(f"[ ok   {index + 1}/{total_chunks}] {tx_hash.hex()}")

    return {
        "uploaded_chunk_count": uploaded_now,
        "already_present_chunk_count": total_chunks - len(missing_indexes),
    }


def send_catalog_tx(w3: Web3, account, catalog_entry: dict, nonce: int) -> tuple[str, dict]:
    payload = build_catalog_payload(catalog_entry)
    max_fee_per_gas, max_priority_fee_per_gas = suggested_eip1559_fees(w3)
    tx = build_type2_tx(
        from_address=account.address,
        to_address=account.address,
        nonce=nonce,
        value_wei=0,
        gas_limit=min_gas_limit_for_data_tx(payload) + DATA_TX_GAS_BUFFER,
        max_fee_per_gas=max_fee_per_gas,
        max_priority_fee_per_gas=max_priority_fee_per_gas,
        data_bytes=payload,
    )

    last_error: Exception | None = None
    for attempt in range(MAX_RETRIES_PER_TX):
        try:
            tx["maxFeePerGas"], tx["maxPriorityFeePerGas"] = suggested_eip1559_fees(w3, attempt=attempt)
            signed = account.sign_transaction(tx)
            tx_hash_bytes = w3.eth.send_raw_transaction(get_raw_signed_tx(signed))
            catalog_tx_hash = tx_hash_bytes.hex()
            update_state_pending_catalog(catalog_tx_hash)
            receipt = wait_for_receipt(w3, tx_hash_bytes)
            if int(receipt.status) != 1:
                raise StoreError(f"catalog tx fallita: {catalog_tx_hash}")
            return catalog_tx_hash, receipt
        except Exception as exc:
            last_error = exc
            if attempt == MAX_RETRIES_PER_TX - 1:
                break
            time.sleep(2 * (attempt + 1))
    raise StoreError(f"Invio catalog entry fallito: {last_error}")


# --------------------
# CLI / output
# --------------------

def print_wallet_qr(address: str) -> None:
    qr = qrcode.QRCode(border=2)
    qr.add_data(address)
    qr.make(fit=True)
    print("\nQR ricezione:\n")
    qr.print_ascii(invert=True)


def print_estimate_common(
    *,
    w3: Web3,
    rpc_url: str,
    account_address: str,
    prepared: PreparedUpload,
    estimates: dict,
    balance_wei: int,
) -> None:
    print(f"Rete                     : {NETWORK_NAME}")
    print(f"RPC                      : {rpc_url}")
    print(f"Wallet                   : {account_address}")
    print(f"File                     : {prepared.file_path.name}")
    print(f"MIME                     : {prepared.mime_type}")
    print(f"Dimensione originale     : {prepared.original_size} bytes")
    print(f"Compressione             : {'si' if prepared.compressed else 'no'}")
    print(f"Dimensione memorizzata   : {prepared.stored_size} bytes")
    print(f"Chunk size plaintext     : {prepared.chunk_size} bytes")
    print(f"Chunk totali             : {prepared.total_chunks}")
    print(f"Tx manifest              : 1")
    print(f"Tx chunk                 : {prepared.total_chunks}")
    print(f"Tx catalog               : 1")
    print(f"Tx totali                : {estimates['payload_count']}")
    print(f"Gas totale stimato       : {estimates['total_gas']}")
    print(f"Fee style                : {estimates['fee_style']}")
    print(f"Base fee                 : {Web3.from_wei(estimates['base_fee_per_gas'], 'gwei')} gwei")
    print(f"Priority fee             : {Web3.from_wei(estimates['max_priority_fee_per_gas'], 'gwei')} gwei")
    print(f"Fee/gas stimata          : {Web3.from_wei(estimates['suggested_fee_per_gas'], 'gwei')} gwei")
    print(f"Costo stimato            : {format_eth(estimates['estimated_cost_wei'])} ETH")
    print(f"Buffer consigliato       : {format_eth(estimates['funding_buffer_wei'])} ETH")
    print(f"Totale consigliato       : {format_eth(estimates['recommended_total_wei'])} ETH")
    print(f"Saldo attuale            : {format_eth(balance_wei)} ETH")
    shortfall = max(0, estimates['recommended_total_wei'] - balance_wei)
    print(f"Da aggiungere circa      : {format_eth(shortfall)} ETH")
    print(f"Stato locale             : {STATE_FILE}")


def cmd_wallet(args: argparse.Namespace) -> int:
    w3, rpc_url = connect_web3()
    _ = maybe_finalize_pending_catalog(w3)
    account, private_key = load_or_create_wallet()
    balance = w3.eth.get_balance(account.address)
    public_key_hex = derive_public_key_hex(private_key)
    print(f"Rete      : {NETWORK_NAME}")
    print(f"RPC       : {rpc_url}")
    print(f"Address   : {account.address}")
    print(f"Saldo     : {format_eth(balance)} ETH")
    print(f"Priv key  : {KEY_FILE}")
    print(f"Pub key   : 0x{public_key_hex}")
    print(f"Stato     : {STATE_FILE}")
    if not args.no_qr:
        print_wallet_qr(account.address)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    w3, rpc_url = connect_web3()
    state = maybe_finalize_pending_catalog(w3)
    print(f"Rete                  : {NETWORK_NAME}")
    print(f"RPC                   : {rpc_url}")
    print(f"Stato file            : {STATE_FILE}")
    print(f"ROOT                  : {state.root_catalog_tx_hash or '-'}")
    print(f"Pending file          : {state.pending_file or '-'}")
    print(f"Pending manifest      : {state.pending_manifest_tx_hash or '-'}")
    print(f"Pending catalog       : {state.pending_catalog_tx_hash or '-'}")
    return 0


def cmd_estimate(args: argparse.Namespace) -> int:
    file_path = Path(args.file).expanduser().resolve()
    if not file_path.is_file():
        raise SystemExit(f"File non trovato: {file_path}")

    w3, rpc_url = connect_web3()
    _ = maybe_finalize_pending_catalog(w3)
    account, private_key = load_or_create_wallet()
    public_key_hex = derive_public_key_hex(private_key)
    prepared = prepare_new_upload(file_path, public_key_hex, args.chunk_size)
    estimates = estimate_upload_cost(w3, prepared)
    balance = int(w3.eth.get_balance(account.address))

    print_estimate_common(
        w3=w3,
        rpc_url=rpc_url,
        account_address=account.address,
        prepared=prepared,
        estimates=estimates,
        balance_wei=balance,
    )
    return 0


def cmd_upload(args: argparse.Namespace) -> int:
    file_path = Path(args.file).expanduser().resolve()
    if not file_path.is_file():
        raise SystemExit(f"File non trovato: {file_path}")

    w3, rpc_url = connect_web3()
    state = maybe_finalize_pending_catalog(w3)
    account, private_key = load_or_create_wallet()
    public_key_hex = derive_public_key_hex(private_key)

    manifest_tx_hash, prepared, existing_chunk_map, manifest_tx = build_resume_prepared_or_new(
        w3=w3,
        file_path=file_path,
        private_key=private_key,
        public_key_hex=public_key_hex,
        requested_chunk_size=args.chunk_size,
    )

    if manifest_tx_hash is None:
        estimates = estimate_upload_cost(w3, prepared)
        balance = int(w3.eth.get_balance(account.address))
        if balance < estimates['estimated_cost_wei']:
            missing = estimates['recommended_total_wei'] - balance
            raise SystemExit(
                "Saldo insufficiente.\n"
                f"Saldo attuale       : {format_eth(balance)} ETH\n"
                f"Costo stimato       : {format_eth(estimates['estimated_cost_wei'])} ETH\n"
                f"Totale consigliato  : {format_eth(estimates['recommended_total_wei'])} ETH\n"
                f"Da aggiungere circa : {format_eth(max(0, missing))} ETH"
            )

        print(f"Upload su {NETWORK_NAME} via {rpc_url}")
        print(f"Address                : {account.address}")
        print(f"File                   : {file_path.name}")
        print(f"File ID                : {prepared.file_id}")
        print(f"Chunk size             : {prepared.chunk_size}")
        print(f"Chunk                  : {prepared.total_chunks}")
        print(f"Tx totali              : {estimates['payload_count']}")
        print(f"Costo stimato          : {format_eth(estimates['estimated_cost_wei'])} ETH")
        print("Invio manifest...")

        manifest_tx_hash, receipt = send_manifest_tx(w3, account, prepared)
        manifest_tx = fetch_transaction(w3, manifest_tx_hash)
        existing_chunk_map = {}

        print(f"Manifest tx hash       : {manifest_tx_hash}")
        print(f"Manifest block         : {receipt.blockNumber}")
    else:
        if manifest_tx is None:
            manifest_tx = fetch_transaction(w3, manifest_tx_hash)
        if existing_chunk_map is None:
            existing_chunk_map = scan_chunks_from_manifest(w3, manifest_tx_hash)[1]

        print(f"Resume upload su {NETWORK_NAME} via {rpc_url}")
        print(f"Address                : {account.address}")
        print(f"File                   : {file_path.name}")
        print(f"Manifest tx hash       : {manifest_tx_hash}")
        print(f"Chunk già presenti     : {len(existing_chunk_map)}/{prepared.total_chunks}")

    missing_indexes = [i for i in range(prepared.total_chunks) if i not in existing_chunk_map]
    if missing_indexes:
        remaining_payloads = [prepared.chunk_payloads[i] for i in missing_indexes]
        remaining_estimate = estimate_payload_costs(w3, remaining_payloads)
        balance = int(w3.eth.get_balance(account.address))
        if balance < remaining_estimate['estimated_cost_wei']:
            missing = remaining_estimate['recommended_total_wei'] - balance
            raise SystemExit(
                "Saldo insufficiente per completare l'upload.\n"
                f"Saldo attuale       : {format_eth(balance)} ETH\n"
                f"Costo restante      : {format_eth(remaining_estimate['estimated_cost_wei'])} ETH\n"
                f"Totale consigliato  : {format_eth(remaining_estimate['recommended_total_wei'])} ETH\n"
                f"Da aggiungere circa : {format_eth(max(0, missing))} ETH"
            )

        print(f"Chunk mancanti         : {len(missing_indexes)}")
        print(f"Parallelism            : {max(1, min(args.parallel, MAX_PARALLELISM))}")
        print("Upload chunk in corso...")

        result = send_missing_chunks(
            w3=w3,
            account=account,
            prepared=prepared,
            manifest_tx=manifest_tx,
            existing_chunk_map=existing_chunk_map,
            parallelism=args.parallel,
        )
    else:
        result = {
            "uploaded_chunk_count": 0,
            "already_present_chunk_count": prepared.total_chunks,
        }

    current_state = read_local_state()
    previous_root = current_state.root_catalog_tx_hash
    catalog_entry = build_catalog_entry_dict(manifest_tx_hash, prepared.manifest, previous_root)
    catalog_nonce = int(manifest_tx["nonce"]) + 1 + prepared.total_chunks

    print("Aggiornamento catalogo...")
    catalog_tx_hash, _catalog_receipt = send_catalog_tx(w3, account, catalog_entry, catalog_nonce)
    commit_root_catalog(catalog_tx_hash)

    print("\n[OK] Upload completato")
    print(f"Manifest tx hash       : {manifest_tx_hash}")
    print(f"Catalog tx hash        : {catalog_tx_hash}")
    print(f"ROOT aggiornato        : {STATE_FILE}")
    print(f"Chunk caricati ora     : {result['uploaded_chunk_count']}")
    print(f"Chunk già presenti     : {result['already_present_chunk_count']}")
    print(f"Catalogo               : python {Path(__file__).name} catalog")
    print(f"Ricostruzione          : python {Path(__file__).name} reconstruct")
    return 0


def cmd_catalog(args: argparse.Namespace) -> int:
    w3, rpc_url = connect_web3()
    state = maybe_finalize_pending_catalog(w3)
    root_hash = state.root_catalog_tx_hash
    if not root_hash:
        raise StoreError("sfs_root.txt non contiene ancora un ROOT")

    entries = collect_catalog_page(
        w3,
        root_hash,
        start_index=max(1, int(args.start)),
        page_size=max(1, int(args.limit)),
        search_term=args.search,
    )
    print(f"Rete                   : {NETWORK_NAME}")
    print(f"RPC                    : {rpc_url}")
    print(f"ROOT                   : {root_hash}")
    print_catalog_entries(entries, title="\n=== Catalogo ===")
    print("\nPuoi usare: python script.py inspect <indice>  oppure  python script.py reconstruct <indice>")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    w3, rpc_url = connect_web3()
    _state = maybe_finalize_pending_catalog(w3)
    manifest_tx_hash = resolve_manifest_tx_hash(
        w3,
        args.selector,
        search_term=args.search,
        interactive_action_label="inspect",
    )

    manifest_tx, manifest, _payload = load_manifest_from_chain(w3, manifest_tx_hash)
    summary = manifest_summary(manifest)

    print(f"Rete                   : {NETWORK_NAME}")
    print(f"RPC                    : {rpc_url}")
    print(f"Manifest tx hash       : {manifest_tx_hash}")
    print(f"Uploader               : {manifest_tx['from']}")
    print(f"Manifest nonce         : {manifest_tx['nonce']}")
    print(f"Manifest block         : {manifest_tx['blockNumber']}")
    print(f"File                   : {summary['file_name']}")
    print(f"MIME                   : {summary['mime_type']}")
    print(f"Compressione           : {'si' if summary['compressed'] else 'no'}")
    print(f"Dimensione originale   : {summary['original_size']} bytes")
    print(f"Dimensione memorizzata : {summary['stored_size']} bytes")
    print(f"Chunk size plaintext   : {summary['plain_chunk_size']} bytes")
    print(f"Chunk totali           : {summary['total_chunks']}")
    print(f"File ID                : {summary['file_id']}")
    return 0


def cmd_reconstruct(args: argparse.Namespace) -> int:
    w3, rpc_url = connect_web3()
    _state = maybe_finalize_pending_catalog(w3)
    _account, private_key = load_or_create_wallet()

    manifest_tx_hash = resolve_manifest_tx_hash(
        w3,
        args.selector,
        search_term=args.search,
        interactive_action_label="reconstruct",
    )
    out_path = Path(args.out).expanduser().resolve() if args.out else None

    manifest, chunk_map = scan_chunks_from_manifest(w3, manifest_tx_hash)
    if out_path is None:
        out_path = SCRIPT_DIR / ("RESTORED_" + manifest["file_name"])

    decrypt_and_reassemble_to_file(private_key, manifest, chunk_map, out_path)

    print(f"Rete                   : {NETWORK_NAME}")
    print(f"RPC                    : {rpc_url}")
    print(f"Manifest tx hash       : {manifest_tx_hash}")
    print(f"Chunk trovati          : {len(chunk_map)}/{manifest['total_chunks']}")
    print(f"File ripristinato      : {out_path}")
    print(f"SHA-256 finale         : {manifest['original_sha256']}")
    return 0


def cmd_sweep(args: argparse.Namespace) -> int:
    w3, rpc_url = connect_web3()
    _ = maybe_finalize_pending_catalog(w3)
    account, _private_key = load_or_create_wallet()

    to_address = Web3.to_checksum_address(args.to_address)
    balance = int(w3.eth.get_balance(account.address))
    max_fee_per_gas, max_priority_fee_per_gas = suggested_eip1559_fees(w3)
    fee = SWEEP_GAS_LIMIT * max_fee_per_gas

    if balance <= fee:
        raise StoreError(
            f"Saldo insufficiente per sweep. Saldo: {format_eth(balance)} ETH, fee stimata: {format_eth(fee)} ETH"
        )

    value = balance - fee
    nonce = int(w3.eth.get_transaction_count(account.address, "pending"))

    tx = build_type2_tx(
        from_address=account.address,
        to_address=to_address,
        nonce=nonce,
        value_wei=value,
        gas_limit=SWEEP_GAS_LIMIT,
        max_fee_per_gas=max_fee_per_gas,
        max_priority_fee_per_gas=max_priority_fee_per_gas,
        data_bytes=b"",
    )

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(get_raw_signed_tx(signed))

    print(f"Rete      : {NETWORK_NAME}")
    print(f"RPC       : {rpc_url}")
    print(f"From      : {account.address}")
    print(f"To        : {to_address}")
    print(f"Value     : {format_eth(value)} ETH")
    print(f"Max fee   : {format_eth(fee)} ETH")
    print(f"TX hash   : {tx_hash.hex()}")
    return 0


# --------------------
# Parser CLI
# --------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Salva file cifrati a chunk nel campo data di transazioni Sepolia, mantiene un catalogo flat "
            "append-only on-chain e usa sfs_root.txt come stato locale minimo."
        )
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_wallet = sub.add_parser("wallet", help="Mostra wallet, saldo, public key e QR")
    p_wallet.add_argument("--no-qr", action="store_true", help="Non mostrare il QR ASCII")
    p_wallet.set_defaults(func=cmd_wallet)

    p_status = sub.add_parser("status", help="Mostra ROOT e stato pendente locale")
    p_status.set_defaults(func=cmd_status)

    p_estimate = sub.add_parser("estimate", help="Stima chunk, tx e ETH testnet richiesti")
    p_estimate.add_argument("file")
    p_estimate.add_argument("--chunk-size", type=int, default=None, help="Chunk size plaintext. Ometti per auto")
    p_estimate.set_defaults(func=cmd_estimate)

    p_upload = sub.add_parser("upload", help="Cifra, carica il file e aggiorna il catalogo/root")
    p_upload.add_argument("file")
    p_upload.add_argument("--chunk-size", type=int, default=None, help="Chunk size plaintext. Ometti per auto")
    p_upload.add_argument("--parallel", type=int, default=DEFAULT_PARALLELISM, help=f"Chunk in volo per batch (max {MAX_PARALLELISM})")
    p_upload.set_defaults(func=cmd_upload)

    p_catalog = sub.add_parser("catalog", help="Mostra una pagina del catalogo o cerca per sottostringa")
    p_catalog.add_argument("--search", help="Sottostringa nel nome file")
    p_catalog.add_argument("--start", type=int, default=1, help="Indice catalogo da cui iniziare (1 = file più recente)")
    p_catalog.add_argument("--limit", type=int, default=DEFAULT_CATALOG_PAGE_SIZE, help="Numero massimo di risultati")
    p_catalog.set_defaults(func=cmd_catalog)

    p_inspect = sub.add_parser("inspect", help="Legge un manifest. Senza argomenti apre il browser catalogo")
    p_inspect.add_argument("selector", nargs="?", help="Manifest tx hash oppure indice catalogo")
    p_inspect.add_argument("--search", help="Avvia il browser catalogo con una ricerca iniziale")
    p_inspect.set_defaults(func=cmd_inspect)

    p_reconstruct = sub.add_parser(
        "reconstruct",
        help="Ricostruisce e decifra un file. Senza argomenti apre il browser catalogo",
    )
    p_reconstruct.add_argument("selector", nargs="?", help="Manifest tx hash oppure indice catalogo")
    p_reconstruct.add_argument("--search", help="Avvia il browser catalogo con una ricerca iniziale")
    p_reconstruct.add_argument("--out")
    p_reconstruct.set_defaults(func=cmd_reconstruct)

    p_sweep = sub.add_parser("sweep", help="Invia tutto il saldo disponibile meno il gas a un address")
    p_sweep.add_argument("to_address")
    p_sweep.set_defaults(func=cmd_sweep)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("Interrotto.")
        return 130
    except StoreError as exc:
        print(f"Errore: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

# File: tools/gnoman.py  # L001
# -*- coding: utf-8 -*-  # L002
"""
GNOMAN — Gnosis + Manager
Standalone CLI for:
- Gnosis Safe (admin + exec + 24h hold toggle)
- Wallets (HD + hidden tree; import/export/derive)
- Key Manager (keyring + .env.secure mirror)
Forensic logging: local, append-only JSONL with hash chaining.
Secrets priority: keyring > .env.secure > env > prompt → persist to keyring + .env.secure.
"""  # L010

import os  # L011
import sys  # L012
import json  # L013
import stat  # L014
import time  # L015
import hmac  # L016
import hashlib  # L017
import getpass  # L018
import logging  # L019
from pathlib import Path  # L020
from typing import Dict, Any, List, Optional, Tuple  # L021
from decimal import Decimal, getcontext  # L022
getcontext().prec = 28  # L023

from dotenv import load_dotenv  # L024
from hexbytes import HexBytes  # L025
from web3 import Web3  # L026
from web3.exceptions import ContractLogicError  # L027
from eth_account import Account  # L028
from eth_account.signers.local import LocalAccount  # L029
Account.enable_unaudited_hdwallet_features()  # L030

# Minimal ERC20 ABI (symbol/decimals/transfer)  # L031
ERC20_ABI_MIN = [
    {"constant": False, "inputs": [{"name": "_to","type":"address"},{"name":"_value","type":"uint256"}],
     "name": "transfer","outputs": [{"name":"","type":"bool"}],"type":"function"},
    {"constant": True, "inputs": [], "name": "symbol", "outputs":[{"name":"","type":"string"}], "type":"function"},
    {"constant": True, "inputs": [], "name": "decimals","outputs":[{"name":"","type":"uint8"}], "type":"function"},
]  # L037

# Optional keyring  # L038
try:
    import keyring  # L039
except ImportError:
    keyring = None  # L041

# ───────── Logger (line-numbered) ─────────  # L043
def _setup_logger() -> logging.Logger:  # L044
    lg = logging.getLogger("gnoman")  # L045
    lg.setLevel(logging.INFO)  # L046
    fmt = logging.Formatter("%(asctime)s - gnoman - %(levelname)s - L%(lineno)d - %(funcName)s - %(message)s")  # L047
    sh = logging.StreamHandler(sys.stdout)  # L048
    sh.setFormatter(fmt); sh.setLevel(logging.INFO)  # L049
    fh = logging.FileHandler("gnoman.log", encoding="utf-8")  # L050
    fh.setFormatter(fmt); fh.setLevel(logging.INFO)  # L051
    if not lg.handlers:
        lg.addHandler(sh); lg.addHandler(fh)  # L053
    lg.info("✅ Logger initialized (writing to gnoman.log)")  # L054
    return lg  # L055

logger = _setup_logger()  # L057

# ───────── Splash (banner stays exactly as you had it) ─────────  # L059
def splash() -> None:  # L050
    banner = r"""  # L051
 ██████╗ ███╗   ██╗ ██████╗ ███╗   ███╗ █████╗ ███╗   ██╗
██╔════╝ ████╗  ██║██╔═══██╗████╗ ████║██╔══██╗████╗  ██║
██║  ███╗██╔██╗ ██║██║   ██║██╔████╔██║███████║██╔██╗ ██║
██║   ██║██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══██║██║╚██╗██║
╚██████╔╝██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██║  ██║██║ ╚████║
 ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                          
        GNOMAN — Safe • Wallet • Keys • Hold24h
        © 2025 Christopher Hirschauer — All Rights Reserved
        Licensed under GNOMAN License (see LICENSE.md)
───────────────────────────────────────────────────────────
"""  # L062
    print(banner)  # L063
    logger.info("GNOMAN startup banner displayed.")  # log splash event
    logger.info("© 2025 Christopher Hirschauer — All Rights Reserved")  # log copyright
    logger.info("Licensed under GNOMAN License (see LICENSE.md)")  # log license

splash()  # L074
# ───────── Forensic Ledger (tamper-evident JSONL) ─────────  # L100
AUDIT_FILE = Path("gnoman_audit.jsonl")  # L101
AUDIT_HMAC_KEY_ENV = "AUDIT_HMAC_KEY"    # L102

def _load_last_hash() -> str:  # L103
    if not AUDIT_FILE.exists(): return ""  # L104
    try:
        with AUDIT_FILE.open("rb") as f:
            f.seek(0, os.SEEK_END); size = f.tell()
            # scan backwards for last newline
            step = min(4096, size); pos = size
            buf = b""
            while pos > 0:
                pos = max(0, pos - step); f.seek(pos); chunk = f.read(min(step, pos+step))
                buf = chunk + buf
                if b"\n" in buf: break
            line = buf.splitlines()[-1]
            rec = json.loads(line.decode("utf-8"))
            return rec.get("hash","")
    except Exception:
        return ""

def _get_hmac_key() -> Optional[bytes]:  # L121
    # keyring > .env.secure > env
    key = None
    if keyring:
        try:
            key = keyring.get_password(_service_name(), AUDIT_HMAC_KEY_ENV)
        except Exception:
            key = None
    if not key:
        key = _env_secure_load().get(AUDIT_HMAC_KEY_ENV) or os.getenv(AUDIT_HMAC_KEY_ENV)
    return key.encode("utf-8") if key else None

def _calc_record_hash(prev_hash: str, payload: Dict[str, Any]) -> str:  # L131
    body = json.dumps({"prev": prev_hash, **payload}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(body).hexdigest()

def _calc_record_hmac(hmac_key: bytes, payload_with_hash: Dict[str, Any]) -> str:  # L136
    body = json.dumps(payload_with_hash, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hmac.new(hmac_key, body, hashlib.sha256).hexdigest()

def audit_log(action: str, params: Dict[str, Any], ok: bool, result: Dict[str, Any]) -> None:  # L141
    rec = {
        "ts": time.time(),
        "action": action,
        "params": params,
        "ok": ok,
        "result": result,
    }
    prev = _load_last_hash()
    rec_hash = _calc_record_hash(prev, rec)
    out = {"prev": prev, **rec, "hash": rec_hash}
    hkey = _get_hmac_key()
    if hkey:
        out["hmac"] = _calc_record_hmac(hkey, out)
    with AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(out, ensure_ascii=False) + "\n")
# ───────── Secrets & .env.secure helpers ─────────  # L170
ENV_SECURE_PATH = Path(".env.secure")  # L171
_SERVICE_NAME: Optional[str] = None    # L172

def _service_name() -> str:  # L173
    global _SERVICE_NAME
    if _SERVICE_NAME: return _SERVICE_NAME
    s = input("Enter keyring service name [default=gnoman]: ").strip() or "gnoman"
    _SERVICE_NAME = s
    return s

def _env_secure_load() -> Dict[str, str]:  # L181
    if not ENV_SECURE_PATH.exists(): return {}
    try:
        lines = ENV_SECURE_PATH.read_text().splitlines()
        pairs = [l.split("=",1) for l in lines if "=" in l]
        return {k: v for k, v in pairs}
    except Exception as e:
        logger.error(f"❌ .env.secure read failed: {e}", exc_info=True)
        return {}

def _env_secure_write(key: str, value: str) -> None:  # L192
    envs = _env_secure_load(); envs[key] = value
    ENV_SECURE_PATH.write_text("\n".join(f"{k}={v}" for k,v in envs.items()) + "\n")
    try: ENV_SECURE_PATH.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except Exception as e: logger.warning(f"⚠️ chmod .env.secure: {e}")
    logger.info(f"💾 Wrote {key} to .env.secure")

def _get_secret(key: str, prompt_text: Optional[str]=None, sensitive: bool=True) -> str:  # L199
    # keyring
    if keyring:
        try:
            v = keyring.get_password(_service_name(), key)
            if v: return v
        except Exception:
            pass
    # .env.secure
    v = _env_secure_load().get(key)
    if v: return v
    # env
    v = os.getenv(key)
    if v: return v
    # prompt
    if prompt_text:
        entered = getpass.getpass(prompt_text).strip() if sensitive else input(prompt_text).strip()
        if entered:
            if keyring:
                try: keyring.set_password(_service_name(), key, entered)
                except Exception: pass
            _env_secure_write(key, entered)
            return entered
    raise RuntimeError(f"Missing required secret: {key}")

def _set_secret(key: str, value: str) -> None:  # L221
    if keyring:
        try: keyring.set_password(_service_name(), key, value)
        except Exception: pass
    _env_secure_write(key, value)

# ───────── Web3 bootstrap (retry until connected, no surprise exit) ─────────  # L227

def _init_web3() -> Web3:  # L228
    load_dotenv(".env"); load_dotenv(".env.secure")
    while True:
        try:
            rpc = _get_secret("RPC_URL", "Enter RPC_URL: ", sensitive=False)
        except RuntimeError:
            rpc = input("Enter RPC_URL: ").strip()
            if rpc:
                _set_secret("RPC_URL", rpc)
        w3 = Web3(Web3.HTTPProvider(rpc))
        if w3.is_connected():
            chain_id = os.getenv("CHAIN_ID", "1").strip()
            logger.info(f"🌐 Web3 connected | chain_id={chain_id}")
            audit_log("web3_connect", {"rpc": rpc[:12]+"…", "chain_id": chain_id}, True, {})
            return w3
        print("❌ Could not connect to RPC. Enter a different URL.")
        audit_log("web3_connect", {"rpc": rpc[:12]+"…"}, False, {"error": "connect_failed"})

w3 = _init_web3()  # L250

# ───────── 24h Hold (local) ─────────  # L260
HOLD_FILE = Path("safe_hold.json")  # L261
def _hold_load() -> Dict[str, Any]:
    if not HOLD_FILE.exists(): return {}
    try: return json.loads(HOLD_FILE.read_text())
    except Exception: return {}
def _hold_save(d: Dict[str, Any]) -> None:
    HOLD_FILE.write_text(json.dumps(d, indent=2))

# ───────── Safe Context ─────────  # L271
class SafeCtx:
    def __init__(self) -> None:
        self.addr: Optional[str] = None
        self.contract = None
        self.owner: Optional[LocalAccount] = None
        self.hold = _hold_load()

SAFE = SafeCtx()  # L281

def _cs(addr: str) -> str: return Web3.to_checksum_address(addr)  # L283

def safe_init() -> None:  # L285
    if SAFE.contract and SAFE.owner and SAFE.addr: return
    # Safe address
    try:
        saddr = _get_secret("GNOSIS_SAFE", "Enter Safe address: ", sensitive=False)
    except RuntimeError:
        saddr = input("Enter Safe address: ").strip()
        if not saddr: raise RuntimeError("Safe address required.")
        _set_secret("GNOSIS_SAFE", saddr)
    SAFE.addr = _cs(saddr)
    # Owner PK
    try:
        pk = _get_secret("OWNER_PRIVATE_KEY", "Enter OWNER_PRIVATE_KEY (hex, no 0x): ", sensitive=True)
    except RuntimeError:
        pk = getpass.getpass("Enter OWNER_PRIVATE_KEY (hex, no 0x): ").strip()
        if pk and not pk.startswith("0x"): pk = "0x"+pk
        _set_secret("OWNER_PRIVATE_KEY", pk)
    if not pk.startswith("0x"): pk = "0x"+pk
    SAFE.owner = Account.from_key(pk)  # type: ignore
    # ABI
    abi_path = os.getenv("GNOSIS_SAFE_ABI", "./abi/GnosisSafe.json").strip()
    with open(abi_path, "r") as f:
        data = json.load(f)
    abi = data["abi"] if isinstance(data, dict) and "abi" in data else data
    SAFE.contract = w3.eth.contract(address=SAFE.addr, abi=abi)
    logger.info(f"🔧 SAFE initialized | address={SAFE.addr} | owner={SAFE.owner.address}")
    audit_log("safe_init", {"safe": SAFE.addr, "owner": SAFE.owner.address}, True, {})

def _safe_nonce() -> int:
    return SAFE.contract.functions.nonce().call()

def _apply_24h_hold() -> bool:
    """Returns True if allowed to proceed now; False if placed/on hold."""
    key = f"{SAFE.addr}:{_safe_nonce()}"
    now = int(time.time())
    hold_until = int(SAFE.hold.get(key, 0))
    if hold_until == 0:
        SAFE.hold[key] = now + 86400
        _hold_save(SAFE.hold)
        print("⏸️ Transaction placed on 24h hold. Re-run after it expires.")
        audit_log("hold_place", {"key": key, "until": SAFE.hold[key]}, True, {})
        return False
    if now < hold_until:
        left = hold_until - now
        print(f"⏳ Still on hold ({left//3600}h {(left%3600)//60}m left).")
        audit_log("hold_block", {"key": key, "left": left}, True, {})
        return False
    return True

def _send_tx(tx: Dict[str, Any]) -> Optional[str]:
    try:
        tx.setdefault("chainId", int(os.getenv("CHAIN_ID","1") or "1"))
        tx.setdefault("nonce", w3.eth.get_transaction_count(SAFE.owner.address))
        if "maxFeePerGas" not in tx or "maxPriorityFeePerGas" not in tx:
            base = w3.eth.gas_price
            tx["maxPriorityFeePerGas"] = Web3.to_wei(1, "gwei")
            tx["maxFeePerGas"] = max(base * 2, Web3.to_wei(3, "gwei"))
        if "gas" not in tx:
            try:
                est = w3.eth.estimate_gas({k:v for k,v in tx.items() if k in ("from","to","value","data")})
                tx["gas"] = int(est) + 100000
            except Exception:
                tx["gas"] = 800000
        signed = w3.eth.account.sign_transaction(tx, SAFE.owner.key)
        txh = w3.eth.send_raw_transaction(signed.rawTransaction)
        rcpt = w3.eth.wait_for_transaction_receipt(txh)
        ok = (rcpt.status == 1)
        print(("✅" if ok else "❌") + f" tx={txh.hex()} block={rcpt.blockNumber} gasUsed={rcpt.gasUsed}")
        audit_log("send_tx", {"to": tx.get("to"), "value": int(tx.get("value",0))}, ok, {"hash": txh.hex(), "block": rcpt.blockNumber, "gasUsed": rcpt.gasUsed})
        return txh.hex()
    except Exception as e:
        print(f"❌ Transaction failed: {e}")
        audit_log("send_tx", {"to": tx.get("to")}, False, {"error": str(e)})
        return None

def safe_show_info() -> None:
    owners = [_cs(o) for o in SAFE.contract.functions.getOwners().call()]
    threshold = SAFE.contract.functions.getThreshold().call()
    nonce = _safe_nonce()
    eth = Decimal(w3.from_wei(w3.eth.get_balance(SAFE.addr), "ether"))
    out = {"safe": SAFE.addr, "owners": owners, "threshold": threshold, "nonce": nonce, "eth_balance": str(eth)}
    print(json.dumps(out, indent=2))
    audit_log("safe_info", {}, True, out)

def safe_fund_eth() -> None:
    amt = input("Amount ETH to send to Safe: ").strip()
    try: v = Decimal(amt)
    except Exception: print("Invalid amount."); return
    tx = {"from": SAFE.owner.address, "to": SAFE.addr, "value": int(Web3.to_wei(v, "ether")), "data": b""}
    if _apply_24h_hold(): _send_tx(tx)

def safe_send_erc20() -> None:
    token_addr = input("ERC20 token address: ").strip()
    try: token = w3.eth.contract(address=_cs(token_addr), abi=ERC20_ABI_MIN)
    except Exception: print("Invalid token."); return
    try: sym = token.functions.symbol().call()
    except Exception: sym = "UNKNOWN"
    try: dec = token.functions.decimals().call()
    except Exception: dec = 18
    amt = input(f"Amount of {sym}: ").strip()
    try: v = Decimal(amt)
    except Exception: print("Invalid amount."); return
    raw = int(v * (10 ** dec))
    data = token.encodeABI(fn_name="transfer", args=[SAFE.addr, raw])
    tx = {"from": SAFE.owner.address, "to": token.address, "value": 0, "data": Web3.to_bytes(hexstr=data)}
    if _apply_24h_hold(): _send_tx(tx)

# On-chain guard toggle (DelayGuard or similar)
def safe_toggle_guard(enable: bool) -> None:
    try:
        safe_assert_owner()
    except Exception as e:
        print(f"❌ {e}"); return
    if enable:
        guard_addr = _get_secret("SAFE_DELAY_GUARD", "Enter DelayGuard address: ", sensitive=False)
        try: g = _cs(guard_addr)
        except Exception: print("Invalid address."); return
        data = SAFE.contract.encodeABI(fn_name="setGuard", args=[g])
        tx = {"from": SAFE.owner.address, "to": SAFE.addr, "value": 0, "data": Web3.to_bytes(hexstr=data)}
        _send_tx(tx); _set_secret("SAFE_DELAY_GUARD", g)
        print(f"🛡 Guard enabled at {g}")
        audit_log("guard_enable", {"guard": g}, True, {})
    else:
        zero = _cs("0x0000000000000000000000000000000000000000")
        data = SAFE.contract.encodeABI(fn_name="setGuard", args=[zero])
        tx = {"from": SAFE.owner.address, "to": SAFE.addr, "value": 0, "data": Web3.to_bytes(hexstr=data)}
        _send_tx(tx)
        print("🛡 Guard disabled.")
        audit_log("guard_disable", {}, True, {})

def safe_show_guard() -> None:
    try:
        g = SAFE.contract.functions.getGuard().call()
        active = int(g,16) != 0
        msg = _cs(g) if active else "none"
        print(f"Guard: {msg}")
        audit_log("guard_show", {}, True, {"guard": msg})
    except Exception as e:
        print(f"❌ getGuard failed: {e}")
        audit_log("guard_show", {}, False, {"error": str(e)})

def safe_assert_owner() -> None:
    owners = [_cs(o) for o in SAFE.contract.functions.getOwners().call()]
    if _cs(SAFE.owner.address) not in owners:
        raise Exception("Signer is not a Safe owner.")
def safe_add_owner() -> None:
    addr = input("New owner address: ").strip()
    try: a = _cs(addr)
    except Exception: print("Invalid address."); return
    thr = SAFE.contract.functions.getThreshold().call()
    data = SAFE.contract.encodeABI(fn_name="addOwnerWithThreshold", args=[a, thr])
    tx = {"from": SAFE.owner.address, "to": SAFE.addr, "value": 0, "data": Web3.to_bytes(hexstr=data)}
    if _apply_24h_hold(): _send_tx(tx); audit_log("owner_add", {"owner": a}, True, {})

def safe_remove_owner() -> None:
    rm = input("Owner to remove: ").strip()
    prev = input("Prev owner (linked-list): ").strip()
    try: rm_cs = _cs(rm); prev_cs = _cs(prev)
    except Exception: print("Invalid address."); return
    thr = SAFE.contract.functions.getThreshold().call()
    data = SAFE.contract.encodeABI(fn_name="removeOwner", args=[prev_cs, rm_cs, thr])
    tx = {"from": SAFE.owner.address, "to": SAFE.addr, "value": 0, "data": Web3.to_bytes(hexstr=data)}
    if _apply_24h_hold(): _send_tx(tx); audit_log("owner_remove", {"owner": rm_cs, "prev": prev_cs}, True, {})

def safe_change_threshold() -> None:
    val = input("New threshold (>0): ").strip()
    try: thr = int(val); assert thr > 0
    except Exception: print("Invalid threshold."); return
    data = SAFE.contract.encodeABI(fn_name="changeThreshold", args=[thr])
    tx = {"from": SAFE.owner.address, "to": SAFE.addr, "value": 0, "data": Web3.to_bytes(hexstr=data)}
    if _apply_24h_hold(): _send_tx(tx); audit_log("threshold_change", {"threshold": thr}, True, {})

def safe_exec() -> None:
    to_in = input(" to (target address): ").strip()
    try: to_addr = _cs(to_in)
    except Exception: print("Bad address."); return
    val = input(" value (ETH, default 0): ").strip()
    value = int(Web3.to_wei(Decimal(val), "ether")) if val else 0
    data_hex = input(" data (0x…): ").strip()
    data = b"" if not data_hex else Web3.to_bytes(hexstr=data_hex)
    op = int(input(" operation (0=CALL,1=DELEGATECALL; default 0): ").strip() or "0")
    if op not in (0,1): print("Invalid op"); return
    nonce = _safe_nonce()
    try:
        txh = SAFE.contract.functions.getTransactionHash(
            to_addr, value, data, op, 0, 0, 0, _cs("0x0000000000000000000000000000000000000000"),
            _cs("0x0000000000000000000000000000000000000000"), nonce
        ).call()
    except ContractLogicError as e:
        print(f"getTransactionHash failed: {e}")
        audit_log("safe_get_hash", {"to": to_addr}, False, {"error": str(e)})
        return
    sig = Account.sign_hash(message_hash=txh, private_key=SAFE.owner.key)
    r = sig.r.to_bytes(32,"big"); s = sig.s.to_bytes(32,"big"); v = (sig.v).to_bytes(1,"big")
    packed = r + s + v
    exec_data = SAFE.contract.encodeABI(fn_name="execTransaction",
        args=[to_addr, value, data, op, 0, 0, 0,
              _cs("0x0000000000000000000000000000000000000000"),
              _cs("0x0000000000000000000000000000000000000000"), packed])
    tx = {"from": SAFE.owner.address, "to": SAFE.addr, "value": 0, "data": Web3.to_bytes(hexstr=exec_data)}
    if _apply_24h_hold():
        _send_tx(tx)
        audit_log("safe_exec", {"to": to_addr, "value": value, "op": op}, True, {"hash32": "0x"+HexBytes(txh).hex()})
# ───────── Wallet Manager (HD + hidden tree) ─────────  # L480
class WalletCtx:
    def __init__(self) -> None:
        self.mnemonic: Optional[str] = None
        self.default_path = "m/44'/60'/0'/0/0"
        self.hidden_root = "m/44'/60'/1337'/0"
        self.discovered: List[Tuple[str, str]] = []
        self.labels: Dict[str, str] = {}
        self.label_file = Path("wallet_labels.json")
        if self.label_file.exists():
            try: self.labels = json.loads(self.label_file.read_text())
            except Exception: self.labels = {}

WAL = WalletCtx()

def wal_import_mnemonic() -> None:
    phrase = getpass.getpass("Enter mnemonic: ").strip()
    if not phrase: print("❌ Empty mnemonic."); return
    WAL.mnemonic = phrase
    _set_secret("WALLET_MNEMONIC", phrase)
    addr, _ = wal_derive(WAL.default_path)
    print(f"✅ Default acct0 = {addr}")
    audit_log("wallet_import_mnemonic", {}, True, {"acct0": addr})

def wal_derive(path: str) -> Tuple[str, Optional[LocalAccount]]:
    if not WAL.mnemonic: return ("", None)
    try:
        acct = Account.from_mnemonic(WAL.mnemonic, account_path=path)  # type: ignore
        return (_cs(acct.address), acct)
    except Exception as e:
        logger.error(f"derive failed: {e}", exc_info=True)
        audit_log("wallet_derive", {"path": path}, False, {"error": str(e)})
        return ("", None)

def wal_scan(n: int, hidden: bool=False) -> None:
    base = WAL.hidden_root if hidden else "m/44'/60'/0'/0"
    out: List[Tuple[str, str]] = []
    for i in range(n):
        path = f"{base}/{i}"
        addr, _ = wal_derive(path)
        if addr: out.append((path, addr))
    WAL.discovered = out
    print(f"🔍 Scanned {n} ({'hidden' if hidden else 'default'})")
    for p,a in out: print(f"  {p} -> {a}")
    audit_log("wallet_scan", {"hidden": hidden, "n": n}, True, {"count": len(out)})

def wal_export_discovered() -> None:
    data = {"mnemonic_present": WAL.mnemonic is not None,
            "discovered": [{"path": p, "address": a, "label": WAL.labels.get(a,"")} for p,a in WAL.discovered]}
    Path("wallet_export.json").write_text(json.dumps(data, indent=2))
    print("📤 Exported -> wallet_export.json")
    audit_log("wallet_export", {}, True, {"file": "wallet_export.json"})

def wal_label() -> None:
    addr = input("Address to label: ").strip()
    if not addr: return
    label = input("Label: ").strip()
    WAL.labels[addr] = label
    WAL.label_file.write_text(json.dumps(WAL.labels, indent=2))
    print(f"🏷️ {addr} => {label}")
    audit_log("wallet_label", {"addr": addr, "label": label}, True, {})
# ───────── Key Manager ─────────  # L560
def km_add() -> None:
    key = input("Secret key (e.g., RPC_URL): ").strip()
    if not key: print("Empty."); return
    val = getpass.getpass(f"Enter value for {key}: ").strip()
    if not val: print("Empty."); return
    if keyring:
        try: keyring.set_password(_service_name(), key, val)
        except Exception as e: logger.error(f"keyring set: {e}", exc_info=True)
    _env_secure_write(key, val)
    print("✅ Stored to keyring + .env.secure")
    audit_log("km_set", {"key": key}, True, {})

def km_get() -> None:
    key = input("Secret key: ").strip()
    if not key: return
    val = None
    if keyring:
        try: val = keyring.get_password(_service_name(), key)
        except Exception: val = None
    if not val: val = _env_secure_load().get(key) or os.getenv(key)
    if val:
        print(f"{key} = {val}")
        audit_log("km_get", {"key": key}, True, {"found": True})
    else:
        print("Not found.")
        audit_log("km_get", {"key": key}, False, {"found": False})

def km_del() -> None:
    key = input("Secret key to delete: ").strip()
    if not key: return
    ok = True
    if keyring:
        try: keyring.delete_password(_service_name(), key)
        except Exception: ok = False
    print("✅ Deleted from keyring (if present).")
    audit_log("km_del", {"key": key}, ok, {})

def km_list_env() -> None:
    envs = _env_secure_load()
    if not envs: print("No entries."); return
    print("=== .env.secure ===")
    for k,v in envs.items():
        print(f"{k} = {v[:6]}…")
    audit_log("km_list_env", {"count": len(envs)}, True, {})

def km_sync_env() -> None:
    envs = _env_secure_load()
    if keyring:
        for k,v in envs.items():
            try: keyring.set_password(_service_name(), k, v)
            except Exception: pass
    print(f"✅ Synced {len(envs)} into keyring")
    audit_log("km_sync_env", {"count": len(envs)}, True, {})
# ───────── Menus ─────────  # L620
def safe_menu() -> None:
    try:
        safe_init()
    except Exception as e:
        print(f"❌ {e}"); return
    while True:
        print("\n┌─ SAFE MANAGER ───────────────────────────────────────────")
        print("│ 1) Show Safe info")
        print("│ 2) Fund Safe with ETH")
        print("│ 3) Send ERC20 to Safe")
        print("│ 4) Execute Safe transaction")
        print("│ 5) Admin: Add owner")
        print("│ 6) Admin: Remove owner")
        print("│ 7) Admin: Change threshold")
        print("│ 8) 24h Hold: (local) status toggle")
        print("│ 9) Guard: Show")
        print("│ 10) Guard: Enable (setGuard)")
        print("│ 11) Guard: Disable")
        print("│ 0) Back")
        print("└──────────────────────────────────────────────────────────")
        ch = input("> ").strip()
        try:
            if ch == "1": safe_show_info()
            elif ch == "2": safe_fund_eth()
            elif ch == "3": safe_send_erc20()
            elif ch == "4": safe_exec()
            elif ch == "5": safe_add_owner()
            elif ch == "6": safe_remove_owner()
            elif ch == "7": safe_change_threshold()
            elif ch == "8":
                # toggle local hold flag by flipping a config bit
                # (hold is enforced per-tx in _apply_24h_hold anyway)
                current = bool(_env_secure_load().get("LOCAL_HOLD_ENABLED","0") == "1")
                new = "0" if current else "1"
                _env_secure_write("LOCAL_HOLD_ENABLED", new)
                print(f"⏳ Local 24h hold now {'ENABLED' if new=='1' else 'DISABLED'}")
                audit_log("hold_toggle_local", {"enabled": new=="1"}, True, {})
            elif ch == "9": safe_show_guard()
            elif ch == "10": safe_toggle_guard(True)
            elif ch == "11": safe_toggle_guard(False)
            elif ch == "0": return
            else: print("Invalid.")
        except KeyboardInterrupt:
            print("\n⚠️ Interrupted.")
        except Exception as e:
            logger.error(f"Safe menu error: {e}", exc_info=True)
            audit_log("safe_menu_error", {"choice": ch}, False, {"error": str(e)})
            print(f"Error: {e}. See gnoman.log.")

def wallet_menu() -> None:
    # warm mnemonic from secrets if present
    if not WAL.mnemonic:
        seed = _env_secure_load().get("WALLET_MNEMONIC")
        if not seed and keyring:
            try: seed = keyring.get_password(_service_name(), "WALLET_MNEMONIC")
            except Exception: seed = None
        WAL.mnemonic = seed
    while True:
        print("\n┌─ WALLET MANAGER ─────────────────────────────────────────")
        print("│ 1) Import mnemonic")
        print("│ 2) Scan default accounts")
        print("│ 3) Scan hidden HD tree")
        print("│ 4) Derive specific path")
        print("│ 5) Export discovered addresses")
        print("│ 6) Label address")
        print("│ 0) Back")
        print("└──────────────────────────────────────────────────────────")
        ch = input("> ").strip()
        try:
            if ch == "1": wal_import_mnemonic()
            elif ch == "2":
                n = int(input("How many accounts (default=5): ").strip() or "5")
                wal_scan(n, hidden=False)
            elif ch == "3":
                n = int(input("How many hidden accounts (default=5): ").strip() or "5")
                wal_scan(n, hidden=True)
            elif ch == "4":
                path = input("Path (e.g., m/44'/60'/0'/0/1): ").strip()
                a,_ = wal_derive(path); print(f"{path} -> {a}")
            elif ch == "5": wal_export_discovered()
            elif ch == "6": wal_label()
            elif ch == "0": return
            else: print("Invalid.")
        except KeyboardInterrupt:
            print("\n⚠️ Interrupted.")
        except Exception as e:
            logger.error(f"Wallet menu error: {e}", exc_info=True)
            audit_log("wallet_menu_error", {"choice": ch}, False, {"error": str(e)})
            print(f"Error: {e}. See gnoman.log.")

def key_manager_menu() -> None:
    while True:
        print("\n┌─ KEY MANAGER ──────────────────────────────────────────")
        print("│ 1) Add/Update secret")
        print("│ 2) Retrieve secret")
        print("│ 3) Delete secret")
        print("│ 4) List .env.secure entries")
        print("│ 5) Sync .env.secure → keyring")
        print("│ 0) Back")
        print("└─────────────────────────────────────────────────────────")
        ch = input("> ").strip()
        try:
            if ch == "1": km_add()
            elif ch == "2": km_get()
            elif ch == "3": km_del()
            elif ch == "4": km_list_env()
            elif ch == "5": km_sync_env()
            elif ch == "0": return
            else: print("Invalid.")
        except KeyboardInterrupt:
            print("\n⚠️ Interrupted.")
        except Exception as e:
            logger.error(f"Key menu error: {e}", exc_info=True)
            audit_log("key_menu_error", {"choice": ch}, False, {"error": str(e)})
            print(f"Error: {e}. See gnoman.log.")

def main_menu() -> None:
    while True:
        print("\n┌─ GNOMAN MAIN MENU ──────────────────────────────────────")
        print("│ 1) Safe Manager (Gnosis Safe)")
        print("│ 2) Wallet Manager (HD / hidden trees)")
        print("│ 3) Key Manager (Secrets)")
        print("│ 0) Exit")
        print("└─────────────────────────────────────────────────────────")
        ch = input("> ").strip()
        try:
            if ch == "1": safe_menu()
            elif ch == "2": wallet_menu()
            elif ch == "3": key_manager_menu()
            elif ch == "0":
                print("👋 Goodbye.")
                return
            else: print("Invalid.")
        except KeyboardInterrupt:
            print("\n⚠️ Interrupted.")
        except Exception as e:
            logger.error(f"Main menu error: {e}", exc_info=True)
            audit_log("main_menu_error", {"choice": ch}, False, {"error": str(e)})
            print(f"Error: {e}. See gnoman.log.")

# ───────── Entrypoint ─────────  # L720
if __name__ == "__main__":
    try:
        splash()
        main_menu()
    finally:
        logger.info("🧹 gnoman exiting.")
        logging.shutdown()
# EOF

# File: tools/gnoman.py  # L001
# -*- coding: utf-8 -*-  # L002
"""
GNOMAN — Gnosis + Manager
Standalone CLI for:
- Gnosis Safe (admin + exec + 24h hold toggle)
- Wallets (HD + hidden tree; import/export/derive/mnemonic)
- Key Manager (keyring only)
Forensic logging: local, append-only JSONL with hash chaining.
Secrets priority: keyring > env > prompt → persist only to .env.
 GNOMAN — Proprietary Software
 Copyright (c) 2025 Christopher Hirschauer

 This software is proprietary and strictly controlled. No license exists
 unless Licensee holds an original GNOMAN License Agreement, executed in
 handwritten ink on physical paper and signed by the Licensor.

 Possession, use, or execution of this software without such signed paper
 license constitutes willful infringement and theft. Electronic signatures,
 scans, digital acknowledgments, or receipts do not create a license.

 All rights reserved. Unauthorized use is prohibited.
"""  # L020

import os  # L021
import sys  # L022
import json  # L023
import stat  # L024
import time  # L025
import hmac  # L026
import hashlib  # L027
import getpass  # L028
import logging  # L029
from pathlib import Path  # L030
from typing import Dict, Any, List, Optional, Tuple  # L031
from decimal import Decimal, getcontext  # L032
getcontext().prec = 28  # L033

from dotenv import load_dotenv  # L034
from hexbytes import HexBytes  # L035
from web3 import Web3  # L036
from web3.exceptions import ContractLogicError  # L037
from eth_account import Account  # L038
from eth_account.signers.local import LocalAccount  # L039
Account.enable_unaudited_hdwallet_features()  # L040

# Minimal ERC20 ABI (symbol/decimals/transfer)  # L041
ERC20_ABI_MIN = [
    {"constant": False, "inputs": [{"name": "_to","type":"address"},{"name":"_value","type":"uint256"}],
     "name": "transfer","outputs": [{"name":"","type":"bool"}],"type":"function"},
    {"constant": True, "inputs": [], "name": "symbol", "outputs":[{"name":"","type":"string"}], "type":"function"},
    {"constant": True, "inputs": [], "name": "decimals","outputs":[{"name":"","type":"uint8"}], "type":"function"},
]  # L047

# Optional keyring  # L048
try:
    import keyring  # L049
except ImportError:
    keyring = None  # L051


# ───────── Logger (line-numbered) ─────────  # L052
def _setup_logger() -> logging.Logger:  # L053
    lg = logging.getLogger("gnoman")  # L054
    lg.setLevel(logging.INFO)  # L055
    fmt = logging.Formatter("%(asctime)s - gnoman - %(levelname)s - L%(lineno)d - %(funcName)s - %(message)s")  # L056
    sh = logging.StreamHandler(sys.stdout)  # L057
    sh.setFormatter(fmt); sh.setLevel(logging.INFO)  # L058
    fh = logging.FileHandler("gnoman.log", encoding="utf-8")  # L059
    fh.setFormatter(fmt); fh.setLevel(logging.INFO)  # L060
    if not lg.handlers:
        lg.addHandler(sh); lg.addHandler(fh)  # L062
    lg.info("✅ Logger initialized (writing to gnoman.log)")  # L063
    return lg  # L064

logger = _setup_logger()  # L066


# ───────── Splash  ─────────  # L068
def splash() -> None:  # L069
    banner = r"""  # L070
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
"""  # L082
    print(banner)  # L083
    logger.info("GNOMAN startup banner displayed.")  # L084
    logger.info("© 2025 Christopher Hirschauer — All Rights Reserved")  # L085
    logger.info("Licensed under GNOMAN License (see LICENSE.md)")  # L086

splash()  # L088


# ───────── Forensic Ledger (tamper-evident JSONL) ─────────  # L089
AUDIT_FILE = Path("gnoman_audit.jsonl")  # L090
AUDIT_HMAC_KEY_ENV = "AUDIT_HMAC_KEY"    # L091
def _load_last_hash() -> str:  # L101
    if not AUDIT_FILE.exists(): return ""
    try:
        with AUDIT_FILE.open("rb") as f:
            f.seek(0, os.SEEK_END); size = f.tell()
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
    key = None
    if keyring:
        try:
            key = keyring.get_password(_service_name(), AUDIT_HMAC_KEY_ENV)
        except Exception:
            key = None
    if not key:
        key = os.getenv(AUDIT_HMAC_KEY_ENV)
    return key.encode("utf-8") if key else None

def _calc_record_hash(prev_hash: str, payload: Dict[str, Any]) -> str:  # L133
    body = json.dumps({"prev": prev_hash, **payload}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(body).hexdigest()

def _calc_record_hmac(hmac_key: bytes, payload_with_hash: Dict[str, Any]) -> str:  # L137
    body = json.dumps(payload_with_hash, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hmac.new(hmac_key, body, hashlib.sha256).hexdigest()

def audit_log(action: str, params: Dict[str, Any], ok: bool, result: Dict[str, Any]) -> None:  # L142
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


# ───────── Secrets & Keyring helpers ─────────  # L161
_SERVICE_NAME: Optional[str] = None    # L162

def _service_name() -> str:  # L163
    global _SERVICE_NAME
    if _SERVICE_NAME: return _SERVICE_NAME
    s = input("Enter keyring service name [default=gnoman]: ").strip() or "gnoman"
    _SERVICE_NAME = s
    return s

def _get_secret(key: str, prompt_text: Optional[str]=None, sensitive: bool=True) -> str:  # L170
    if keyring:
        try:
            v = keyring.get_password(_service_name(), key)
            if v: return v
        except Exception:
            pass
    v = os.getenv(key)
    if v: return v
    if prompt_text:
        entered = getpass.getpass(prompt_text).strip() if sensitive else input(prompt_text).strip()
        if entered:
            if keyring:
                try: keyring.set_password(_service_name(), key, entered)
                except Exception: pass
            return entered
    raise RuntimeError(f"Missing required secret: {key}")

def _set_secret(key: str, value: str) -> None:  # L188
    if keyring:
        try: keyring.set_password(_service_name(), key, value)
        except Exception: pass

def _env_load() -> Dict[str, str]:
    """Load values from .env (flat key=value)."""
    path = Path(".env")
    if not path.exists():
        return {}
    try:
        lines = path.read_text().splitlines()
        pairs = [l.split("=", 1) for l in lines if "=" in l]
        return {k: v for k, v in pairs}
    except Exception as e:
        logger.error(f"❌ .env read failed: {e}", exc_info=True)
        return {}


# ───────── Web3 bootstrap (retry until connected) ─────────  # L201
def _init_web3() -> Web3:  # L202
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

w3 = _init_web3()  # L221


# ───────── 24h Hold (local persistence) ─────────  # L225
HOLD_FILE = Path("safe_hold.json")  # L226

def _hold_load() -> Dict[str, Any]:  # L228
    if not HOLD_FILE.exists(): return {}
    try: return json.loads(HOLD_FILE.read_text())
    except Exception: return {}

def _hold_save(d: Dict[str, Any]) -> None:  # L234
    HOLD_FILE.write_text(json.dumps(d, indent=2))


# ───────── Safe Context ─────────  # L238
class SafeCtx:  # L239
    def __init__(self) -> None:
        self.addr: Optional[str] = None
        self.contract = None
        self.owners: List[str] = []
        self.threshold: int = 1
        self.collected: Dict[str,str] = {}
        self.prepared: Dict[str,Any] = {}
        self.hold = _hold_load()

SAFE = SafeCtx()  # L250

def _cs(addr: str) -> str:  # L253
    return Web3.to_checksum_address(addr)

def safe_init() -> None:  # L256
    if SAFE.contract and SAFE.addr: return
    try:
        saddr = _get_secret("GNOSIS_SAFE", "Enter Safe address: ", sensitive=False)
    except RuntimeError:
        saddr = input("Enter Safe address: ").strip()
        if not saddr: raise RuntimeError("Safe address required.")
        _set_secret("GNOSIS_SAFE", saddr)
    SAFE.addr = _cs(saddr)

    abi_path = os.getenv("GNOSIS_SAFE_ABI", "./abi/GnosisSafe.json").strip()
    with open(abi_path, "r") as f:
        data = json.load(f)
    abi = data["abi"] if isinstance(data, dict) and "abi" in data else data
    SAFE.contract = w3.eth.contract(address=SAFE.addr, abi=abi)

    SAFE.owners = [_cs(o) for o in SAFE.contract.functions.getOwners().call()]
    SAFE.threshold = SAFE.contract.functions.getThreshold().call()
    logger.info(f"🔧 SAFE initialized | address={SAFE.addr} | owners={len(SAFE.owners)} | threshold={SAFE.threshold}")
    audit_log("safe_init", {"safe": SAFE.addr, "owners": SAFE.owners, "threshold": SAFE.threshold}, True, {})
# ───────── Delegate Registry (mapping owner->delegates) ─────────  # L301
DELEGATE_FILE = Path("safe_delegates.json")  # L302

def _delegate_load() -> Dict[str,List[str]]:  # L304
    if not DELEGATE_FILE.exists(): return {}
    try: return json.loads(DELEGATE_FILE.read_text())
    except Exception: return {}

def _delegate_save(d: Dict[str,List[str]]) -> None:  # L310
    DELEGATE_FILE.write_text(json.dumps(d, indent=2))

def safe_add_delegate() -> None:  # map delegate to owner  # L313
    owner = input("Owner address: ").strip()
    delegate = input("Delegate address: ").strip()
    try: o = _cs(owner); d = _cs(delegate)
    except Exception: print("Invalid address."); return
    reg = _delegate_load()
    reg.setdefault(o, [])
    if d not in reg[o]: reg[o].append(d)
    _delegate_save(reg)
    print(f"🗝 Delegate {d} added for owner {o}")
    audit_log("delegate_add", {"owner": o, "delegate": d}, True, {})

def safe_remove_delegate() -> None:  # remove delegate  # L326
    owner = input("Owner address: ").strip()
    delegate = input("Delegate to remove: ").strip()
    try: o = _cs(owner); d = _cs(delegate)
    except Exception: print("Invalid address."); return
    reg = _delegate_load()
    if o in reg and d in reg[o]:
        reg[o].remove(d)
        _delegate_save(reg)
        print(f"🗑 Removed delegate {d} from {o}")
        audit_log("delegate_remove", {"owner": o, "delegate": d}, True, {})
    else:
        print("Delegate not found.")
        audit_log("delegate_remove", {"owner": o, "delegate": d}, False, {"error": "not_found"})

def safe_list_delegates() -> None:  # L342
    reg = _delegate_load()
    if not reg:
        print("No delegates recorded.")
        return
    for owner, dels in reg.items():
        print(f"{owner}:")
        for d in dels: print(f"  - {d}")
    audit_log("delegate_list", {}, True, {"count": len(reg)})


# ───────── Safe helpers ─────────  # L353
def _safe_nonce() -> int:  # L354
    return SAFE.contract.functions.nonce().call()

def _apply_24h_hold() -> bool:  # L357
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

def _send_tx(tx: Dict[str, Any]) -> Optional[str]:  # L374
    try:
        tx.setdefault("chainId", int(os.getenv("CHAIN_ID","1") or "1"))
        tx.setdefault("nonce", w3.eth.get_transaction_count(SAFE.owners[0]))
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
        txh = w3.eth.send_transaction(tx)
        rcpt = w3.eth.wait_for_transaction_receipt(txh)
        ok = (rcpt.status == 1)
        print(("✅" if ok else "❌") + f" tx={txh.hex()} block={rcpt.blockNumber} gasUsed={rcpt.gasUsed}")
        audit_log("send_tx", {"to": tx.get("to"), "value": int(tx.get("value",0))}, ok,
                  {"hash": txh.hex(), "block": rcpt.blockNumber, "gasUsed": rcpt.gasUsed})
        return txh.hex()
    except Exception as e:
        print(f"❌ Transaction failed: {e}")
        audit_log("send_tx", {"to": tx.get("to")}, False, {"error": str(e)})
        return None
def safe_assert_owner(addr: str) -> None:  # L401
    if _cs(addr) not in SAFE.owners:
        raise Exception(f"{addr} is not a Safe owner.")

def safe_add_owner() -> None:  # L405
    addr = input("New owner address: ").strip()
    try: a = _cs(addr)
    except Exception: print("Invalid address."); return
    thr = SAFE.contract.functions.getThreshold().call()
    data = SAFE.contract.encodeABI(fn_name="addOwnerWithThreshold", args=[a, thr])
    tx = {"to": SAFE.addr, "value": 0, "data": Web3.to_bytes(hexstr=data)}
    if _apply_24h_hold(): 
        _send_tx(tx)
        audit_log("owner_add", {"owner": a}, True, {})

def safe_remove_owner() -> None:  # L417
    rm = input("Owner to remove: ").strip()
    prev = input("Prev owner (linked-list): ").strip()
    try: rm_cs = _cs(rm); prev_cs = _cs(prev)
    except Exception: print("Invalid address."); return
    thr = SAFE.contract.functions.getThreshold().call()
    data = SAFE.contract.encodeABI(fn_name="removeOwner", args=[prev_cs, rm_cs, thr])
    tx = {"to": SAFE.addr, "value": 0, "data": Web3.to_bytes(hexstr=data)}
    if _apply_24h_hold(): 
        _send_tx(tx)
        audit_log("owner_remove", {"owner": rm_cs, "prev": prev_cs}, True, {})

def safe_change_threshold() -> None:  # L430
    val = input("New threshold (>0): ").strip()
    try: thr = int(val); assert thr > 0
    except Exception: print("Invalid threshold."); return
    data = SAFE.contract.encodeABI(fn_name="changeThreshold", args=[thr])
    tx = {"to": SAFE.addr, "value": 0, "data": Web3.to_bytes(hexstr=data)}
    if _apply_24h_hold(): 
        _send_tx(tx)
        audit_log("threshold_change", {"threshold": thr}, True, {})

def safe_exec_tx(to_addr: str, value: int, data: bytes, op: int=0) -> None:  # L442
    if not SAFE.contract: safe_init()
    nonce = _safe_nonce()
    txh = SAFE.contract.functions.getTransactionHash(
        to_addr, value, data, op, 0, 0, 0,
        _cs("0x0000000000000000000000000000000000000000"),
        _cs("0x0000000000000000000000000000000000000000"),
        nonce
    ).call()
    print(f"📝 SafeTxHash = {txh.hex()}")
    audit_log("safe_get_hash", {"to": to_addr, "value": value, "op": op}, True, {"hash": txh.hex()})

    needed = SAFE.threshold
    sigs: List[bytes] = []
    for i in range(needed):
        sighex = input(f"Enter signature {i+1}/{needed} (0x…): ").strip()
        if not sighex: 
            print("❌ Empty sig"); 
            return
        sigs.append(bytes.fromhex(sighex[2:] if sighex.startswith("0x") else sighex))

    packed = b"".join(sigs)
    exec_data = SAFE.contract.encodeABI(fn_name="execTransaction",
        args=[to_addr, value, data, op, 0, 0, 0,
              _cs("0x0000000000000000000000000000000000000000"),
              _cs("0x0000000000000000000000000000000000000000"),
              packed])
    tx = {"to": SAFE.addr, "value": 0, "data": Web3.to_bytes(hexstr=exec_data)}
    if _apply_24h_hold():
        _send_tx(tx)
        audit_log("safe_exec", {"to": to_addr, "value": value, "op": op}, True, {"hash32": txh.hex()})

def safe_show_info() -> None:  # L478
    owners = SAFE.owners
    threshold = SAFE.threshold
    nonce = _safe_nonce()
    eth = Decimal(w3.from_wei(w3.eth.get_balance(SAFE.addr), "ether"))
    out = {"safe": SAFE.addr, "owners": owners, "threshold": threshold, "nonce": nonce, "eth_balance": str(eth)}
    print(json.dumps(out, indent=2))
    audit_log("safe_info", {}, True, out)
def safe_fund_eth() -> None:  # L501
    amt = input("Amount ETH to send to Safe: ").strip()
    try: v = Decimal(amt)
    except Exception: 
        print("Invalid amount."); 
        return
    tx = {"to": SAFE.addr, "value": int(Web3.to_wei(v, "ether")), "data": b""}
    if _apply_24h_hold(): 
        _send_tx(tx)

def safe_send_erc20() -> None:  # L511
    token_addr = input("ERC20 token address: ").strip()
    try: token = w3.eth.contract(address=_cs(token_addr), abi=ERC20_ABI_MIN)
    except Exception: 
        print("Invalid token."); 
        return
    try: sym = token.functions.symbol().call()
    except Exception: sym = "UNKNOWN"
    try: dec = token.functions.decimals().call()
    except Exception: dec = 18
    amt = input(f"Amount of {sym}: ").strip()
    try: v = Decimal(amt)
    except Exception: 
        print("Invalid amount."); 
        return
    raw = int(v * (10 ** dec))
    data = token.encodeABI(fn_name="transfer", args=[SAFE.addr, raw])
    tx = {"to": token.address, "value": 0, "data": Web3.to_bytes(hexstr=data)}
    if _apply_24h_hold(): 
        _send_tx(tx)

def safe_toggle_guard(enable: bool) -> None:  # L533
    if enable:
        guard_addr = _get_secret("SAFE_DELAY_GUARD", "Enter DelayGuard address: ", sensitive=False)
        try: g = _cs(guard_addr)
        except Exception: 
            print("Invalid address."); 
            return
        data = SAFE.contract.encodeABI(fn_name="setGuard", args=[g])
        tx = {"to": SAFE.addr, "value": 0, "data": Web3.to_bytes(hexstr=data)}
        _send_tx(tx)
        _set_secret("SAFE_DELAY_GUARD", g)
        print(f"🛡 Guard enabled at {g}")
        audit_log("guard_enable", {"guard": g}, True, {})
    else:
        zero = _cs("0x0000000000000000000000000000000000000000")
        data = SAFE.contract.encodeABI(fn_name="setGuard", args=[zero])
        tx = {"to": SAFE.addr, "value": 0, "data": Web3.to_bytes(hexstr=data)}
        _send_tx(tx)
        print("🛡 Guard disabled.")
        audit_log("guard_disable", {}, True, {})

def safe_show_guard() -> None:  # L555
    try:
        g = SAFE.contract.functions.getGuard().call()
        active = int(g,16) != 0
        msg = _cs(g) if active else "none"
        print(f"Guard: {msg}")
        audit_log("guard_show", {}, True, {"guard": msg})
    except Exception as e:
        print(f"❌ getGuard failed: {e}")
        audit_log("guard_show", {}, False, {"error": str(e)})
# ───────── Wallet Manager (HD + hidden tree, mnemonic, passphrase, preview) ─────────  # L601
class WalletCtx:
    def __init__(self) -> None:
        self.mnemonic: Optional[str] = None
        self.passphrase: str = ""   # optional passphrase for hidden tree
        self.default_path = "m/44'/60'/0'/0/0"
        self.hidden_root = "m/44'/60'/1337'/0"
        self.discovered: List[Tuple[str, str]] = []
        self.labels: Dict[str, str] = {}
        self.label_file = Path("wallet_labels.json")
        if self.label_file.exists():
            try: 
                self.labels = json.loads(self.label_file.read_text())
            except Exception: 
                self.labels = {}

WAL = WalletCtx()

def wal_generate_mnemonic() -> None:  # L617
    from eth_account.hdaccount import generate_mnemonic
    phrase = generate_mnemonic()
    WAL.mnemonic = phrase
    _set_secret("WALLET_MNEMONIC", phrase)
    print(f"🌱 Generated mnemonic:\n{phrase}")
    addr, _ = wal_derive(WAL.default_path)
    print(f"✅ Default acct0 = {addr}")
    audit_log("wallet_generate_mnemonic", {}, True, {"acct0": addr})

def wal_import_mnemonic() -> None:  # L627
    phrase = getpass.getpass("Enter mnemonic: ").strip()
    if not phrase: 
        print("❌ Empty mnemonic."); 
        return
    WAL.mnemonic = phrase
    _set_secret("WALLET_MNEMONIC", phrase)
    addr, _ = wal_derive(WAL.default_path)
    print(f"✅ Default acct0 = {addr}")
    audit_log("wallet_import_mnemonic", {}, True, {"acct0": addr})

def wal_set_passphrase() -> None:  # L637
    pw = getpass.getpass("Enter passphrase (empty to clear): ").strip()
    WAL.passphrase = pw
    if pw:
        _set_secret("WALLET_PASSPHRASE", pw)
        print("🔐 Passphrase set.")
    else:
        _set_secret("WALLET_PASSPHRASE", "")
        print("🧹 Passphrase cleared.")
    audit_log("wallet_passphrase", {}, True, {"set": bool(pw)})

def wal_preview() -> None:  # L648
    path = input("Enter derivation path (e.g., m/44'/60'/0'/0/0): ").strip()
    addr, _ = wal_derive(path)
    if addr: 
        print(f"{path} -> {addr}")
    else: 
        print("❌ Failed to derive.")
    audit_log("wallet_preview", {"path": path}, bool(addr), {"addr": addr})

def wal_derive(path: str) -> Tuple[str, Optional[LocalAccount]]:  # L656
    if not WAL.mnemonic: 
        return ("", None)
    try:
        acct = Account.from_mnemonic(WAL.mnemonic, account_path=path, passphrase=WAL.passphrase)  # type: ignore
        return (_cs(acct.address), acct)
    except Exception as e:
        logger.error(f"derive failed: {e}", exc_info=True)
        audit_log("wallet_derive", {"path": path}, False, {"error": str(e)})
        return ("", None)

def wal_scan(n: int, hidden: bool=False) -> None:  # L666
    base = WAL.hidden_root if hidden else "m/44'/60'/0'/0"
    out: List[Tuple[str, str]] = []
    for i in range(n):
        path = f"{base}/{i}"
        addr, _ = wal_derive(path)
        if addr: 
            out.append((path, addr))
    WAL.discovered = out
    print(f"🔍 Scanned {n} ({'hidden' if hidden else 'default'})")
    for p,a in out: 
        print(f"  {p} -> {a}")
    audit_log("wallet_scan", {"hidden": hidden, "n": n}, True, {"count": len(out)})
def wal_export_discovered() -> None:  # L701
    data = {
        "mnemonic_present": WAL.mnemonic is not None,
        "discovered": [
            {"path": p, "address": a, "label": WAL.labels.get(a,"")} 
            for p,a in WAL.discovered
        ]
    }
    Path("wallet_export.json").write_text(json.dumps(data, indent=2))
    print("📤 Exported -> wallet_export.json")
    audit_log("wallet_export", {}, True, {"file": "wallet_export.json"})

def wal_label() -> None:  # L713
    addr = input("Address to label: ").strip()
    if not addr: 
        return
    label = input("Label: ").strip()
    WAL.labels[addr] = label
    WAL.label_file.write_text(json.dumps(WAL.labels, indent=2))
    print(f"🏷️ {addr} => {label}")
    audit_log("wallet_label", {"addr": addr, "label": label}, True, {})


# ───────── Key Manager ─────────  # L730
def km_add() -> None:
    key = input("Secret key (e.g., RPC_URL): ").strip()
    if not key: 
        print("Empty."); 
        return
    val = getpass.getpass(f"Enter value for {key}: ").strip()
    if not val: 
        print("Empty."); 
        return
    if keyring:
        try: 
            keyring.set_password(_service_name(), key, val)
        except Exception as e: 
            logger.error(f"keyring set: {e}", exc_info=True)
    print("✅ Stored in keyring")
    audit_log("km_set", {"key": key}, True, {})

def km_get() -> None:
    key = input("Secret key: ").strip()
    if not key: 
        return
    val = None
    if keyring:
        try: 
            val = keyring.get_password(_service_name(), key)
        except Exception: 
            val = None
    if val:
        print(f"{key} = {val}")
        audit_log("km_get", {"key": key}, True, {"found": True})
    else:
        print("Not found.")
        audit_log("km_get", {"key": key}, False, {"found": False})

def km_del() -> None:
    key = input("Secret key to delete: ").strip()
    if not key: 
        return
    ok = True
    if keyring:
        try: 
            keyring.delete_password(_service_name(), key)
        except Exception: 
            ok = False
    print("✅ Deleted from keyring (if present).")
    audit_log("km_del", {"key": key}, ok, {})

def km_list_keyring() -> None:  # L780
    if not keyring:
        print("⚠️ keyring not available")
        return
    service = _service_name()
    print(f"=== keyring entries for service {service} ===")
    try:
        # WARNING: some backends cannot enumerate; handle gracefully
        keys = []
        try:
            keys = keyring.get_credential(service, None)  # type: ignore
        except Exception:
            pass
        if not keys:
            print("No entries visible (backend may not support listing).")
        else:
            print(keys)
    except Exception as e:
        logger.error(f"km_list_keyring failed: {e}", exc_info=True)
        print("❌ Failed to list keyring.")
# ──────────────────────────────────────────────  # L801
# ABOUT & LICENSE                                # L802
# ──────────────────────────────────────────────  # L803
def about_menu() -> None:
    text = """
GNOMAN — Safe • Wallet • Keys • Hold24h
────────────────────────────────────────
Author & Owner : Christopher Hirschauer
Copyright      : (c) 2025 All rights reserved.
License        : Proprietary (see LICENSE.md and LICENSEE.md)

Terms
-----
- You may use GNOMAN only with explicit permission of the author.
- Redistribution, modification, or resale without permission is forbidden.
- GNOMAN is provided "AS IS" without warranty of any kind.
- "GNOMAN" is a proprietary trademark of Christopher Hirschauer.

For permissions or commercial licensing, contact:
Christopher Hirschauer — Fort Dodge, Iowa, USA
"""
    print(text)


def safe_menu() -> None:  # L827
    try:
        safe_init()
    except Exception as e:
        print(f"❌ {e}"); 
        return
    while True:
        print("\n┌─ SAFE MANAGER ───────────────────────────────────────────")
        print("│ 1) Show Safe info")
        print("│ 2) Fund Safe with ETH")
        print("│ 3) Send ERC20 to Safe")
        print("│ 4) Execute Safe transaction")
        print("│ 5) Admin: Add owner")
        print("│ 6) Admin: Remove owner")
        print("│ 7) Admin: Change threshold")
        print("│ 8) Delegates: Add")
        print("│ 9) Delegates: Remove")
        print("│ 10) Delegates: List")
        print("│ 11) Guard: Show")
        print("│ 12) Guard: Enable (setGuard)")
        print("│ 13) Guard: Disable")
        print("│ 0) Back")
        print("└──────────────────────────────────────────────────────────")
        ch = input("> ").strip()
        try:
            if ch == "1": 
                safe_show_info()
            elif ch == "2": 
                safe_fund_eth()
            elif ch == "3": 
                safe_send_erc20()
            elif ch == "4":
                to_in = input(" to (target address): ").strip()
                try: 
                    to_addr = _cs(to_in)
                except Exception: 
                    print("Bad address."); 
                    continue
                val = input(" value (ETH, default 0): ").strip()
                value = int(Web3.to_wei(Decimal(val), "ether")) if val else 0
                data_hex = input(" data (0x…): ").strip()
                data = b"" if not data_hex else Web3.to_bytes(hexstr=data_hex)
                op = int(input(" operation (0=CALL,1=DELEGATECALL; default 0): ").strip() or "0")
                if op not in (0,1): 
                    print("Invalid op"); 
                    continue
                safe_exec_tx(to_addr, value, data, op)
            elif ch == "5": 
                safe_add_owner()
            elif ch == "6": 
                safe_remove_owner()
            elif ch == "7": 
                safe_change_threshold()
            elif ch == "8": 
                safe_add_delegate()
            elif ch == "9": 
                safe_remove_delegate()
            elif ch == "10": 
                safe_list_delegates()
            elif ch == "11": 
                safe_show_guard()
            elif ch == "12": 
                safe_toggle_guard(True)
            elif ch == "13": 
                safe_toggle_guard(False)
            elif ch == "0": 
                return
            else: 
                print("Invalid.")
        except KeyboardInterrupt:
            print("\n⚠️ Interrupted.")
        except Exception as e:
            logger.error(f"Safe menu error: {e}", exc_info=True)
            audit_log("safe_menu_error", {"choice": ch}, False, {"error": str(e)})
            print(f"Error: {e}. See gnoman.log.")

def wallet_menu() -> None:  # L901
    if not WAL.mnemonic:
        seed = _env_load().get("WALLET_MNEMONIC")
        if not seed and keyring:
            try: 
                seed = keyring.get_password(_service_name(), "WALLET_MNEMONIC")
            except Exception: 
                seed = None
        WAL.mnemonic = seed
    while True:
        print("\n┌─ WALLET MANAGER ─────────────────────────────────────────")
        print("│ 1) Generate new mnemonic")
        print("│ 2) Import mnemonic")
        print("│ 3) Set/clear passphrase (hidden tree)")
        print("│ 4) Preview address (any path)")
        print("│ 5) Scan default accounts")
        print("│ 6) Scan hidden HD tree")
        print("│ 7) Derive specific path")
        print("│ 8) Export discovered addresses")
        print("│ 9) Label address")
        print("│ 0) Back")
        print("└──────────────────────────────────────────────────────────")
        ch = input("> ").strip()
        try:
            if ch == "1": 
                wal_generate_mnemonic()
            elif ch == "2": 
                wal_import_mnemonic()
            elif ch == "3": 
                wal_set_passphrase()
            elif ch == "4": 
                wal_preview()
            elif ch == "5":
                n = int(input("How many accounts (default=5): ").strip() or "5")
                wal_scan(n, hidden=False)
            elif ch == "6":
                n = int(input("How many hidden accounts (default=5): ").strip() or "5")
                wal_scan(n, hidden=True)
            elif ch == "7":
                path = input("Path (e.g., m/44'/60'/0'/0/1): ").strip()
                a,_ = wal_derive(path); 
                print(f"{path} -> {a}")
            elif ch == "8": 
                wal_export_discovered()
            elif ch == "9": 
                wal_label()
            elif ch == "0": 
                return
            else: 
                print("Invalid.")
        except KeyboardInterrupt:
            print("\n⚠️ Interrupted.")
        except Exception as e:
            logger.error(f"Wallet menu error: {e}", exc_info=True)
            audit_log("wallet_menu_error", {"choice": ch}, False, {"error": str(e)})
            print(f"Error: {e}. See gnoman.log.")

def key_manager_menu() -> None:  # L960
    while True:
        print("\n┌─ KEY MANAGER ──────────────────────────────────────────")
        print("│ 1) Add/Update secret")
        print("│ 2) Retrieve secret")
        print("│ 3) Delete secret")
        print("│ 4) List keyring entries")
        print("│ 0) Back")
        print("└─────────────────────────────────────────────────────────")
        ch = input("> ").strip()
        try:
            if ch == "1": 
                km_add()
            elif ch == "2": 
                km_get()
            elif ch == "3": 
                km_del()
            elif ch == "4": 
                km_list_keyring()
            elif ch == "0": 
                return
            else: 
                print("Invalid.")
        except KeyboardInterrupt:
            print("\n⚠️ Interrupted.")
        except Exception as e:
            logger.error(f"Key menu error: {e}", exc_info=True)
            audit_log("key_menu_error", {"choice": ch}, False, {"error": str(e)})
            print(f"Error: {e}. See gnoman.log.")

# ───────── Main Menu ─────────  # L1000
def main_menu() -> None:  # L1001
    while True:
        print("\n┌─ GNOMAN MAIN MENU ──────────────────────────────────────")
        print("│ 1) Safe Manager (Gnosis Safe)")
        print("│ 2) Wallet Manager (HD / hidden trees)")
        print("│ 3) Key Manager (Secrets)")
        print("│ 4) About & License")
        print("│ 5) Exit")
        print("└─────────────────────────────────────────────────────────")
        ch = input("> ").strip()
        try:
            if ch == "1": 
                safe_menu()
            elif ch == "2": 
                wallet_menu()
            elif ch == "3": 
                key_manager_menu()
            elif ch == "4": 
                about_menu()
            elif ch == "5":
                print("👋 Goodbye.")
                return
            else: 
                print("Invalid.")
        except KeyboardInterrupt:
            print("\n⚠️ Interrupted.")
        except Exception as e:
            logger.error(f"💥 Main menu error: {e}", exc_info=True)
            print(f"Error: {e}. See gnoman.log.")


# ───────── Entrypoint ─────────  # L1030
if __name__ == "__main__":
    try:
        splash()
        main_menu()
    finally:
        logger.info("🧹 gnoman exiting.")
        logging.shutdown()
# EOF  # L1038

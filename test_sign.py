"""
XELIS Ledger App — Minimal TX streamer + attestation with blinder support

Writes <basename>.attest.json with:
  - device_pubkey_hex (32B compressed, whatever GET_PUBKEY returns)
  - tx_sha3_512_hex   (64B SHA3-512 of tx bytes)
  - signature.s_hex, signature.e_hex (LE scalars, 32B each)
"""
import os, json, time, struct
from pathlib import Path
from ledgerblue.commTCP import getDongle
from ledgerblue.commException import CommException

CLA             = 0xE0
INS_GET_PUBKEY  = 0x05  # P1: 0=no display, 1=display; P2: 0
INS_SIGN_TX     = 0x06  # streaming signer
INS_LOAD_MEMO   = 0x10  # optional memo/preview
INS_SEND_BLINDERS = 0x12  # send blinders for commitment verification

P1_FIRST        = 0x00
P2_MORE         = 0x80
P2_LAST         = 0x00

def sha3_512_hex(data: bytes) -> str:
    try:
        from sha3 import sha3_512
    except Exception:
        from hashlib import sha3_512
    return sha3_512(data).hexdigest()

def serialize_bip32_path(path="m/44'/587'/0'/0/0") -> bytes:
    elems = []
    for part in path.split('/')[1:]:
        if part.endswith("'"):
            elems.append(0x80000000 | int(part[:-1]))
        else:
            elems.append(int(part))
    out = struct.pack('B', len(elems))
    for v in elems:
        out += struct.pack('>I', v)
    return out

def apdu_exchange(dongle, cla, ins, p1, p2, data=b"", timeout=60000):
    apdu = bytes([cla, ins, p1, p2, len(data)]) + data
    return dongle.exchange(apdu, timeout=timeout)

def get_pubkey_no_display(dongle, bip32_path="m/44'/587'/0'/0/0") -> bytes:
    path = serialize_bip32_path(bip32_path)
    resp = apdu_exchange(dongle, CLA, INS_GET_PUBKEY, 0x00, 0x00, path)
    if len(resp) < 33 or resp[0] != 32:
        raise RuntimeError(f"unexpected pubkey response: {resp.hex()}")
    return resp[1:33]  # compressed, as returned by device

def read_leb128(buf: bytes, off: int):
    val = 0; shift = 0
    while True:
        if off >= len(buf): raise ValueError("truncated LEB128")
        b = buf[off]; off += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0: break
        shift += 7
    return val, off

def load_any(path: str):
    """Load bundle or raw TX file, now supports v2 with blinders"""
    data = Path(path).read_bytes()
    
    if len(data) >= 6 and data[:4] == b"XLB1":
        ver = data[4]
        off = 5
        
        # Read memo
        memo_len, off = read_leb128(data, off)
        memo = data[off:off+memo_len]
        off += memo_len
        
        blinders = []
        if ver >= 1:
            # V2: has blinders section
            blinders_len, off = read_leb128(data, off)
            if blinders_len % 32 != 0:
                raise ValueError(f"Invalid blinders length: {blinders_len}")
            
            blinders_data = data[off:off+blinders_len]
            off += blinders_len
            
            # Split into 32-byte chunks
            blinders = [blinders_data[i:i+32] for i in range(0, len(blinders_data), 32)]
            
            # Rest is TX
            tx = data[off:]
        else:
            raise ValueError(f"Unsupported bundle version {ver}")
        
        return memo, tx, blinders
    
    # Not a bundle, treat as raw TX
    return None, data, []

def send_memo_preview_if_any(dongle, memo: bytes | None):
    if not memo:
        return
        
    print(f"📤 Sending memo ({len(memo)} bytes)...")
    
    # Send in chunks of 250 bytes
    CHUNK_SIZE = 250
    for i in range(0, len(memo), CHUNK_SIZE):
        chunk = memo[i:i+CHUNK_SIZE]
        
        if i == 0:
            p1 = 0  # First chunk
        else:
            p1 = ((i // CHUNK_SIZE - 1) % 255) + 1
            
        p2 = 0x80 if i + CHUNK_SIZE < len(memo) else 0x00  # More/Last flag
        
        apdu = bytes([
            CLA,
            INS_LOAD_MEMO,
            p1,
            p2,
            len(chunk)
        ]) + chunk
        
        dongle.exchange(apdu)
    
    print("✓ Memo sent")

def send_blinders_if_any(dongle, blinders: list[bytes]):
    """Send blinders to device for commitment verification"""
    if not blinders:
        return
    
    print(f"📤 Sending {len(blinders)} blinders for commitment verification...")
    
    # Send up to 7 blinders per APDU (7 * 32 = 224 bytes, fits in 255 byte limit)
    BLINDERS_PER_CHUNK = 7
    
    for i in range(0, len(blinders), BLINDERS_PER_CHUNK):
        chunk_blinders = blinders[i:i+BLINDERS_PER_CHUNK]
        chunk_data = b''.join(chunk_blinders)
        
        p1 = i // BLINDERS_PER_CHUNK  # chunk index
        p2 = P2_LAST if i + BLINDERS_PER_CHUNK >= len(blinders) else P2_MORE
        
        apdu_exchange(dongle, CLA, INS_SEND_BLINDERS, p1, p2, chunk_data)
    
    print(f"✓ Blinders sent")

def send_transaction_chunks(dongle, tx_bytes: bytes, bip32_path="m/44'/587'/0'/0/0", chunk_size=250):
    # 1) path first
    path_data = serialize_bip32_path(bip32_path)
    apdu_exchange(dongle, CLA, INS_SIGN_TX, P1_FIRST, P2_MORE, path_data)
    
    # 2) stream payload
    off = 0; idx = 1; resp_last = None
    total = len(tx_bytes)
    
    print(f"📤 Streaming {total} bytes...")
    
    while off < total:
        chunk = tx_bytes[off: off + chunk_size]
        off += len(chunk)
        p2 = P2_LAST if off == total else P2_MORE
        
        # Progress indicator
        pct = int(100 * off / total)
        print(f"\r  Progress: {pct}%", end='', flush=True)
        
        resp_last = apdu_exchange(dongle, CLA, INS_SIGN_TX, idx & 0xFF, p2, chunk)
        idx += 1
    
    print("\r✓ Transaction sent      ")
    return resp_last

def save_attestation(base_path: str, bip32_path: str, tx_bytes: bytes, sig_resp: bytes, 
                    pubkey: bytes, blinders: list[bytes]):
    out_path = str(Path(base_path).with_suffix("")) + ".attest.json"
    if len(sig_resp) < 65 or sig_resp[0] != 64:
        raise RuntimeError(f"unexpected signature response length={len(sig_resp)}")
    sig = sig_resp[1:65]
    s_le = sig[:32].hex()
    e_le = sig[32:].hex()
    
    artifact = {
        "version": 1,
        "timestamp": int(time.time()),
        "bip32_path": bip32_path,
        "device_pubkey_hex": pubkey.hex(),         # compressed as device returns it
        "tx_len": len(tx_bytes),
        "tx_sha3_512_hex": sha3_512_hex(tx_bytes), # 64B message
        "signature": {
            "concat_hex": sig.hex(),
            "s_hex": s_le,
            "e_hex": e_le,
        },
    }
    
    # Include blinder count for verification records
    if blinders:
        artifact["blinders_count"] = len(blinders)
    
    Path(out_path).write_text(json.dumps(artifact, indent=2))
    print(f"✓ Wrote attestation: {out_path}")

def main():
    default_path = "tx/poc_tx.unsigned.bundle"
    path = os.environ.get("XELIS_SRC", default_path)
    
    print(f"📁 Loading: {path}")
    memo, tx_data, blinders = load_any(path)
    
    print(f"✓ Loaded TX bytes: {len(tx_data)}")
    print(f"  SHA3-512(tx) = {sha3_512_hex(tx_data)}")
    if memo:
        print(f"  Memo size: {len(memo)} bytes")
    if blinders:
        print(f"  Blinders: {len(blinders)} (for commitment verification)")

    try:
        dongle = getDongle("127.0.0.1", 9999, debug=True)
        print("✓ Connected to device")
    except Exception as e:
        print(f"✗ Could not connect: {e}")
        return

    bip32_path = "m/44'/587'/0'/0/0"
    try:
        # Send memo preview if available
        send_memo_preview_if_any(dongle, memo)
        
        # Send blinders for commitment verification (v2 bundles)
        send_blinders_if_any(dongle, blinders)
        
        # Stream transaction and get signature
        sig_resp = send_transaction_chunks(dongle, tx_data, bip32_path=bip32_path)

        print("⏳ Waiting for device confirmation...")
        time.sleep(5)

        # Get public key
        pubkey = get_pubkey_no_display(dongle, bip32_path=bip32_path)
        print(f"✓ Device pubkey: {pubkey.hex()}")

        # Save attestation
        save_attestation(path, bip32_path, tx_data, sig_resp, pubkey, blinders)

        # Display signature
        sig = sig_resp[1:65]
        print("\n✓ Signature (LE)")
        print(f"  s = {sig[:32].hex()}")
        print(f"  e = {sig[32:].hex()}")
        print("\n✅ Transaction signed successfully!")
        
    except CommException as e:
        print(f"\n✗ APDU error {e.sw:04x}")
        if e.sw == 0x6985:
            print("  → User rejected the transaction")
        elif e.sw == 0x6A86:
            print("  → Invalid parameters")
    except Exception as e:
        print(f"\n✗ Error: {e}")
    finally:
        dongle.close()

if __name__ == "__main__":
    main()
"""Test script for Xelis Ledger app debug functionality"""

from ledgerblue.commTCP import getDongle
import binascii

def parse_debug_response(response):
    """Parse the debug test response"""
    idx = 0
    test_id = response[idx]
    idx += 1
    
    if test_id == 0x2C:
        print("=== DEBUG TESTS ===\n")
        idx = parse_bip32_debug(response, idx)
        idx = parse_key_derivation_test(response, idx)
        idx = parse_address_generation_test(response, idx)
    else:
        print(f"Unknown test ID: 0x{test_id:02x}")

def parse_bip32_debug(response, idx):
    """Parse BIP32 derivation debug results"""
    if idx >= len(response) or response[idx] not in [0xBD, 0xF6]:
        return idx
    
    if response[idx] == 0xBD:
        print("--- BIP32 Derivation Debug ---")
        idx += 1
        
        # Test D4: Without scalar_reduce  
        if idx < len(response) and response[idx] == 0xD4:
            print("\nTest D4: BIP32 + Ed25519 clamping (no scalar_reduce)")
            idx += 1
            
            if idx < len(response):
                success = response[idx]
                idx += 1
                if success == 0x01:
                    print("  ✓ BIP32 derivation succeeded")
                    if idx + 8 <= len(response):
                        raw_key = response[idx:idx+8]
                        idx += 8
                        print(f"    Raw key (first 8): {binascii.hexlify(raw_key).decode()}")
                    
                    # Skip scalar_reduce result (should be 0x01 placeholder)
                    if idx < len(response):
                        idx += 1  # Skip success marker
                        if idx + 8 <= len(response):
                            clamped = response[idx:idx+8]
                            idx += 8
                            print(f"    Clamped (first 8): {binascii.hexlify(clamped).decode()}")
                        
                        # Public key derivation result
                        if idx < len(response):
                            pk_success = response[idx]
                            idx += 1
                            if pk_success == 0x01:
                                print(f"  ✓ Public key derivation succeeded")
                                if idx + 8 <= len(response):
                                    pubkey = response[idx:idx+8]
                                    idx += 8
                                    print(f"    Pubkey (first 8): {binascii.hexlify(pubkey).decode()}")
                            else:
                                print(f"  ✗ Public key derivation FAILED")
                else:
                    print(f"  ✗ BIP32 derivation FAILED")
        
        # Find end marker
        while idx < len(response) and response[idx] != 0xDD and response[idx] != 0xF6:
            idx += 1
        if idx < len(response) and response[idx] == 0xDD:
            idx += 1  # Skip end marker
        
        print()
    
    return idx

def parse_key_derivation_test(response, idx):
    """Parse the key derivation test results"""
    if idx >= len(response):
        return idx
        
    variant = response[idx]
    idx += 1
    
    if variant == 0xF6:
        print("--- Full Key Pair Verification ---")
        print("Test F6: Ristretto Public Key Tests")
        print("====================================\n")
        
        # Expected public keys
        expected_keys = {
            1: "8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134",
            2: "f05bc1df2831717c2992d85b57e0cf3d123fd6c254257de5f784be369747b249",
            3: "02064b89dc89f5c353cf2077800e24fb83300d48b1af4a3926f1fe0a1864cf06",
            4: "f6decfbf9efabc8aa59452aa570cb84eed7fcfca7daea58a93b93444400a7a73"  # NEW
        }
        
        test_names = {
            0xA1: ("Private key = 1", 1),
            0xA2: ("Private key = 2", 2),
            0xA3: ("Private key = [0x01; 32]", 3),
            0xA4: ("Private key = [0xff; 32]", 4)  # NEW
        }
        
        all_passed = True
        
        while idx < len(response):
            if response[idx] == 0xAA:
                idx += 1
                break
                
            marker = response[idx]
            idx += 1
            
            if marker in test_names:
                test_name, key_num = test_names[marker]
                print(f"Test {key_num}: {test_name}")
                print("-" * 40)
                
                if idx >= len(response):
                    break
                    
                success = response[idx]
                idx += 1
                
                if success == 0x01:
                    print("✓ Key derivation successful")
                    
                    if idx >= len(response):
                        break
                        
                    matches = response[idx]
                    idx += 1
                    
                    if matches == 0x01:
                        print("✓ Public key matches expected value")
                        print(f"  Expected: {expected_keys[key_num]}")
                        print("  Result: PASS ✅")
                    else:
                        print("✗ Public key does NOT match expected value")
                        print(f"  Expected: {expected_keys[key_num]}")
                        print("  Result: FAIL ❌")
                        all_passed = False
                else:
                    print("✗ Key derivation failed")
                    print("  Result: FAIL ❌")
                    all_passed = False
                
                print()
        
        print("\n" + "=" * 50)
        if all_passed:
            print("🎉 ALL RISTRETTO TESTS PASSED! 🎉")
            print("Your Ristretto implementation matches the reference perfectly!")
        else:
            print("❌ Some Ristretto tests failed. Please check the implementation.")
        print("=" * 50)
        print()
        
    else:
        print(f"Unknown test variant: 0x{variant:02x}")
        
    return idx

def parse_address_generation_test(response, idx):
    """Parse address generation test results"""
    if idx >= len(response) or response[idx] != 0xAD:
        return idx
    
    print("--- Address Generation Tests ---")
    idx += 1
    
    test_cases = {
        0xB1: "Private key = 1",
        0xB2: "Private key = 2", 
        0xB3: "Private key = [0x01; 32]",
        0xB4: "Private key = [0xff; 32]"  # NEW
    }
    
    while idx < len(response) and response[idx] != 0xAF:
        marker = response[idx]
        idx += 1
        
        if marker in test_cases:
            print(f"\nTest {marker:02x}: {test_cases[marker]}")
            
            # Parse mainnet result
            if idx < len(response):
                success = response[idx]
                idx += 1
                
                if success == 0x01:
                    print("  ✓ Mainnet address succeeded")
                elif success == 0xFF:
                    print("  ✗ Mainnet address failed")
                else:
                    print("  ✗ Mainnet address mismatch")
                    # Parse debug info if available
                    if idx + 2 <= len(response):
                        actual_len = response[idx]
                        expected_len = response[idx + 1]
                        idx += 2
                        print(f"    Actual: {actual_len} bytes, Expected: {expected_len} bytes")
                        
                        if idx + 8 <= len(response):
                            debug_bytes = response[idx:idx+8]
                            idx += 8
                            print(f"    Debug: {binascii.hexlify(debug_bytes).decode()}")
            
            # Parse testnet result
            if idx < len(response) and response[idx] not in test_cases and response[idx] != 0xAF:
                success = response[idx]
                idx += 1
                
                if success == 0x01:
                    print("  ✓ Testnet address succeeded")
                elif success == 0xFF:
                    print("  ✗ Testnet address failed")
                else:
                    print("  ✗ Testnet address mismatch")
        else:
            # Skip unknown data
            pass
    
    if idx < len(response) and response[idx] == 0xAF:
        idx += 1  # Skip end marker
    
    print()
    return idx

def test_debug():
    """Test the debug handler with all tests"""
    try:
        # Connect to the device
        dongle = getDongle("127.0.0.1", 9999, debug=True)
        print("🔌 Connected to device\n")
        
        print("="*70)
        print("🧪 XELIS LEDGER APP - COMPREHENSIVE DEBUG TESTS")  
        print("="*70)
        
        # Build debug APDU
        # CLA=0xE0, INS=0xF0, P1=0x00, P2=0x00, LC=0x00 (no data)
        apdu = bytes([0xE0, 0xF0, 0x00, 0x00, 0x00])
        
        print(f"📤 Sending debug APDU: {binascii.hexlify(apdu).decode()}")
        
        try:
            # Send command
            response = dongle.exchange(apdu)
            print(f"📥 Response received ({len(response)} bytes)")
            print(f"🔍 Raw response: {binascii.hexlify(response).decode()}")
            print()
            
            # Parse the detailed response
            parse_debug_response(response)
                    
        except Exception as e:
            error_msg = str(e)
            print(f"\n❌ Error: {error_msg}")
            
            # Parse common error codes
            if "6985" in error_msg:
                print("→ User denied the request")
            elif "6a86" in error_msg:
                print("→ Wrong P1/P2 parameters")
            elif "6d00" in error_msg:
                print("→ Instruction not supported")
            elif "b009" in error_msg:
                print("→ Key derivation failed")
            elif "6700" in error_msg:
                print("→ Wrong APDU length")
        
        dongle.close()
        print("\n🏁 Debug tests completed!")
        
    except Exception as e:
        print(f"💥 Failed to connect: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_debug()
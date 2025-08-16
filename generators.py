from ledgerblue.comm import getDongle
from ledgerblue.commTCP import getDongle as getDongleTCP
import argparse
import sys

class XelisApp:
    def __init__(self, use_speculos=False, port=9999):
        if use_speculos:
            # Connect to Speculos
            self.dongle = getDongleTCP(port=port)
        else:
            # Connect to physical device
            self.dongle = getDongle(debug=False)
    
    def get_generator(self, which: int):
        """Get decompressed generator point (0=G, 1=H)"""
        # Build APDU: CLA=E0 INS=F0 P1=which P2=01 Lc=00
        apdu = bytes([0xE0, 0xF0, which, 0x01, 0x00])
        
        response = self.dongle.exchange(apdu)
        
        if len(response) != 128:
            raise Exception(f"Expected 128 bytes, got {len(response)}")
        
        # Split into x, y, z, t (32 bytes each)
        x = list(response[0:32])
        y = list(response[32:64])
        z = list(response[64:96])
        t = list(response[96:128])
        
        return (x, y, z, t)
    
    def close(self):
        self.dongle.close()

def format_rust_array(data: list, indent: int = 8) -> str:
    """Format byte array as Rust syntax"""
    lines = []
    for i in range(0, len(data), 8):
        chunk = data[i:i+8]
        hex_values = [f"0x{b:02x}" for b in chunk]
        line = " " * indent + ", ".join(hex_values)
        if i + 8 < len(data):
            line += ","
        lines.append(line)
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description='Extract Xelis generator points')
    parser.add_argument('--speculos', action='store_true', help='Use Speculos instead of physical device')
    parser.add_argument('--port', type=int, default=9999, help='Speculos port (default: 9999)')
    args = parser.parse_args()
    
    try:
        app = XelisApp(use_speculos=args.speculos, port=args.port)
        
        generators = [
            ("XELIS_G_POINT", 0),
            ("XELIS_H_POINT", 1)
        ]
        
        print("// Auto-generated generator points")
        print("// Add this to your ristretto.rs file\n")
        
        for name, idx in generators:
            print(f"// Extracting {name}...", file=sys.stderr)
            x, y, z, t = app.get_generator(idx)
            
            print(f"pub const {name}: RistrettoPoint = RistrettoPoint {{")
            print(f"    x: [")
            print(format_rust_array(x))
            print(f"    ],")
            print(f"    y: [")
            print(format_rust_array(y))
            print(f"    ],")
            print(f"    z: [")
            print(format_rust_array(z))
            print(f"    ],")
            print(f"    t: [")
            print(format_rust_array(t))
            print(f"    ],")
            print(f"}};\n")
            
        app.close()
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
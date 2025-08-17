import re
import sys

def analyze_map(filename="app.map"):
    symbol_sizes = {}
    section_sizes = {}
    current_section = None
    
    with open(filename, 'r') as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines):
        line = line.strip()
        
        # Skip empty lines and headers
        if not line or line.startswith('VMA') or line.startswith('PAGE_SIZE'):
            continue
            
        # Parse lines with format: hex hex size align section
        # Example: c0de0000 c0de0000     9400     4 .text
        match = re.match(r'^([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+(\d+)\s+(\.\w+)', line)
        if match:
            vma = match.group(1)
            lma = match.group(2)
            size = int(match.group(3), 16)
            section = match.group(5)
            
            if size > 0:
                section_sizes[section] = section_sizes.get(section, 0) + size
                current_section = section
            continue
        
        # Parse symbol lines with format: hex hex size align symbol_name
        # or with additional info like: hex hex size align file.o:(.text.function_name)
        match = re.match(r'^([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+(\d+)\s+(.+)', line)
        if match:
            size = int(match.group(3), 16)
            symbol_info = match.group(5)
            
            if size > 0:
                # Clean up symbol name
                symbol = symbol_info.strip()
                
                # Handle entries like "file.o:(.text.function)"
                if ':' in symbol and '(' in symbol:
                    parts = symbol.split(':(')
                    file_name = parts[0]
                    func_match = re.search(r'\.text\.([^)]+)', parts[1] if len(parts) > 1 else '')
                    if func_match:
                        symbol = func_match.group(1)
                    symbol = f"{symbol} ({file_name})"
                
                symbol_sizes[symbol] = size
            continue
            
        # Alternative format: just symbol name after spaces (aligned output)
        # Look for patterns like "         symbol_name = value"
        match = re.match(r'^\s+(\w+)\s*=', line)
        if match and i > 0:
            # Check previous line for size
            prev_line = lines[i-1].strip()
            size_match = re.match(r'^[0-9a-f]+\s+[0-9a-f]+\s+([0-9a-f]+)', prev_line)
            if size_match:
                size = int(size_match.group(1), 16)
                if size > 0:
                    symbol = match.group(1)
                    symbol_sizes[symbol] = size
    
    # Also look for a different format (GNU ld style)
    # where symbols appear like: "  .text.function_name"
    for line in lines:
        if '.text.' in line or '.rodata.' in line:
            match = re.search(r'\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(.text\.\S+|\.\rodata\.\S+)', line)
            if match:
                size = int(match.group(2), 16)
                symbol = match.group(3)
                if size > 0:
                    symbol_sizes[symbol] = size
    
    print("=== SECTION SIZES ===")
    total = 0
    for section, size in sorted(section_sizes.items(), key=lambda x: x[1], reverse=True):
        if size > 0:
            print(f"{size:6d} bytes ({size//1024:3d} KB): {section}")
            total += size
    print(f"{total:6d} bytes total ({total//1024:3d} KB)")
    
    print(f"\n=== TOP SYMBOLS (>100 bytes) ===")
    count = 0
    for symbol, size in sorted(symbol_sizes.items(), key=lambda x: x[1], reverse=True):
        if size > 100:
            print(f"{size:5d} bytes: {symbol}")
            count += 1
            if count >= 30:
                break
    
    if count == 0:
        print("No large symbols found. Trying alternative parsing...")
        # Try to find symbols with a simpler grep
        print("\nSearching for function symbols in map file...")
        for line in lines:
            if re.search(r'(0x[0-9a-f]+)\s+(0x[0-9a-f]+).*(main|crypto|ristretto|address|format)', line, re.IGNORECASE):
                print(line.strip())

if __name__ == "__main__":
    filename = sys.argv[1] if len(sys.argv) > 1 else "app.map"
    analyze_map(filename)
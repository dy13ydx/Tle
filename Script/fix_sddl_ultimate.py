import sys
import re
import argparse

def clean_input(raw_data):
    """
    Removes whitespace, newlines, and common prefixes to ensure 
    one continuous, clean SDDL string.
    """
    # Remove common LDAP prefix if present
    if "nTSecurityDescriptor: " in raw_data:
        raw_data = raw_data.replace("nTSecurityDescriptor: ", "")
    
    # Remove all whitespace and newlines (LDAP line-wrapping fix)
    return "".join(raw_data.split())

def bitmask_to_sddl(hex_str):
    """
    Converts a hex string into a standard 2-letter SDDL code string.
    Reference: [MS-DTYP] 2.4.4.6
    """
    try:
        val = int(hex_str, 16)
    except ValueError:
        return hex_str

    # 1. Handle Full Control Shortcuts first
    if (val & 0x1F01FF) == 0x1F01FF: return "GA" # Generic All
    if val == 0xF01FF: return "GA"
    if val == 0x20094: return "RPLC" # Read Prop + List Contents

    # 2. Comprehensive Bit Mapping (The "Ultimate" List)
    bits = [
        # --- ADS Specific Rights ---
        (0x1, "CC"),      # Create Child
        (0x2, "DC"),      # Delete Child
        (0x4, "LC"),      # List Children
        (0x8, "SW"),      # Self Write
        (0x10, "RP"),     # Read Property
        (0x20, "WP"),     # Write Property
        (0x40, "DT"),     # Delete Tree
        (0x80, "LO"),     # List Object
        (0x100, "CR"),    # Control Access (Extended Right)
        
        # --- Standard Access Rights ---
        (0x10000, "SD"),  # Standard Delete
        (0x20000, "RC"),  # Read Control (Read Permissions)
        (0x40000, "WD"),  # Write DAC (Change Permissions)
        (0x80000, "WO"),  # Write Owner
        (0x100000, "SY"), # Synchronize (Rare in AD, but valid)
    ]

    result = []
    for mask, code in bits:
        if val & mask:
            result.append(code)

    # If we found matches, return the clean code.
    # If val was 0 (no rights) or completely unknown, return original hex 
    # to alert the user rather than failing silently.
    return "".join(result) if result else hex_str

def fix_sddl_ultimate(sddl_string):
    # Pattern: Semicolon, Hex (0x...), Semicolon
    pattern = re.compile(r';(0x[0-9a-fA-F]+);')

    def replace_match(match):
        hex_val = match.group(1).lower()
        new_code = bitmask_to_sddl(hex_val)
        return f";{new_code};"

    return pattern.sub(replace_match, sddl_string)

def main():
    parser = argparse.ArgumentParser(
        description="Ultimate SDDL Fixer: Handles formatting issues and all permission bits.",
        epilog="Usage: python3 fix_sddl_ultimate.py -f sddl.txt"
    )
    parser.add_argument("input", nargs="?", help="SDDL string (in quotes).")
    parser.add_argument("-f", "--file", help="Path to file containing SDDL.")

    args = parser.parse_args()

    raw_input = ""
    
    # 1. Input Source Logic
    if args.file:
        try:
            with open(args.file, 'r') as f:
                raw_input = f.read()
        except FileNotFoundError:
            print(f"[-] Error: File '{args.file}' not found.")
            sys.exit(1)
    elif args.input:
        raw_input = args.input
    elif not sys.stdin.isatty():
        raw_input = sys.stdin.read()
    else:
        parser.print_help()
        sys.exit(1)

    # 2. Sanitize (Fix Line Wraps)
    clean_text = clean_input(raw_input)
    
    # 3. Process Hex Values
    fixed_output = fix_sddl_ultimate(clean_text)

    # 4. Output
    print("\n" + "=" * 60)
    print(f"[*] Input Size: {len(raw_input)} chars | Clean Size: {len(clean_text)} chars")
    print("[*] FIXED SDDL (Copy below for wconv):")
    print("=" * 60)
    print(fixed_output)
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()

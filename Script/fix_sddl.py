import sys
import re
import argparse

def fix_sddl_hex(sddl_string):
    """
    Parses an SDDL string and replaces known AD hex permission masks 
    with their standard 2-letter SDDL codes for tools like wconv.
    """
    
    # Mapping Hex values to standard SDDL shorthands
    # This strictly translates specific hex codes to standard text codes.
    hex_map = {
        "0x30": "RPWP",       # Read + Write Property
        "0x3": "CCDC",        # Create + Delete Child
        "0x130": "CRRPWP",    # Control Access + Read/Write Prop
        "0xf01ff": "GA",      # Generic All (Full Control)
        "0xf01bd": "GA",      # Full Control (Admin objects)
        "0x20094": "RPLC",    # Read Prop + List Contents + Read Control
        "0x10": "RP",         # Read Property
        "0x20": "WP",         # Write Property
        "0x4": "LC",          # List Contents
        "0x8": "SW",          # Self Write
        "0x100": "CR"         # Control Access (Extended Right)
    }

    # Regex looks for: semicolon, '0x' followed by hex digits, then semicolon
    pattern = re.compile(r';(0x[0-9a-fA-F]+);')

    def replace_match(match):
        hex_val = match.group(1).lower()
        if hex_val in hex_map:
            # Replace valid hex with standard code
            return f";{hex_map[hex_val]};"
        else:
            # Keep unknown values exactly as they are
            return f";{hex_val};"

    return pattern.sub(replace_match, sddl_string)

def main():
    # Setup the argument parser for the help menu (-h)
    parser = argparse.ArgumentParser(
        description="A helper tool to fix raw SDDL strings from bloodyAD for use with wconv.",
        epilog="Example: python3 fix_sddl.py 'O:S-1-5-21...'"
    )
    
    parser.add_argument(
        "sddl_string", 
        nargs="?", 
        help="The raw SDDL string inside single quotes."
    )

    args = parser.parse_args()

    # If no input is provided, show help and exit
    if not args.sddl_string:
        parser.print_help()
        sys.exit(1)

    raw_input = args.sddl_string
    fixed_output = fix_sddl_hex(raw_input)

    # --- OUTPUT DECORATION ---
    print("\n" + "-" * 50)
    print(f"[*] Input SDDL Length: {len(raw_input)} chars")
    print("-" * 50)
    
    # Print the clean result clearly separated
    print("\n" + "=" * 50)
    print("[+] FIXED SDDL (Ready for wconv):")
    print("=" * 50)
    print(fixed_output)
    print("=" * 50 + "\n")

if __name__ == "__main__":
    main()

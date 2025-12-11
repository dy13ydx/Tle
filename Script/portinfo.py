import urllib.request
import urllib.error
import json
import concurrent.futures
import argparse
import sys
import textwrap
import shutil  # NEW: For getting terminal size
from html.parser import HTMLParser
from itertools import zip_longest

# --- 1. Custom HTML Parser ---
class SpeedGuideParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_table = False
        self.in_row = False
        self.in_cell = False
        self.current_row = []
        self.all_rows = []
        self.cell_data = ""

    def handle_starttag(self, tag, attrs):
        if tag == 'table':
            self.in_table = True
        elif tag == 'tr' and self.in_table:
            self.in_row = True
            self.current_row = []
        elif (tag == 'td' or tag == 'th') and self.in_row:
            self.in_cell = True
            self.cell_data = ""

    def handle_endtag(self, tag):
        if tag == 'table':
            self.in_table = False
        elif tag == 'tr':
            self.in_row = False
            if self.current_row:
                self.all_rows.append(self.current_row)
        elif (tag == 'td' or tag == 'th'):
            self.in_cell = False
            self.current_row.append(self.cell_data.strip())

    def handle_data(self, data):
        if self.in_cell:
            self.cell_data += data

# --- 2. Networking Logic ---
def fetch_url(port):
    url = f"https://www.speedguide.net/port.php?port={port}"
    headers = {'User-Agent': 'Mozilla/5.0'} 
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.read().decode('utf-8')
    except Exception as e:
        print(f"[-] Error fetching port {port}: {e}", file=sys.stderr)
        return None

def parse_html_to_dict(html_content):
    parser = SpeedGuideParser()
    parser.feed(html_content)
    
    clean_data = []
    headers = []
    
    for row in parser.all_rows:
        if not row: continue
        
        if 'Service' in row and 'Port(s)' in row:
            headers = row
            continue

        if headers and len(row) == len(headers):
            row_dict = dict(zip(headers, row))
            clean_data.append({
                "name": row_dict.get('Service', 'N/A'),
                "port": row_dict.get('Port(s)', 'N/A'),
                "protocol": row_dict.get('Protocol', 'N/A'),
                "description": row_dict.get('Details', 'N/A')
            })
            
    return clean_data

def lookup_ports(port_list):
    final_list = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_port = {executor.submit(fetch_url, port): port for port in port_list}
        
        for future in concurrent.futures.as_completed(future_to_port):
            html = future.result()
            if html:
                data = parse_html_to_dict(html)
                final_list.extend(data)
    return final_list

# --- 3. Dynamic Display Logic ---
def print_table(data):
    if not data:
        print("No results found.")
        return

    # A. Get current terminal width
    # fallback=(80, 20) ensures it doesn't crash if it can't detect size
    terminal_width = shutil.get_terminal_size(fallback=(80, 20)).columns

    # B. Define Fixed Widths
    # We keep Name, Port, and Protocol semi-fixed because they are usually short.
    w_name = 25
    w_port = 8
    w_proto = 8
    padding = 4 # 1 space between each of the 4 columns
    
    # C. Calculate Dynamic Description Width
    # Description gets whatever space is left
    w_desc = terminal_width - (w_name + w_port + w_proto + padding)
    
    # Safety: ensure w_desc is at least 10 chars so it doesn't crash on tiny screens
    if w_desc < 10:
        w_desc = 10

    # D. Print Header
    header = f"{'Name':<{w_name}} {'Port':<{w_port}} {'Protocol':<{w_proto}} {'Description':<{w_desc}}"
    print("-" * terminal_width) # Divider matches full screen width
    print(header)
    print("-" * terminal_width)
    
    for item in data:
        # E. Wrap text using the calculated widths
        name_lines = textwrap.wrap(str(item['name']), width=w_name)
        port_lines = textwrap.wrap(str(item['port']), width=w_port)
        proto_lines = textwrap.wrap(str(item['protocol']), width=w_proto)
        desc_lines = textwrap.wrap(str(item['description']), width=w_desc)

        for n, p, pr, d in zip_longest(name_lines, port_lines, proto_lines, desc_lines, fillvalue=""):
            print(f"{n:<{w_name}} {p:<{w_port}} {pr:<{w_proto}} {d:<{w_desc}}")

def main():
    parser = argparse.ArgumentParser(description="Lookup port details from SpeedGuide.net")
    parser.add_argument('ports', metavar='PORT', type=int, nargs='+', help='List of ports')
    parser.add_argument('--json', action='store_true', help='Output in JSON')

    args = parser.parse_args()
    results = lookup_ports(args.ports)

    if args.json:
        print(json.dumps(results, indent=4))
    else:
        print_table(results)

if __name__ == "__main__":
    main()

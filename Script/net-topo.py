#!/usr/bin/env python3
import argparse
import ipaddress
import re
import sys

COLOR = "\033[38;2;159;239;0m\033[1m"
RESET = "\033[0m"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate clean ASCII simple network topology diagrams for pivoting and multi-subnet network.",
        epilog="""
Constraints & Rules:
  1. Input file must have one host entry per line.
  2. Format: 'Hostname: IP1, IP2' OR simply 'IP1, IP2'.
  3. If no hostname is provided, the script assigns 'Host <line_number>'.
  4. Subnet Mask Constraint: Assumes standard /24 (Class C, X.X.X.0) if no CIDR is explicitly provided.
  5. Multi-homed pivot hosts and their direct backbone paths are highlighted in green (#9FEF00) by default.

Flags:
  --pivot      Isolate and display only multi-homed pivot jump hosts (eliminates leaf clutter).
  --no-color   Disable ANSI color codes and wrap output in markdown code fences for note copying.

Example Input File:
172.18.0.2, 172.19.0.3
Web-DMZ: 172.19.0.2
172.19.0.4, 172.20.0.4
172.19.0.5
172.19.0.6
172.20.0.2
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Path to the targets file containing host names and IPs.",
    )
    parser.add_argument(
        "--pivot",
        action="store_true",
        help="Display only the multi-homed pivot backbone and suppress single-homed leaf hosts.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes and format output for Markdown notes.",
    )
    return parser.parse_args()


def parse_input_file(filepath):
    hosts = []
    try:
        with open(filepath, "r") as f:
            for line_idx, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue

                if ":" in clean_line:
                    parts = clean_line.split(":", 1)
                    hostname = parts[0].strip()
                    ips_raw = parts[1].strip()
                else:
                    hostname = f"Host {line_idx}"
                    ips_raw = clean_line

                ips = [
                    ip.strip()
                    for ip in re.split(r"[,\s]+", ips_raw)
                    if ip.strip()
                ]
                if ips:
                    hosts.append({"name": hostname, "ips": ips})
    except FileNotFoundError:
        sys.stderr.write(f"[-] Error: File not found: {filepath}\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"[-] Error reading input file: {e}\n")
        sys.exit(1)

    return hosts


def extract_subnet(ip_str):
    try:
        if "/" in ip_str:
            iface = ipaddress.IPv4Interface(ip_str)
        else:
            iface = ipaddress.IPv4Interface(f"{ip_str}/24")
        return str(iface.network)
    except ValueError:
        return "Unknown_Network"


def make_box(hostname, ips, is_pivot=False, use_color=True, box_width=25):
    ip_str = "/".join(ips)
    h_centered = hostname[: box_width - 4].center(box_width - 4)
    ip_centered = ip_str[: box_width - 4].center(box_width - 4)

    border = "+" + "-" * (box_width - 2) + "+"
    h_line = f"| {h_centered} |"
    ip_line = f"| {ip_centered} |"

    if is_pivot and use_color:
        return [
            f"{COLOR}{border}{RESET}",
            f"{COLOR}{h_line}{RESET}",
            f"{COLOR}{ip_line}{RESET}",
            f"{COLOR}{border}{RESET}",
        ]

    return [border, h_line, ip_line, border]


def render_topology(hosts, use_color=True, pivot_only=False):
    if not hosts:
        return "[-] No hosts to map."

    for h in hosts:
        h["nets"] = [extract_subnet(ip) for ip in h["ips"]]

    if pivot_only:
        hosts = [h for h in hosts if len(h["nets"]) > 1]
        if not hosts:
            return "[-] No multi-homed pivot hosts detected."

    processed = set()
    levels = []

    first_net = hosts[0]["nets"][0]
    current_net = first_net

    while len(processed) < len(hosts):
        level = [
            h
            for h in hosts
            if h["name"] not in processed and current_net in h["nets"]
        ]

        if not level:
            remaining = [h for h in hosts if h["name"] not in processed]
            if remaining:
                level = [remaining[0]]
                current_net = remaining[0]["nets"][0]
            else:
                break

        level = sorted(
            level,
            key=lambda h: ipaddress.IPv4Address(re.sub(r"/.*", "", h["ips"][0]))
            if not h["ips"][0].startswith("Unknown")
            else 0,
        )

        levels.append(level)
        for h in level:
            processed.add(h["name"])

        next_net = None
        for h in level:
            downstream = [n for n in h["nets"] if n != current_net]
            if downstream:
                next_net = downstream[0]
                break

        if next_net:
            current_net = next_net
        else:
            remaining_hosts = [h for h in hosts if h["name"] not in processed]
            if remaining_hosts:
                current_net = remaining_hosts[0]["nets"][0]
            else:
                break

    BOX_WIDTH = 25
    BOX_GAP = 3
    MID = BOX_WIDTH // 2

    output_lines = []

    for lvl_idx, level in enumerate(levels):
        box_matrices = [
            make_box(
                h["name"],
                h["ips"],
                is_pivot=(len(h["nets"]) > 1),
                use_color=use_color,
                box_width=BOX_WIDTH,
            )
            for h in level
        ]
        num_rows = 4

        for row_i in range(num_rows):
            line_parts = [b[row_i] for b in box_matrices]
            output_lines.append((" " * BOX_GAP).join(line_parts))

        if lvl_idx < len(levels) - 1:
            next_level = levels[lvl_idx + 1]

            next_nets = {net for h in next_level for net in h["nets"]}
            pivot_indices = [
                idx
                for idx, h in enumerate(level)
                if any(net in next_nets for net in h["nets"])
            ]
            pivot_idx = pivot_indices[0] if pivot_indices else 0
            pivot_center = pivot_idx * (BOX_WIDTH + BOX_GAP) + MID

            child_pivot_indices = [
                idx for idx, h in enumerate(next_level) if len(h["nets"]) > 1
            ]
            child_pivot_idx = (
                child_pivot_indices[0] if child_pivot_indices else None
            )
            child_pivot_center = (
                child_pivot_idx * (BOX_WIDTH + BOX_GAP) + MID
                if child_pivot_idx is not None
                else None
            )

            shared_nets = {
                net
                for h in level[pivot_idx : pivot_idx + 1]
                for net in h["nets"]
            }.intersection(next_nets)
            shared_label = list(shared_nets)[0] if shared_nets else ""
            label_text = f" ({shared_label})" if shared_label else ""

            is_pivot_stem = (child_pivot_center is not None) or pivot_only

            # 1. Pivot Drop Pipe
            if use_color and is_pivot_stem:
                output_lines.append(
                    f"{' ' * pivot_center}{COLOR}|{RESET}{label_text}"
                )
            else:
                output_lines.append(f"{' ' * pivot_center}|{label_text}")

            dest_centers = [
                i * (BOX_WIDTH + BOX_GAP) + MID for i in range(len(next_level))
            ]
            min_c = min(dest_centers + [pivot_center])
            max_c = max(dest_centers + [pivot_center])

            if len(dest_centers) > 1 or min_c != max_c:
                # 2. Horizontal Branch Bar with selective character-level coloring
                bar_chars = list(" " * (max_c + 1))
                for c in range(min_c, max_c + 1):
                    bar_chars[c] = "-"
                bar_chars[pivot_center] = "+"
                for c in dest_centers:
                    bar_chars[c] = "+"

                green_span_start, green_span_end = None, None
                if child_pivot_center is not None:
                    green_span_start = min(pivot_center, child_pivot_center)
                    green_span_end = max(pivot_center, child_pivot_center)

                colored_bar = []
                for idx_char, ch in enumerate(bar_chars):
                    if (
                        use_color
                        and green_span_start is not None
                        and green_span_start <= idx_char <= green_span_end
                    ):
                        colored_bar.append(f"{COLOR}{ch}{RESET}")
                    else:
                        colored_bar.append(ch)
                output_lines.append("".join(colored_bar).rstrip())

                # 3. Vertical Drops into destination boxes
                drop_chars = list(" " * (max_c + 1))
                for c in dest_centers:
                    drop_chars[c] = "|"

                colored_drops = []
                for idx_char, ch in enumerate(drop_chars):
                    if (
                        use_color
                        and child_pivot_center is not None
                        and idx_char == child_pivot_center
                    ):
                        colored_drops.append(f"{COLOR}{ch}{RESET}")
                    else:
                        colored_drops.append(ch)
                output_lines.append("".join(colored_drops).rstrip())

            else:
                # Single vertical connector
                target_center = dest_centers[0]
                if use_color and is_pivot_stem:
                    output_lines.append(
                        f"{' ' * target_center}{COLOR}|{RESET}"
                    )
                else:
                    output_lines.append(f"{' ' * target_center}|")

    return "\n".join(output_lines)


def main():
    args = parse_args()

    if not args.file:
        sys.stderr.write(
            "[-] Error: Target file required. Run with -h or --help for instructions.\n"
        )
        sys.exit(1)

    hosts = parse_input_file(args.file)
    use_color = not args.no_color

    if not use_color:
        print("```text")
    print(
        render_topology(
            hosts, use_color=use_color, pivot_only=args.pivot
        )
    )
    if not use_color:
        print("```")


if __name__ == "__main__":
    main()

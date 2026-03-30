#!/usr/bin/env python3

import json
import argparse
import sys
from collections import Counter, defaultdict

def analyze_log(input_file):
    stats = {
        'total_queries': 0,
        'clients': Counter(),
        'qtypes': Counter(),
        'client_qtypes': defaultdict(Counter),
        'client_resolutions': defaultdict(lambda: defaultdict(set))
    }

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    print(f"Warning: Invalid JSON on line {line_no}", file=sys.stderr)
                    continue

                action = record.get('action')
                if not action:
                    continue

                if action == 'query':
                    stats['total_queries'] += 1
                    client = record.get('client')
                    qtype = record.get('qtype')
                    if client:
                        stats['clients'][client] += 1
                    if qtype:
                        stats['qtypes'][qtype] += 1
                    if client and qtype:
                        stats['client_qtypes'][client][qtype] += 1

                elif action == 'proxy':
                    client = record.get('client')
                    qname = record.get('qname')
                    answers = record.get('answers', [])
                    if answers is None:
                        answers = []
                    elif isinstance(answers, str):
                        answers = [answers]
                    elif not isinstance(answers, (list, tuple, set)):
                        answers = [str(answers)]
                    if client and qname:
                        for answer in answers:
                            if answer:
                                stats['client_resolutions'][client][qname].add(str(answer))

                elif action == 'spoof':
                    client = record.get('client')
                    qname = record.get('qname')
                    value = record.get('value')
                    if client and qname and value is not None:
                        if isinstance(value, dict):
                            for v in value.values():
                                if v is not None:
                                    stats['client_resolutions'][client][qname].add(str(v))
                        else:
                            stats['client_resolutions'][client][qname].add(str(value))

    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{input_file}': {e}", file=sys.stderr)
        sys.exit(1)
    
    return stats

def generate_report(stats):
    report = []
    report.append("=" * 60)
    report.append(" DNSChef Statistics Report ".center(60, "="))
    report.append("=" * 60)
    
    report.append(f"\nTotal Queries: {stats['total_queries']}")
    
    report.append("\nClients:")
    for client, count in stats['clients'].most_common():
        report.append(f"  - {client}: {count} queries")
    if not stats['clients']:
        report.append("  (none)")

    report.append("\nQuery Types:")
    for qtype, count in stats['qtypes'].most_common():
        report.append(f"  - {qtype}: {count}")
    if not stats['qtypes']:
        report.append("  (none)")

    report.append("\nQuery Types by Client:")
    if not stats['client_qtypes']:
        report.append("  (none)")
    else:
        for client in sorted(stats['client_qtypes'].keys()):
            report.append(f"  [Client: {client}]")
            for qtype, count in stats['client_qtypes'][client].most_common():
                report.append(f"    - {qtype}: {count}")

    report.append("\nUnique DNS Names and Resolutions (by Client):")
    if not stats['client_resolutions']:
        report.append("  (no resolutions found)")
    else:
        for client in sorted(stats['client_resolutions'].keys()):
            report.append(f"\n  [Client: {client}]")
            client_res = stats['client_resolutions'][client]
            for domain in sorted(client_res.keys()):
                resolutions = sorted(list(client_res[domain]))
                if resolutions:
                    report.append(f"    - {domain} -> {', '.join(resolutions)}")

    report.append("\n" + "=" * 60)
    return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description="Generate statistics from DNSChef JSON log.")
    parser.add_argument("-i", "--input", help="Path to the input JSON log file", required=True)
    parser.add_argument("-o", "--output", help="Path to the output statistics file", required=True)
    
    args = parser.parse_args()

    stats = analyze_log(args.input)
    report_text = generate_report(stats)

    # Print to screen
    print(report_text)

    # Write to output file
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report_text + '\n')
        print(f"\n[+] Statistics successfully saved to {args.output}")
    except Exception as e:
        print(f"[-] Error writing to output file '{args.output}': {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

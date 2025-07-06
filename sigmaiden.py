import os
import re
from rigmaiden import Rigmaiden
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import random

LOG_FILE = 'ironmaiden_events.log'

SIGMA_RULE_TEMPLATES = [
    'detection:\n  selection:\n    IMSI: "{imsi}"\n  condition: selection',
    'detection:\n  selection:\n    Location: "{location}"\n  condition: selection',
    'detection:\n  selection:\n    Timestamp: "{timestamp}"\n  condition: selection',
]

def parse_log():
    if not os.path.exists(LOG_FILE):
        print("No events logged yet.")
        return []
    events = []
    with open(LOG_FILE, 'r') as f:
        for line in f:
            m = re.match(r'([^|]+)\| IMSI: ([0-9]+) \| Location: (.+)', line.strip())
            if m:
                timestamp, imsi, location = m.groups()
                events.append({
                    'timestamp': timestamp.strip(),
                    'imsi': imsi.strip(),
                    'location': location.strip()
                })
    return events

def analyze_events(events):
    if not events:
        print("No events to analyze.")
        return
    imsis = [e['imsi'] for e in events]
    locations = [e['location'] for e in events]
    times = [datetime.strptime(e['timestamp'], '%Y-%m-%d %H:%M:%S') for e in events]

    imsi_counts = Counter(imsis)
    location_counts = Counter(locations)

    bursts = []
    times_sorted = sorted(times)
    for i in range(len(times_sorted) - 2):
        if (times_sorted[i+2] - times_sorted[i]) <= timedelta(minutes=1):
            bursts.append((times_sorted[i], times_sorted[i+2]))
    bursts = list(set(bursts))

    print("\n=== Sigmaiden Threat Intelligence Report ===")
    print(f"Total events analyzed: {len(events)}")
    print(f"Unique IMSIs: {len(imsi_counts)}")
    print(f"Unique locations: {len(location_counts)}")
    print("\nTop IMSIs:")
    for imsi, count in imsi_counts.most_common(3):
        print(f"  {imsi}: {count} events")
    print("\nTop Locations:")
    for loc, count in location_counts.most_common(3):
        print(f"  {loc}: {count} events")
    if bursts:
        print(f"\nDetected {len(bursts)} event burst(s) (3+ events in 1 minute):")
        for start, end in bursts:
            print(f"  Burst from {start.strftime('%Y-%m-%d %H:%M:%S')} to {end.strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        print("\nNo significant event bursts detected.")
    print("\n==========================================\n")

def generate_sigma_rules(events, n=3):
    if not events:
        return
    print("Fake Sigma Rules for IMSI-Catcher Detection:")
    for _ in range(n):
        event = random.choice(events)
        template = random.choice(SIGMA_RULE_TEMPLATES)
        rule = template.format(**event)
        print(f"---\n{rule}\n")

def main():
    events = parse_log()
    analyze_events(events)
    generate_sigma_rules(events)

if __name__ == '__main__':
    main() 

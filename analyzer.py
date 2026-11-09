# Python Log Analyzer for Threat Hunting
# Reads sample_logs.txt and flags:
# - brute-force logins (5 or more failed logins from one IP)
# - port scans (4 or more different ports from one IP)
# - large payments (over $1000)
#
# Sample data only. All IPs are documentation ranges, all amounts are fake,
# for learning and portfolio use. No real users, no real money.
#
# Run: python3 analyzer.py

from collections import Counter, defaultdict

with open("sample_logs.txt") as f:
    lines = f.readlines()

print(f"Total log lines: {len(lines)}")

# --- Brute-force detection ---
failed_ips = []
for line in lines:
    parts = line.split()
    if len(parts) >= 4 and parts[3] == "LOGIN_FAILED":
        failed_ips.append(parts[2])

failed = Counter(failed_ips)
print("Failed logins per IP:", dict(failed))

for ip, count in failed.items():
    if count >= 5:
        print(f"ALERT: Possible brute force - {count} failed logins from {ip}")

# --- Port-scan detection ---
ports_by_ip = defaultdict(set)
for line in lines:
    parts = line.split()
    if len(parts) >= 5 and parts[3] == "PORT":
        ports_by_ip[parts[2]].add(parts[4])

print("Ports touched per IP:", {ip: sorted(ports) for ip, ports in ports_by_ip.items()})

for ip, ports in ports_by_ip.items():
    if len(ports) >= 4:
        print(f"ALERT: Possible port scan - {ip} touched {len(ports)} ports: {sorted(ports)}")

# --- Large-payment detection ---
print("Large payments over $1000:")
for line in lines:
    parts = line.split()
    if len(parts) >= 6 and parts[3] == "PAYMENT":
        amount = int(parts[5].split("=")[1])
        if amount > 1000:
            print(f"ALERT: Large payment - {line.strip()}")

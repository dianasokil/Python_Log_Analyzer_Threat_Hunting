# Python Log Analyzer for Threat Hunting

A Python tool that reads a log file and flags suspicious activity: brute-force logins, port scans, and unusually large payments.

Built step by step in Ubuntu (Python 3.14), with plain Python only, no extra libraries.

## What it does

It reads `sample_logs.txt`, 19 lines, and checks three rules:

1. **Brute force** — 5 or more failed logins from the same IP
2. **Port scan** — 4 or more different ports touched by the same IP
3. **Large payment** — a payment over $1,000

Normal activity in the sample is a few successful logins and payments of $28 and $480. The attack chain in the sample is:

- 09:10 — 6 failed logins for `org_003` from `198.51.100.99`
- 09:11 — a successful login for `org_003` from that same new IP
- 09:12 — that IP touches 5 ports: 22, 80, 443, 3389, 8080
- 09:15 — a $4,800 payment for `org_003`

One alert alone could be a mistake. The three together, for the same user in 5 minutes, is the incident. Note the payment line itself shows `203.0.113.30`, the normal IP for `org_003`, because the attacker logged in as `org_003`, so the payment looks like it came from that user.

## Log format

Each line is:

```
date time IP event user-or-detail
```

Examples:

```
2026-11-08 09:10:01 198.51.100.99 LOGIN_FAILED org_003
2026-11-08 09:12:10 198.51.100.99 PORT 22
2026-11-08 09:15:20 203.0.113.30 PAYMENT org_003 amount=4800
```

## How to run it

```bash
python3 analyzer.py
```

## Sample output

```
Total log lines: 19
Failed logins per IP: {'198.51.100.99': 6}
ALERT: Possible brute force - 6 failed logins from 198.51.100.99
Ports touched per IP: {'198.51.100.99': ['22', '3389', '443', '80', '8080']}
ALERT: Possible port scan - 198.51.100.99 touched 5 ports: ['22', '3389', '443', '80', '8080']
Large payments over $1000:
ALERT: Large payment - 2026-11-08 09:15:20 203.0.113.30 PAYMENT org_003 amount=4800
```

## How it works

- `line.split()` cuts each log line into pieces by spaces: date is piece 0, time is 1, IP is 2, event is 3.
- `Counter` counts how many failed logins each IP has.
- A `set` collects the different ports each IP touched, so touching the same port twice still counts as 1.
- `amount=4800` is split on `=` to get the number, then compared to the $1,000 threshold.
- Each detector is the same pattern: filter by event, count per IP, compare to a threshold, print an alert if it is over.

To make a new detector, change the event word, the piece number, and the threshold.

## Files

- `analyzer.py` — the analyzer
- `sample_logs.txt` — the sample log file, 19 lines

## Note

All data in this project is simulated for learning. IPs are documentation ranges (`203.0.113.x`, `198.51.100.99`), amounts are fake, and there are no real users or real money.

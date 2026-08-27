# Sample logs

Synthetic corpus for `log-sentinel analyze samples/`. Every address is from RFC 5737 TEST-NET (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or RFC 1918. No real victims, credentials, or hosts.

Day of traffic: **2026-08-26 UTC**. Hosts: `jump` (sshd), `www1` (nginx), `fw1` (firewall).

## Files

| File | Format | Parser |
|---|---|---|
| `auth.log` | rsyslog ISO + sshd | `parsers.parse_auth_line` |
| `nginx_access.log` | nginx combined | `parsers.parse_nginx_line` |
| `firewall.log` | `ts action proto src_ip src_port dst_ip dst_port bytes rule` | `parsers.parse_firewall_line` |

## Planted scenarios

These **will** fire with the default `rules/detections.yaml`.

### 1. Web probing then SSH brute-force success — `203.0.113.50` vs `alice` (AUTH-001, WEB-001)

Campaign-style sequence used as the primary incident in `out/incident_report.md`.

- **11:28–11:30** nginx: SQLi (`' OR 1=1--`, `UNION SELECT`), XSS (`<script>`, `onerror=`), path traversal (`../../etc/passwd`) from `203.0.113.50` (synthetic geo: Moscow, RU). Mixed with two benign GETs so the IP is not 100% malicious in the access log.
- **11:40–11:43** sshd: 12 `Failed password for alice` then `Accepted password for alice` from the same IP.
- Firewall shows the late SSH allow after earlier denies.

### 2. Impossible travel — user `bob` (AUTH-002)

- **14:02** successful SSH from `198.51.100.10` (New York, US).
- **14:24** successful SSH from `203.0.113.80` (Tokyo, JP).
- ~10,800 km in 22 minutes. Earlier the same day bob had a normal internal login from `10.0.2.8` (not part of this pair).

### 3. Horizontal scan — `198.51.100.77` (NET-001)

- **11:02** eighteen `deny` rows against `10.0.1.1`–`10.0.1.18` port 22, plus 445 and 3389 on two more hosts. Synthetic geo: Frankfurt, DE.

### 4. After-hours admin — user `admin` (AUTH-003)

- **03:14** `Accepted password for admin` from `198.51.100.200` (Frankfurt, DE). Business hours in rules: 08:00–18:00 UTC.
- Contrast: `admin` also logs in at **08:02** from `10.0.0.8` (internal, in-hours) — that row must **not** fire this rule.

### 5. Password spray — `203.0.113.91` (AUTH-004)

- **19:02–19:03** one failed SSH each for 12 common usernames (`root`, `admin`, `ubuntu`, …) from `203.0.113.91`.
- Must **not** fire AUTH-001 (brute force is many fails against one user). Spray is many users, few tries each.

## Benign noise (must not fire AUTH-001)

- Internet background: 2–3 failed attempts for `root` / `test` / `ubuntu` / `oracle` from `192.0.2.88`, `203.0.113.14`, `198.51.100.33` (below the fail threshold, no success).
- Employee traffic: alice, bob, carol, dave, evan during business hours from `10.0.2.0/24` and VPN `192.0.2.10`.
- kube-probe `/healthz`, 404s for `/wp-login.php` and `/xmlrpc.php`, DNS and SaaS allows.

## Geo cheat-sheet (see `src/log_sentinel/geo.py`)

| CIDR / IP | City |
|---|---|
| `10.0.0.0/8` | San Francisco (internal) |
| `192.0.2.0/24` | San Francisco (HQ VPN) |
| `198.51.100.10` | New York |
| `198.51.100.0/24` | Frankfurt |
| `203.0.113.50` | Moscow |
| `203.0.113.80` | Tokyo |
| `203.0.113.0/24` | London (default) |

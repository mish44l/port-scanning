# NetGuard — Network Security Scanner & Firewall Visualizer

A Flask-based educational network scanner and firewall **simulator**. It does not change the host's real firewall configuration.

## Setup (Windows / macOS / Linux)

1. Install Python 3.10+.
2. In this folder, create and activate a virtual environment (recommended):
   - Windows: `py -m venv .venv` then `.venv\Scripts\activate`
   - macOS/Linux: `python3 -m venv .venv` then `source .venv/bin/activate`
3. Install packages: `pip install -r requirements.txt`
4. Run: `python app.py`
5. Open **http://127.0.0.1:5000**.

**TCP Full Connect** works with Python alone. For **TCP SYN / UDP**, install the Nmap executable separately from https://nmap.org/download.html, ensure it is in your PATH, and run with appropriate OS privileges (administrator/root may be necessary). SYN/UDP scanning is optional for environments without Nmap.

## Features

- Scan authorized localhost/private IPv4 addresses or resolving hostnames.
- TCP Connect scans with standard Python sockets; SYN and UDP scans via Nmap.
- Custom port lists and ranges, max 256 ports per request.
- Results: IP, port, protocol, service, state; open/closed/other counts and elapsed time.
- Firewall rules: allow/deny, source IP or CIDR, port, protocol, priority.
- First matching rule (lowest priority number first); ties follow insertion order; default allow.
- Create, edit, delete rules and visualize simulated packet decisions.
- Last 20 scans and CSV export (in memory; lost when server restarts).
- Responsive dashboard, status labels, error messages.

## Quick demonstration

1. Start the app and scan `127.0.0.1` with ports `22,80,443,5000` using TCP Full Connect. Since the dashboard uses port 5000, it should normally appear **open**.
2. Create a rule: **deny**, IP `192.168.1.0/24`, port `443`, protocol `tcp`, priority `10`.
3. Create another rule: **allow**, IP `any`, port `443`, protocol `tcp`, priority `100`.
4. Simulate `192.168.1.15`, TCP, port `443` → **BLOCKED** (priority 10).
5. Simulate `10.0.0.5`, TCP, port `443` → **ALLOWED** (priority 100).
6. Change the first rule's priority to `200` → same packet is **ALLOWED** by priority 100.
7. Delete a rule; export a scan CSV; view history.

## Important limitations

- Use only on networks you own or have explicit permission to assess. Public IP scans are blocked.
- Scan output alone **does not confirm vulnerabilities**. The dashboard reports exposed services as indicators for further authorized review, not CVEs or exploitability.
- UDP `open|filtered` and similar ambiguous states are normal; UDP scans can be slow.
- Nmap scans may time out, and administrator privileges may be required.
- The simulator evaluates user-defined policies; it does **not** intercept live traffic.
- This is a single-user local demo; no authentication or persistence. Do not expose it publicly.

## Architecture

`Browser UI (HTML/CSS/JS) → Flask REST API → socket/Nmap scan engine`

`Browser traffic form → Flask priority-based firewall evaluation → decision → visual flow`

### REST endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/scan` | POST | Scan target/ports/mode |
| `/api/rules` | GET, POST | List/add rules |
| `/api/rules/<id>` | PUT, DELETE | Edit/delete rule |
| `/api/simulate` | POST | Simulate a packet |
| `/api/history` | GET | Scan metadata |
| `/api/export/<id>` | GET | Download CSV |

## Test checklist

- [ ] Invalid hostname displays an error.
- [ ] Public IP is rejected.
- [ ] Invalid port or >256 ports is rejected.
- [ ] Localhost TCP scan shows port 5000 open while server runs.
- [ ] Rules match IP/CIDR, port, protocol.
- [ ] Lower priority number takes precedence.
- [ ] Default allow works with no matching rule.
- [ ] Edit/delete work.
- [ ] CSV export contains result columns.
- [ ] History shows recent scans.
- [ ] SYN/UDP scan works when Nmap and permissions are available.

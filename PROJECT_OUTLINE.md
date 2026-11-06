# MiniSIEM — Project Outline

A lightweight Security Information and Event Management (SIEM) tool that ingests logs, detects suspicious activity, maps it to MITRE ATT&CK, and presents findings in a dashboard.

This document lists **what** to build and the order to build it in. It doesn't cover **how** to build it. Each section is a suggestion; cut, reorder, or expand as the project grows.

---

## 1. Goals

- Show you understand how a SOC turns raw logs into actionable alerts
- Show full-stack ability (ingestion pipeline + API + React dashboard)
- Produce something a recruiter can understand in 60 seconds from the README and screenshots
- Keep scope small enough to finish an MVP, then iterate

## 2. Suggested Scope

### MVP (finish this first)
- Ingest **one** log source end-to-end
- Normalize events into a common schema
- Run a handful of detection rules
- Display alerts in a simple dashboard

### Stretch (after MVP works)
- Multiple log sources
- Real-time / streaming ingestion
- Alert triage workflow (status, assignee, notes)
- Correlation rules across sources
- Reporting/export

## 3. Log Sources to Consider

Pick one for the MVP, then add others:

- **Linux auth logs** (`/var/log/auth.log`, `secure`) for SSH logins, sudo use, failed auths
- **Windows Security Event Logs** (exported EVTX or JSON) for event IDs like 4624, 4625, 4672, 4720, 4732
- **Web server access logs** (Apache/Nginx) for scanning, injection attempts, 4xx/5xx spikes
- **Firewall logs** (pfSense, iptables) for blocked connections and port scans
- **Sysmon logs** for process creation, network connections (good stretch goal)

Consider including **sample log datasets** in the repo so anyone can run the demo without their own environment.

## 4. Architecture to Think About

Components a SIEM typically has. Decide which you'll build and which you'll simplify:

| Component | Purpose | Questions to decide |
|---|---|---|
| **Collector / Ingestor** | Reads raw logs from files or a network listener | File upload? Folder watcher? Syslog listener? |
| **Parser / Normalizer** | Converts each format into one common event schema | What fields are required? How to handle unparseable lines? |
| **Storage** | Keeps events and alerts searchable | SQLite vs. PostgreSQL vs. Elasticsearch/OpenSearch? |
| **Detection Engine** | Runs rules against events, creates alerts | Rules in code vs. YAML/JSON config? Sigma-style format? |
| **API** | Serves events/alerts to the frontend | REST vs. GraphQL? Auth required? |
| **Dashboard** | Visualizes alerts, trends, and event search | Which views matter most to an analyst? |

The repo already has a **React + Vite** frontend scaffold. Decide on the backend language (Python and Node are both reasonable). Python has stronger log/security libraries; Node keeps everything in one language.

## 5. Common Event Schema (fields to consider)

- Timestamp (normalized to UTC)
- Source type (auth, windows, web, firewall)
- Host / hostname
- Source IP / destination IP
- Username
- Event category / action (login, logout, privilege change, process start)
- Outcome (success / failure)
- Raw log line (always keep the original)

Look at the **Elastic Common Schema (ECS)** or **OCSF** for inspiration. Borrowing their naming makes the project look industry-aware.

## 6. Detection Rules to Implement

Start with 4–6 rules. Map each to a MITRE ATT&CK technique.

| Rule idea | ATT&CK mapping (look up and confirm) |
|---|---|
| Brute force: X failed logins from one IP in Y minutes | T1110 – Brute Force |
| Successful login after many failures (possible compromise) | T1110 / T1078 |
| New user account created | T1136 – Create Account |
| User added to admin/privileged group | T1098 – Account Manipulation |
| Login at unusual hour or from new IP for that user | T1078 – Valid Accounts |
| Web scanning / directory enumeration (many 404s) | T1595 – Active Scanning |
| Suspicious commands via sudo | T1548 – Abuse Elevation Control |

Consider:
- Making thresholds configurable
- Assigning a **severity** (low / medium / high / critical) per rule
- Writing rules in a **Sigma-like YAML format**. Sigma is the industry standard and a strong résumé keyword.

## 7. Dashboard Views to Consider

- **Overview:** alert counts by severity, events over time, top source IPs, top targeted users
- **Alerts list:** sortable/filterable table with severity, rule, host, time, status
- **Alert detail:** the triggering events, raw logs, ATT&CK technique link, analyst notes
- **Event search:** filter by time range, host, user, IP, keyword
- **ATT&CK view (stretch):** which techniques have been detected, shown as a heatmap grid

## 8. Security of the Tool Itself

A security tool with obvious holes undercuts the portfolio piece. Think about:

- Authentication on the dashboard and API
- Input validation on uploaded logs (size limits, file types)
- Avoiding injection in search queries
- Not committing secrets (`.env` + `.gitignore`)
- Dependency scanning (Dependabot, `npm audit`, `pip-audit`)

## 9. Testing & Demo

- Unit tests for each parser and each detection rule
- A **"generate attack" script** or sample dataset that reliably triggers every rule. This makes the demo repeatable.
- Consider a `docker-compose` setup so the whole stack starts with one command

## 10. Suggested Milestones

1. **Plan:** pick log source, backend language, storage, schema
2. **Ingest + parse:** one log source into normalized events in storage
3. **Detect:** first 3 rules generating alerts
4. **API:** endpoints for events and alerts
5. **Dashboard:** overview + alerts list
6. **Polish MVP:** README, screenshots, sample data, tests
7. **Expand:** second log source, more rules, ATT&CK mapping view
8. **Stretch:** real-time ingestion, triage workflow, Docker, auth

## 11. README Checklist (for when it's done)

- [ ] One-paragraph summary of what it does and why
- [ ] Architecture diagram
- [ ] Screenshots / GIF of the dashboard
- [ ] Supported log sources and detection rules (with ATT&CK IDs)
- [ ] How to run it (ideally one command)
- [ ] Tech stack
- [ ] What you learned / challenges / future work

## 12. Résumé Keywords This Project Can Back Up

SIEM · Log Analysis · Threat Detection · MITRE ATT&CK · Sigma Rules · Incident Triage · Python/Node.js · React · REST API · SQL · Docker · Security Monitoring · SOC Operations

---

## Related Projects (same portfolio series)

- **File Integrity Monitor:** its change alerts could later feed into MiniSIEM as another log source
- **Network Scanner & Asset Inventory:** asset data could enrich MiniSIEM alerts (e.g., "this IP belongs to a known server")

Linking the three together later gives you a story: *"I built a small security monitoring ecosystem."*

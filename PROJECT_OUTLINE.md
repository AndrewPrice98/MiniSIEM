# MiniSIEM — Project Outline

A lightweight Security Information and Event Management (SIEM) tool that ingests logs, detects suspicious activity, maps it to MITRE ATT&CK, and presents findings in a dashboard.

This document breaks the project into **milestones**, each with ordered **steps** and a **done when** check. It covers **what** to build, not **how**. Cut, reorder, or expand as the project grows. Reference material (log sources, schema fields, rule ideas) is at the bottom.

**Goals**
- Show how a SOC turns raw logs into actionable alerts
- Show full-stack ability (ingestion pipeline + API + React dashboard)
- Produce something a recruiter can understand in 60 seconds from the README and screenshots
- Keep scope small enough to finish an MVP, then iterate

---

## Roadmap at a Glance

| # | Milestone | Phase | Outcome |
|---|---|---|---|
| M0 | Plan & Decide | MVP | Stack, log source, storage, and schema chosen |
| M1 | Ingest & Parse | MVP | One log source lands in storage as normalized events |
| M2 | Detect | MVP | First 3 rules generate alerts |
| M3 | API | MVP | Events and alerts available over HTTP |
| M4 | Dashboard | MVP | Overview and alerts list in React |
| M5 | Polish MVP | MVP | Tests, sample data, README, screenshots, **MVP shipped** |
| M6 | Expand | Post-MVP | Second log source, more rules, ATT&CK view |
| M7 | Harden | Post-MVP | Auth, input validation, dependency scanning |
| M8 | Stretch | Post-MVP | Real-time ingestion, triage workflow, Docker, correlation |

---

## M0: Plan & Decide

**Goal:** Make the decisions everything else depends on.

- [x] **0.1** Pick the MVP log source (see [Log Sources](#a-log-sources)). Linux auth logs are the simplest start.
- [x] **0.2** Pick the backend language (Python: stronger log/security libraries; Node: one language across the stack)
- [x] **0.3** Pick storage (SQLite for MVP simplicity; PostgreSQL or OpenSearch later)
- [x] **0.4** Draft the common event schema (see [Event Schema](#c-common-event-schema)), borrowing ECS or OCSF field names
- [x] **0.5** Decide the rule format (rules in code vs. Sigma-like YAML)
- [x] **0.6** Decide the ingestion method for MVP (file upload, folder watcher, or CLI import)
- [x] **0.7** Sketch the architecture (see [Architecture](#b-architecture-components))
- [x] **0.8** Set up the backend folder, `.env` + `.gitignore`, and a basic run script

**Done when:** Every decision above is written down (in this doc or a `DECISIONS.md`) and the backend skeleton runs.

---

## M1: Ingest & Parse

**Goal:** One log source flows end to end into storage as normalized events.

- [x] **1.1** Collect or create a sample log file for the chosen source and commit it under `samples/`
- [x] **1.2** Build the collector/ingestor that reads the raw log file
- [x] **1.3** Build the parser that turns each line into the common schema
- [x] **1.4** Normalize timestamps to UTC
- [x] **1.5** Always keep the raw log line on each event
- [x] **1.6** Decide and implement handling for unparseable lines (skip + count, or store as "unparsed")
- [x] **1.7** Create the events table/index and write parsed events to it
- [x] **1.8** Write unit tests for the parser (good lines, malformed lines, edge cases)

**Done when:** Running the ingestor on the sample file fills storage with normalized events, and parser tests pass.

---

## M2: Detect

**Goal:** A detection engine turns events into alerts.

- [x] **2.1** Define the alert schema (rule ID, severity, ATT&CK technique, triggering event IDs, timestamp, status)
- [x] **2.2** Build the detection engine that runs rules against stored events
- [x] **2.3** Implement rule 1: **Brute force** (X failed logins from one IP in Y minutes), T1110
- [x] **2.4** Implement rule 2: **Success after many failures** (possible compromise), T1110 / T1078
- [x] **2.5** Implement rule 3: pick one that fits the log source (e.g. suspicious sudo, T1548, or new account, T1136)
- [x] **2.6** Make thresholds configurable
- [x] **2.7** Assign a severity (low / medium / high / critical) to each rule
- [x] **2.8** Store alerts and link them to their triggering events
- [x] **2.9** Write unit tests for each rule (should fire / should not fire)

**Done when:** Running detection on the sample data produces the expected alerts, and rule tests pass.

---

## M3: API

**Goal:** The frontend can read events and alerts over HTTP.

- [x] **3.1** Choose REST (recommended) or GraphQL and set up the server
- [x] **3.2** `GET /alerts` with filters (severity, rule, host, time range) and sorting
- [x] **3.3** `GET /alerts/:id` returning the alert plus its triggering events and raw logs
- [x] **3.4** `GET /events` with filters (time range, host, user, IP, keyword) and pagination
- [x] **3.5** `GET /stats` for overview numbers (alerts by severity, events over time, top IPs, top users)
- [x] **3.6** Use parameterized queries everywhere (no string-built SQL)
- [x] **3.7** Add an endpoint or CLI command to trigger ingestion + detection
- [x] **3.8** Write basic API tests

**Done when:** Every endpoint returns correct data for the sample dataset and API tests pass.

---

## M4: Dashboard

**Goal:** An analyst can see what happened at a glance.

- [x] **4.1** Wire the existing React + Vite app to the API
- [x] **4.2** **Overview page:** alert counts by severity, events over time, top source IPs, top targeted users
- [x] **4.3** **Alerts list:** sortable/filterable table (severity, rule, host, time, status)
- [x] **4.4** **Alert detail:** triggering events, raw logs, ATT&CK technique link
- [x] **4.5** Add navigation between pages
- [x] **4.6** Handle loading, empty, and error states

**Done when:** You can open the dashboard, see the overview, filter alerts, and click into an alert to see its raw logs.

---

## M5: Polish MVP 🚩

**Goal:** Anyone can clone the repo and see a working demo in minutes.

- [x] **5.1** Write a **"generate attack" script** or curated sample dataset that triggers every rule
- [x] **5.2** Fill test gaps so every parser and rule has tests
- [x] **5.3** Make the demo runnable with as few commands as possible
- [x] **5.4** Take screenshots / record a GIF of the dashboard
- [x] **5.5** Draw an architecture diagram
- [x] **5.6** Write the README (see [README Checklist](#f-readme-checklist))
- [ ] **5.7** Tag a release (`v0.1.0`)

**Done when:** A fresh clone runs the demo by following the README alone, and every README checklist item is checked. **This is the MVP.**

---

## M6: Expand

**Goal:** Show the design generalizes beyond one log source.

- [x] **6.1** Add a second log source (Windows Security events or web server logs) with its own parser and tests
- [x] **6.2** Add 2–4 more rules from the [rule ideas](#d-detection-rule-ideas), including at least one for the new source
- [x] **6.3** Move rules to a Sigma-like YAML format if not already
- [x] **6.4** **Event search page** in the dashboard (time range, host, user, IP, keyword)
- [x] **6.5** **ATT&CK view:** heatmap grid of detected techniques
- [x] **6.6** Update README, screenshots, and sample data

**Done when:** Two log sources are ingested, 6+ rules fire on the demo data, and the ATT&CK view renders.

---

## M7: Harden

**Goal:** The security tool itself has no obvious holes.

- [x] **7.1** Add authentication to the API and dashboard
- [ ] **7.2** Validate uploaded logs (size limits, file types)
- [ ] **7.3** Review search/filter code for injection risks
- [ ] **7.4** Confirm no secrets are committed (`.env` in `.gitignore`, history checked)
- [ ] **7.5** Enable dependency scanning (Dependabot, `npm audit`, `pip-audit`)
- [ ] **7.6** Add a "Security" section to the README describing these measures

**Done when:** Unauthenticated requests are rejected, bad uploads are refused, and dependency scans are clean or triaged.

---

## M8: Stretch

Pick any, in any order:

- [ ] **8.1** `docker-compose` setup so the whole stack starts with one command
- [ ] **8.2** Real-time / streaming ingestion (folder watcher or syslog listener)
- [ ] **8.3** Alert triage workflow (status, assignee, analyst notes)
- [ ] **8.4** Correlation rules across sources
- [ ] **8.5** Reporting / export (CSV, PDF)
- [ ] **8.6** Sysmon or firewall log source
- [ ] **8.7** Integrate with the File Integrity Monitor or Network Scanner projects (see [Related Projects](#related-projects-same-portfolio-series))

---

# Reference

## A. Log Sources

- **Linux auth logs** (`/var/log/auth.log`, `secure`) for SSH logins, sudo use, failed auths
- **Windows Security Event Logs** (exported EVTX or JSON) for event IDs like 4624, 4625, 4672, 4720, 4732
- **Web server access logs** (Apache/Nginx) for scanning, injection attempts, 4xx/5xx spikes
- **Firewall logs** (pfSense, iptables) for blocked connections and port scans
- **Sysmon logs** for process creation, network connections (good stretch goal)

Include **sample log datasets** in the repo so anyone can run the demo without their own environment.

## B. Architecture Components

| Component | Purpose | Questions to decide |
|---|---|---|
| **Collector / Ingestor** | Reads raw logs from files or a network listener | File upload? Folder watcher? Syslog listener? |
| **Parser / Normalizer** | Converts each format into one common event schema | What fields are required? How to handle unparseable lines? |
| **Storage** | Keeps events and alerts searchable | SQLite vs. PostgreSQL vs. Elasticsearch/OpenSearch? |
| **Detection Engine** | Runs rules against events, creates alerts | Rules in code vs. YAML/JSON config? Sigma-style format? |
| **API** | Serves events/alerts to the frontend | REST vs. GraphQL? Auth required? |
| **Dashboard** | Visualizes alerts, trends, and event search | Which views matter most to an analyst? |

## C. Common Event Schema

- Timestamp (normalized to UTC)
- Source type (auth, windows, web, firewall)
- Host / hostname
- Source IP / destination IP
- Username
- Event category / action (login, logout, privilege change, process start)
- Outcome (success / failure)
- Raw log line (always keep the original)

Look at the **Elastic Common Schema (ECS)** or **OCSF** for inspiration. Borrowing their naming makes the project look industry-aware.

## D. Detection Rule Ideas

| Rule idea | ATT&CK mapping (look up and confirm) |
|---|---|
| Brute force: X failed logins from one IP in Y minutes | T1110 – Brute Force |
| Successful login after many failures (possible compromise) | T1110 / T1078 |
| New user account created | T1136 – Create Account |
| User added to admin/privileged group | T1098 – Account Manipulation |
| Login at unusual hour or from new IP for that user | T1078 – Valid Accounts |
| Web scanning / directory enumeration (many 404s) | T1595 – Active Scanning |
| Suspicious commands via sudo | T1548 – Abuse Elevation Control |

Writing rules in a **Sigma-like YAML format** is worth it: Sigma is the industry standard and a strong résumé keyword.

## E. Dashboard Views

- **Overview:** alert counts by severity, events over time, top source IPs, top targeted users
- **Alerts list:** sortable/filterable table with severity, rule, host, time, status
- **Alert detail:** the triggering events, raw logs, ATT&CK technique link, analyst notes
- **Event search:** filter by time range, host, user, IP, keyword
- **ATT&CK view:** which techniques have been detected, shown as a heatmap grid

## F. README Checklist

- [x] One-paragraph summary of what it does and why
- [x] Architecture diagram
- [x] Screenshots / GIF of the dashboard
- [x] Supported log sources and detection rules (with ATT&CK IDs)
- [x] How to run it (ideally one command)
- [x] Tech stack
- [ ] What you learned / challenges / future work

## G. Résumé Keywords This Project Can Back Up

SIEM · Log Analysis · Threat Detection · MITRE ATT&CK · Sigma Rules · Incident Triage · Python/Node.js · React · REST API · SQL · Docker · Security Monitoring · SOC Operations

---

## Related Projects (same portfolio series)

- **File Integrity Monitor:** its change alerts could later feed into MiniSIEM as another log source
- **Network Scanner & Asset Inventory:** asset data could enrich MiniSIEM alerts (e.g., "this IP belongs to a known server")

Linking the three together later gives you a story: *"I built a small security monitoring ecosystem."*

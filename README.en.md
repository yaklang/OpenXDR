# OpenXDR

[![CI](https://github.com/yaklang/OpenXDR/actions/workflows/ci.yml/badge.svg)](https://github.com/yaklang/OpenXDR/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[中文](README.md) | English

An open-source autonomous XDR: EDR + SIEM + network traffic analysis.

**From the first sign to the last action, it walks the whole way on its own. You review — or overrule.**

- **It never sleeps.** Collection, detection, triage and inspections run day and night; the noise settles here, and what remains is worth your time.
- **It acts.** Seconds after an attack lands, the offending container is cut off, the source is blocked and the fallen account is locked.
- **It answers for itself.** Every decision is written down with its reasons, every action can be undone in one click. No one has to keep watch at the screen — only read what it left behind when morning comes.

> Detailed documentation under `docs/` is currently written in Chinese.

## What it does

### Onboarding and collection

- **One-command onboarding**: per-group enrollment tokens; one command installs the agent on Linux (x86_64 / arm64) or Windows, the key is generated locally and the server issues a host-bound certificate.
  Drop a new build into the distribution directory and online agents upgrade themselves. Ops documents can be imported, with credentials encrypted and SSH onboarding authorized per group.
- **Collection that adapts**: processes, files, persistence points, logon and security logs, network connections and DNS, kernel modules, listening ports and software inventory, with container attribution by cgroup.
  eBPF / ETW are optional and fall back to netlink, fanotify or polling — weaker collection over fake data.
- **Network sensor**: session metadata only (DNS, TLS JA3 and certificates, HTTP), no PCAP; syslog ingestion built in.

### Detection and noise reduction

- **Rules and intel**: 200+ Sigma-compatible rules (hot reload, an ATT&CK matrix that flags "rule but no data source"), temporal count and sequence rules,
  threat intel matching with public feeds such as abuse.ch, UEBA first-seen and beacon detection.
- **Noise reduction**: persistent dedup, revocable and expiring suppressions, known-automation recognition (ops scripts and container health checks stop flooding),
  entity-based correlation into incident graphs, auto-closing of expired low-severity benign incidents.
- **Cross-host attacks stay in one piece**: buckets per asset and container, lateral movement recognized from the victims' failed logons (across groups too),
  and a severity-5 synthetic alert with immediate re-triage when one managed host sprays several others.
- **Validated in CI**: real attack commands are replayed through the rule engine, and the full timeline of a real intrusion is replayed through ingestion, correlation and autonomous response.

### AI triage, assistant and inspections

- **Active triage**: the AI triages each incident with read-only investigation tools and gives a verdict, confidence and evidence; re-triage has cooldowns and fair scheduling.
- **Chat-driven operations**: the AI can run commands on hosts in the group, query per-group read-only views, record findings and submit reports; select incidents or findings and hand them to the AI.
- **Scheduled inspections**: preset tasks run AI inspections across a group on a cron schedule and produce HTML / PDF reports.
- **AI auditor**: high-risk commands and suppression drafts initiated by the AI are reviewed on the spot by an AI auditor instead of waiting all night for a click;
  stopping the agent, wiping logs, flushing firewalls and formatting disks are on a hard-deny list the AI can never execute.
- **Independent closure auditor**: low-risk benign closure proposals are reviewed by an independent AI closure auditor and auto-closed as false positive only when positive evidence explains every alert in the incident (marked `ai_review`, reopenable by people); suspicious or malicious incidents may also close as contained after successful containment covers every alert, no core assets are involved, a six-hour quiet window has passed, and no person has taken ownership or locked the incident. New evidence reopens the incident; containment leases continue independently. Missing evidence, uncertainty or an invalid reply keeps the incident open, and it never creates long-lived allow-lists.

### Autonomous response

When a deterministic attack signal fires, the platform contains it based on who is the source, who is the victim, and each host's response tier:

| Signal | What the platform does |
|---|---|
| Internal lateral spray | Isolates only the attacking container when identified; isolates the whole host only for lab machines; every victim blocks the source address |
| Brute-force success | Blocks the login source and locks the compromised account (not built-in accounts or core hosts) |
| Database spawns a shell (`COPY FROM PROGRAM`, UDFs) | Kills that process and blocks the issuing client on the database host |
| High-severity intel hit | Blocks the address; kills a malicious process that dialed out; quarantines files whose hash matched |

- **Response tiers**: the AI assigns each asset a lab / production / core tier (editable and lockable). Lab machines may be cut off, production hosts are never fully isolated, core hosts get only the lightest actions, and platform nodes never block each other.
- **Reversible and bounded**: blocks and isolations are leases reviewed by the AI at expiry (lift or extend); a fuse caps actions per hour and isolations per group;
  every decision, including the ones not executed, is recorded, and the Autonomous Response page rolls any of them back in one click.
- Off by default; start with lab-tier hosts only and widen after observing.

### Protecting the platform itself

A security platform that can act on its own is the first thing an attacker wants. OpenXDR is designed with that assumption:

- **Signed commands**: every response command is sealed in an envelope bound to the target host and an expiry, and agents execute only what verifies. Reaching the database or the message bus is not enough to forge one.
- **Signed releases**: agents only install upgrades signed by an offline release key, so a compromised server node cannot push a malicious agent.
- **Tamper-evident audit**: the audit log is sealed into an HMAC chain whose key is not in the database; modifying or deleting a record raises an alert, and deleting the newest records shows up in monitoring outside the cluster.
- **Self-monitoring**: changes to the database HA control-plane config and silent agents on platform nodes raise alerts; control-plane ports only accept fixed peers.

### Assets, attack surface and vulnerabilities

- **Asset map**: listening ports and connections aggregate into a dependency graph; the AI annotates each asset's role, purpose, importance and response tier.
- **Attack surface**: assets are zoned by subnet and cloud environment; exposed services are ranked by exposure × port risk × importance, and unmanaged hosts seen on the wire are listed as blind spots.
- **Software vulnerabilities**: dpkg inventories are matched against OSV, highlighting fixable vulnerabilities and affected exposed services (Debian / Ubuntu for now).
- **Identity correlation** (in development): normalized logons and local accounts, with directory sync from Keycloak, Entra ID and AD / LDAP.

### Production-ready

mTLS with host-bound certificates, three RBAC roles with group permissions, NATS JetStream queues sharded by asset, multi-node servers,
and a cross-host HA deployment with Patroni, three-node JetStream and Keepalived, with rolling releases.

## Screenshots

These screenshots come from a fictional demo environment; all hosts, addresses and domains are examples.

**Overview**: over a million raw events and ten thousand alerts a day, boiled down to the 3 incidents that need a human.

![Overview](docs/images/screenshots/overview-en.png)

**AI assistant handling an incident**: hand an incident to the AI; it gathers evidence on the host, queries platform data, contains the threat after approval, and proposes how to close it.

![AI assistant](docs/images/screenshots/ai-assistant-en.png)

**Incidents**: every incident carries an AI verdict; benign ones say why, and the truly suspicious ones sit at the top.

![Incidents](docs/images/screenshots/incidents-en.png)

**Incident detail**: verdict, kill chain and suggested actions up front, with the process tree and connections in one graph.

![Incident detail](docs/images/screenshots/incident-detail-en.png)

**Asset map**: dependencies drawn from connections actually observed, with AI-annotated roles and criticality.

![Asset map](docs/images/screenshots/asset-map-en.png)

**Attack surface**: which services face the internet, who reaches them and how risky they are, laid out by zone.

![Attack surface](docs/images/screenshots/attack-surface-en.png)

**Daily inspection reports**: the AI inspects every host each day and puts what needs a human first.

![Reports](docs/images/screenshots/reports-en.png)

**Scheduled tasks**: each task works like an AI teammate on a roster; see what its last shift did and which report it filed.

![Scheduled tasks](docs/images/screenshots/scheduled-tasks-en.png)

**Asset detail**: collection health, network sensor status, the asset profile and related incidents on one page.

![Asset detail](docs/images/screenshots/asset-detail-en.png)

## Architecture

```
┌─────────┐  ┌──────────┐  ┌──────────┐
│  Agent  │  │  Sensor  │  │  Syslog  │
│endpoint │  │ network  │  │   logs   │
└────┬────┘  └────┬─────┘  └────┬─────┘
     │  ▲         │             │
     │  │ signed  │             │   gRPC (mTLS), agent dials out
     ▼  │ commands▼             ▼
   ┌──────────────────────────────────┐
   │ Server (Go, multi-node)          │
   │  normalize → JetStream queue     │
   │  rules / intel / UEBA / temporal │
   │  dedup → suppress → correlate    │
   │  AI triage · assistant · tasks   │
   │  autonomous response             │──→ Webhook (DingTalk / Feishu / WeCom)
   │  (leases · fuse · AI review)     │
   │  self-monitoring · audit chain   │
   └────────────────┬─────────────────┘
                    ▼
   PostgreSQL (Patroni HA) ←→ Web console (React)
```

## Install

On a Linux server with Docker, one command:

```bash
curl -fsSL https://github.com/yaklang/OpenXDR/releases/latest/download/install.sh | sudo sh -s -- <console-domain-or-ip>
```

The script generates passwords and keys, issues mTLS certificates and sets up HTTPS (a Let's Encrypt certificate for
domains that resolve to a public IP, a private CA for internal addresses), then starts everything and prints the console
URL and admin password. Log in, connect any OpenAI-compatible endpoint under "Settings → AI models", then copy the install
command from "Assets → Add host" onto the hosts you want to monitor. Running it again upgrades.

**Or let your AI agent do it** (Claude Code, Codex, Cursor, … running on the target server) — send it this:

```text
Install OpenXDR on this server, following https://github.com/yaklang/OpenXDR/blob/master/docs/install.md exactly:
check the environment, ask me which domain or IP the console should use, run the installer, then tell me the console URL,
the admin password and the commands managed hosts need to trust the CA.
```

See [Install](docs/install.md) (Chinese) for verification, upgrades, backups and troubleshooting. To build from source for development:

```bash
docker compose up -d
# Console http://localhost:5173   API :8080   gRPC :8081
docker compose logs server | grep admin   # admin password generated on first start
```

## Documentation

| Document | Content |
|---|---|
| [Install](docs/install.md) | One-line install, verification, upgrades and backups; also the install guide for AI agents (Chinese) |
| [Deployment guide](docs/deployment.md) | Startup, onboarding, logs and intel, suppression and response, mTLS, configuration |
| [High availability](deploy/ha/README.md) | Patroni + 3-node JetStream + Keepalived VIP, rolling release |
| [Asset map and attack surface](docs/asset-map.md) | Inventory, dependencies, zones, risk scores and AI annotation |
| [Autonomous response and self-protection](docs/autonomous-response-design.md) | Signals and actions, response tiers, leases and fuse, container isolation, signed commands, audit chain, self-monitoring |
| [Cross-host campaign correlation](docs/attack-campaign-design.md) | Post-mortem of a real internal pivot attack; per-entity buckets, victim-side lateral evidence, spray alerts |
| [AI assistant and inspections](docs/pi-backend.md) | Sessions, command list and the AI auditor, read-only queries, findings, preset tasks |
| [Document import and onboarding](docs/host-enrollment.md) | Ops document import, credential encryption, SSH onboarding, release signing |
| [Software vulnerabilities](docs/vulns.md) | dpkg inventory, OSV sync, version comparison, known limits |
| [Temporal detection](docs/temporal-detection.md) · [Identity correlation](docs/identity-correlation.md) | Count and sequence rules; logon normalization and directory sync (both under development) |
| [Architecture](docs/architecture.md) · [Collection](docs/collection.md) · [Event model](docs/events.md) · [Detection](docs/detection.md) | Design and implementation |
| [REST API](docs/api.md) · [Cluster](docs/cluster.md) · [Roadmap](docs/roadmap.md) | Integration, operations and plans |

See [docs/README.md](docs/README.md) for the full index.

## Repository layout

| Directory | Content |
|---|---|
| `agent/` | Rust endpoint agent (Linux / Windows), including response actions |
| `sensor/` | Rust network sensor, AF_PACKET v3 / AF_XDP backends |
| `server/` | Go backend: ingestion, detection, correlation, AI triage and assistant, REST / gRPC |
| `web/` | React management console |
| `rules/` | Sigma-compatible detection rules |
| `temporal-rules/` | Temporal detection rules (count / sequence), kept apart from Sigma rules |
| `tasks/` | Preset inspection tasks (YAML) |
| `validation/` | [Detection validation corpus](validation/README.md): real attack commands replayed through the rule engine, guarded in CI |
| `deploy/` | Cluster and HA deployment |
| `proto/` | gRPC contracts |
| `schema/` | Reference DDL; the actual schema lives in `server/ent/schema/` |
| `pages/` | Project homepage (GitHub Pages), unrelated to the product code |

## Status

The current release is v0.4.0. OpenXDR runs continuously on a two-node HA deployment in the maintainers' own network, managing twenty-odd Linux and Windows hosts,
with autonomous response, self-monitoring and the audit chain enabled in production.

- **Linux**: collection, detection, triage and inspections have run in production since October; autonomous response is enabled there since v0.4.0. eBPF network and DNS collection and container attribution are verified on real machines across distributions.
- **Windows**: ETW process, network, DNS and security-log collection is verified item by item on real Windows 10 machines (see [real-machine replay](validation/replay/README.md)); coverage is still narrower than on Linux.
- **Autonomous response**: off by default. The engine acts only on deterministic synthetic detections and high-severity intel, never directly on an AI verdict (the AI only assigns tiers and reviews expiring leases); start with lab-tier hosts.
- **AI**: quality depends on the tool-calling ability of the model you connect; weaker models drift with long context. The platform guarantees the AI cannot cross permission, allow-list and hard-deny boundaries,
  not that its conclusions are right — low-risk benign incidents with positive evidence and threats meeting strict containment gates can be auto-closed by the independent closure auditor; other incidents stay for people.

See the [roadmap](docs/roadmap.md) for known gaps and the [CHANGELOG](CHANGELOG.md) for every release's changes and upgrade notes.

## Contributing

Issues and PRs are welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) first. Report security issues
privately as described in [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE)

Third-party data: `rules/sigmahq/` contains SigmaHQ community rules (DRL 1.1, see its README); the offline IP
ownership database bundled in release images is [DB-IP Lite](https://db-ip.com) (IP Geolocation by DB-IP, CC BY 4.0).

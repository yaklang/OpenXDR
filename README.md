# OpenXDR

[![CI](https://github.com/professoxrmoriarty/OpenXDR/actions/workflows/ci.yml/badge.svg)](https://github.com/professoxrmoriarty/OpenXDR/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[中文](README.md) | English

An open-source XDR platform: EDR + SIEM + network traffic analysis, with AI-driven noise reduction and operations.

**Onboarded means operated, onboarded means secured.** Install the agent on a host and put it in a group,
and it immediately gets continuous collection, detection, daily inspection and an AI assistant you can talk to.
People make the calls instead of digging through alert lists.

**Noise stops here. What's left is worth your time.**

> Detailed documentation under `docs/` is currently written in Chinese.

## What it does

- **One-command onboarding**: the console issues per-group enrollment tokens; one command installs the agent
  on Linux / Windows, generates the private key locally and gets a host-bound certificate from the server.
  Afterwards, drop a new build into the distribution directory and online agents upgrade themselves.
  Existing ops documents can be imported, with credentials encrypted at rest and SSH onboarding authorized per group.
- **Collection that adapts**: processes, files, persistence points, logon and security logs, outbound connections,
  kernel modules. eBPF / ETW are optional and fall back automatically to netlink, fanotify or polling —
  weaker collection is preferred over fake data. The network sensor emits session metadata only
  (DNS / TLS JA3 and certificates / HTTP), no PCAP. Syslog ingestion is built in.
- **Layered noise reduction**: Sigma-compatible rules (hot reload, ATT&CK matrix that flags
  "rule exists but no data source"), threat intel matching with built-in public feeds such as abuse.ch,
  persistent dedup, revocable suppressions, entity-based correlation into incident graphs, UEBA first-seen detection,
  and finally AI triage that investigates with tools. Low-severity benign incidents are auto-closed after a grace period;
  anything that needs human review stays with humans. Temporal detection (count and sequence rules in a separate
  directory, opt-in) is under development.
- **Software vulnerabilities**: agents report the dpkg package inventory and the server matches it against the OSV
  database, flagging vulnerabilities fixable by upgrade and the exposed services they affect; an offline feed is supported.
  Debian / Ubuntu only for now.
- **Identity correlation** (under development): Linux / Windows logons and local accounts are normalized, and directory
  accounts can be synced from Keycloak, Entra ID and AD / LDAP. Same-name accounts are not merged across devices until
  the directory authority is verified.
- **Asset map and attack surface**: agents report listening ports and cloud metadata, and observed connections
  become a dependency graph; AI annotates each asset's role, function and criticality (editable and lockable by people).
  Assets are zoned automatically as internal / DMZ / internet-facing / cloud by CIDR, cloud metadata and IP, every
  listening service is ranked by exposure × port risk × criticality, and unmanaged hosts in contact are listed as blind spots.
- **AI assistant and inspections**: run commands on the group's hosts, query the database through a per-group
  read-only view, track ops findings and file reports — all by conversation. Incidents and findings can be
  multi-selected and handed to the AI. Conversations run in the background on the server, so switching pages
  doesn't interrupt them. Preset tasks inspect every host in a group on a cron schedule and render HTML / PDF reports.
- **Humans stay in charge**: commands matching the high-risk list block until a group admin approves (with a notification);
  everything else runs directly. Process kill / host isolation are gated by a global switch and an isolation allowlist.
  Every login, approval and response action is audited.
- **Production-ready**: mTLS with host-bound certificates, three-tier RBAC plus group roles, NATS JetStream queues
  sharded by asset, multi-node servers, and a cross-host HA deployment with Patroni + Keepalived.

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
     └────────────┼─────────────┘  gRPC (mTLS), agent dials out
                  ▼
   ┌──────────────────────────────┐
   │ Server (Go)                  │
   │  normalize → JetStream queue │
   │  rules / intel / UEBA        │
   │  dedup → suppress → correlate│
   │  → AI triage                 │
   │  AI assistant · inspections  │──→ Webhook (DingTalk / Feishu / WeCom)
   │  · command approvals         │
   └──────────────┬───────────────┘
                  ▼
   PostgreSQL ←→ Web console (React)
```

## Install

On a Linux server with Docker, one command:

```bash
curl -fsSL https://github.com/professoxrmoriarty/OpenXDR/releases/latest/download/install.sh | sudo sh -s -- <console-domain-or-ip>
```

The script generates passwords and keys, issues mTLS certificates and sets up HTTPS (a Let's Encrypt certificate for
domains that resolve to a public IP, a private CA for internal addresses), then starts everything and prints the console
URL and admin password. Log in, connect any OpenAI-compatible endpoint under "Settings → AI models", then copy the install
command from "Assets → Add host" onto the hosts you want to monitor. Running it again upgrades.

**Or let your AI agent do it** (Claude Code, Codex, Cursor, … running on the target server) — send it this:

```text
Install OpenXDR on this server, following https://github.com/professoxrmoriarty/OpenXDR/blob/master/docs/install.md exactly:
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
| [AI assistant and inspections](docs/pi-backend.md) | Sessions, command list and approvals, read-only queries, findings, preset tasks |
| [Document import and onboarding](docs/host-enrollment.md) | Ops document import, credential encryption, SSH onboarding |
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

v0.1.0 is the first public release. Linux collection, detection, the AI assistant and inspections run continuously
on a two-node HA deployment. Windows code is cross-compiled and linted in CI but still lacks systematic testing on
real machines. AI quality depends on the tool-calling ability of the model you connect: weaker models drift with
long context. The platform guarantees the AI cannot cross permission and approval boundaries, not that its
conclusions are right — incidents are still closed by people.

See the [roadmap](docs/roadmap.md) for known gaps and the [CHANGELOG](CHANGELOG.md) for changes.

## Contributing

Issues and PRs are welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) first. Report security issues
privately as described in [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE)

Third-party data: `rules/sigmahq/` contains SigmaHQ community rules (DRL 1.1, see its README); the offline IP
ownership database bundled in release images is [DB-IP Lite](https://db-ip.com) (IP Geolocation by DB-IP, CC BY 4.0).

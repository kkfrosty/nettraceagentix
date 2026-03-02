# Changelog

All notable changes to **NetTrace Agentix** will be documented in this file.

## [0.1.5] - 2026-03-02

### Fixed
- **Packet Bytes pane** — Toggle button now correctly visible and clickable after collapsing (label hidden, button centered in collapsed strip)

### Added
- **Packet Detail pane minimize** — New `▼/▲` toggle button on the Packet Detail header collapses the entire bottom section (Packet Detail + Packet Bytes) to a thin strip, giving the packet list maximum vertical space; click again to restore

## [0.1.0] - 2026-02-27

### Added
- **`@nettrace` Chat Participant** — AI-powered network trace analysis in GitHub Copilot Chat
- **tshark parsing engine** — Automatic pcap/pcapng parsing with parallel command execution
- **Context assembly engine** — Token budget management (~900K usable), anomaly-based stream prioritization
- **7 Language Model Tools** — getStreamDetail, getPacketRange, getExpertInfo, applyFilter, getConversations, followStream, compareCaptures
- **Interactive capture viewer** — Wireshark-style 3-pane webview with filter bar, protocol tree, and hex dump
- **Analysis agents** — Built-in General Analyzer + configurable TLS, DNS, and VoIP specialist agents
- **Knowledge base system** — Wisdom, security heuristics, and known-issues templates injected into analysis
- **Client/server capture comparison** — Compare traces from different network points
- **Workspace initializer wizard** — Multi-step setup wizard for `.nettrace/` configuration
- **Sidebar TreeViews** — Captures, Agents, Knowledge, and Scenario Context panels
- **Configuration hot-reload** — File watchers auto-reload `.nettrace/` JSON config changes
- **Noise filtering** — Three-layer protocol exclusion (built-in defaults, agent-level, user overrides)
- **Chat commands** — `/summarize`, `/diagnose`, `/stream`, `/compare`, `/agent`

### Chat Commands
- `@nettrace <question>` — General analysis question
- `@nettrace /summarize` — Capture summary with statistics and anomalies
- `@nettrace /diagnose` — Root cause diagnosis using scenario context
- `@nettrace /stream <number>` — Deep dive into a specific TCP stream
- `@nettrace /compare` — Compare client vs server captures
- `@nettrace /agent <name>` — Switch analysis agent

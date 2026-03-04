# Changelog

All notable changes to **NetTrace Agentix** will be documented in this file.

## [0.1.7] - 2026-03-04

### Fixed
- **Large capture token exhaustion** — Analysis of captures larger than the model's context window was cutting off before all packet ranges were reviewed. The tool loop was running out of headroom after only 2-3 round-trips because the initial context reserve was too small for the required range-paging calls
- **Context reserve now scales with capture size** — For captures that fit entirely within the model's context window, the original 10% reserve is preserved (no regression). For captures requiring sampling mode, the reserve scales by model size: 35% for models under 200K tokens, 20% for 200K–500K, 15% for 500K+. This ensures the tool loop has enough room to page through all uncovered frame ranges
- **Sampling mode pre-detection** — A lightweight packet-count estimate (no tshark call) now determines which reserve strategy to use before context assembly begins, so the split is always correctly sized for the actual capture
- **Tool loop cutoff threshold** — The remaining-budget threshold that stops tool calls and forces a final synthesis now scales with model size (`max(20K, 10% of modelMax)`) instead of a flat 20K. On 128K models the old flat threshold was firing after just 2 rounds
- **SAMPLED MODE PROTOCOL enforced in system prompt** — The AI is now explicitly instructed to issue all `nettrace-getPacketRange` calls in parallel in round 1 before making any filter or stats calls. This prevents exploratory calls from consuming budget before uncovered ranges are reviewed

### Improved
- **Sampled mode status line** — The UI stat line now reads `📊 Pre-loaded X of Y packets · 🔍 tools scanning remaining Z% via N range passes` instead of the misleading "Sampled X" wording, making clear this is a coverage plan rather than a cap

## [0.1.6] - 2026-03-03

### Added
- **Live Packet Capture** — New `liveCaptureWebviewPanel.ts` provides a full Live Capture panel for capturing live network traffic directly inside VS Code. Select an interface, set an optional BPF filter, stream packets in real time, stop, and immediately hand off to `@nettrace` for AI analysis. Captures are saved as `.pcapng` files.
- **AI-initiated live capture** — `nettrace-startCapture` Language Model Tool lets the AI open the Live Capture panel on a user-specified interface in response to natural language requests like `@nettrace start a capture on my Wi-Fi adapter`
- **`nettrace-setDisplayFilter` tool** — AI can now update the active Capture Viewer filter bar without running a data query; keeps the panel in sync with whatever the model is investigating
- **`nettrace-runTshark` tool** — AI can execute arbitrary read-only tshark commands for ad-hoc statistics, protocol hierarchies, and custom queries. Write operations and shell metacharacters are blocked for safety
- **`nettrace-createAgent` tool** — AI can generate a fully structured `.nettrace/agents/*.json` agent definition on the fly based on the analysis at hand; immediately hot-reloaded into the sidebar
- **`nettrace-createKnowledge` tool** — AI can write new knowledge documents to `.nettrace/knowledge/wisdom|security|known-issues/` during a session when it learns something environment-specific
- **Knowledge Base sidebar** (`knowledgeTreeProvider.ts`) — New tree view in the NetTrace sidebar shows all knowledge documents organized by category (Analysis Guidance, Security Heuristics, Known Issues) with enabled/disabled status indicators
- **Multi-turn conversation mode** — Follow-up questions in Copilot Chat use lightweight context (summary only, no packet data re-send). The AI uses tools to revisit specific packets on demand, keeping subsequent turns fast and within token budget
- **No-capture agentic mode** — `@nettrace` can now be invoked before any capture file is open; the AI can use tools like `nettrace-startCapture` to initiate a live session rather than returning an error
- **Agentic tool loop with token budget tracking** — Tool calling loop supports up to 25 round-trips per turn with per-message token estimation to avoid exceeding the model's context window

### Improved
- **Capture Viewer panel filter sync** — All tools that evaluate a display filter (`nettrace-applyFilter`, `nettrace-runTshark`) automatically push the filter to the active Capture Viewer panel so the user always sees what the AI is looking at
- **Tool response quality** — `nettrace-applyFilter` now distinguishes between zero-match results and errors, providing actionable guidance for each case rather than a generic error message
- **`getDefaultCaptureFile` resolution** — Live capture sessions now take absolute priority over static capture panels; tools correctly target the live capture file rather than a stale previously-opened capture

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

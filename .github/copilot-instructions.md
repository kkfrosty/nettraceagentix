# NetTrace Agentix — Copilot Project Context

## What This Project Is
A VS Code extension called **NetTrace Agentix** that provides AI-powered network trace analysis for support engineers and customers. It parses pcap/pcapng files using tshark (Wireshark CLI) and provides intelligent diagnosis via GitHub Copilot's Language Model API.

The extension registers a **`@nettrace` Chat Participant** in Copilot Chat. Users type things like `@nettrace what's wrong with this capture?` and get streaming AI-powered network diagnosis.

## Why It Exists
With large context models (1M+ tokens) available through GitHub Copilot, we can feed entire parsed network captures to the LLM and get expert-level network diagnosis. This turns Copilot into a network analysis tool for support engineers who may not be Wireshark experts.

## Architecture Overview

### Three-Layer Design
1. **Parsing Layer** (`src/parsing/tsharkRunner.ts`) — Spawns tshark as a child process to convert binary pcap files into structured text. Runs multiple tshark commands in parallel for speed.
2. **Context Assembly Engine** (`src/contextAssembler.ts`) — Manages the token budget (~900K usable), prioritizes anomalous streams, and structures the prompt for maximum diagnostic value.
3. **Chat Participant + LM Tools** (`src/participant/`, `src/tools/`) — The `@nettrace` participant handles user requests. Six Language Model Tools let the LLM autonomously call tshark to drill deeper during analysis.

### Configuration-Driven (No Code Changes Needed)
The extension is driven by JSON configuration files in a `.nettrace/` folder within the user's workspace:
- `.nettrace/config.json` — Workspace-level settings (tshark path, token budget, default agent, filters)
- `.nettrace/scenario.json` — Scenario context (symptom, topology, IPs) injected into every LLM prompt
- `.nettrace/agents/*.json` — Custom analysis agents (persona + prompt + tools + filters)
- `.nettrace/tools/*.json` — Custom tool definitions (tshark commands, scripts)
- `.nettrace/filters/*.json` — Reusable filter profiles (exclude noise, focus on specific traffic)

Users create JSON files, hit "Reload Config" or restart, and get new capabilities without touching TypeScript.

### Key Design Decisions
- **tshark is a hard dependency** — Binary pcap files cannot be read directly. tshark converts them to structured text for the LLM. The extension auto-detects tshark on PATH or standard install locations.
- **VS Code extension (not MCP server)** — We need the rich UI (TreeViews, Chat Participant, Webviews, Walkthroughs) that only a VS Code extension provides. The parsing layer is designed so it could be wrapped in an MCP server later if needed.
- **Copilot's Language Model API** — No separate API keys. The extension uses `vscode.lm.selectChatModels()` and `request.model.sendRequest()` to access the same models the user's Copilot subscription provides.
- **Agentic tool calling** — The LLM can autonomously call tools (getStreamDetail, applyFilter, followStream, etc.) to gather more data during analysis. It starts with a summary and drills into specific streams on its own.
- **Client/server capture comparison** — First-class feature. Users can mark captures as client-side or server-side, and the extension correlates packets between them to find what's missing.

## File Structure

```
src/
├── extension.ts                    # Entry point — activation, commands, auto-discovery, file watchers
├── types.ts                        # All shared TypeScript interfaces
├── configLoader.ts                 # Loads .nettrace/ JSON config with hot-reload file watchers
├── contextAssembler.ts             # Token budgeting, priority ranking, prompt assembly
├── workspaceInitializer.ts         # Workspace scaffolding wizard (creates .nettrace/ structure)
├── parsing/
│   └── tsharkRunner.ts             # tshark execution engine — all pcap parsing goes through here
├── participant/
│   └── nettraceParticipant.ts      # @nettrace chat participant (handles /summarize, /diagnose, /stream, /compare, /agent)
├── views/
│   ├── capturesTreeProvider.ts     # Sidebar: capture files organized by folder
│   ├── streamsTreeProvider.ts      # Sidebar: TCP streams sorted by anomaly score (most suspicious first)
│   ├── scenarioDetailsTreeProvider.ts  # Sidebar: scenario context (symptom, IPs, topology)
│   └── agentsTreeProvider.ts       # Sidebar: analysis agents (click to activate)
└── tools/
    └── lmTools.ts                  # 6 Language Model Tools the LLM can call during analysis
```

## Built-in Agents
- **General Analyzer** (hardcoded in configLoader.ts) — Works for any traffic type
- **TLS/SSL Specialist** (created by workspace initializer) — Certificate issues, cipher suites, handshake failures
- **DNS Troubleshooter** (created by workspace initializer) — NXDOMAIN, slow lookups, server failures
- **VoIP/SIP Analyzer** (created by workspace initializer) — SIP call flows, RTP quality, registration failures

## Language Model Tools (registered in package.json + lmTools.ts)
1. `nettrace-getStreamDetail` — Full packet-level detail for a TCP stream
2. `nettrace-getExpertInfo` — Wireshark expert info (errors, warnings)
3. `nettrace-applyFilter` — Apply a display filter, return matching packets
4. `nettrace-getConversations` — List all TCP/UDP conversations with stats
5. `nettrace-followStream` — Reconstruct application-layer data
6. `nettrace-compareCaptures` — Compare client/server captures

## Chat Commands
- `@nettrace <question>` — General analysis question
- `@nettrace /summarize` — Capture summary with stats and anomalies
- `@nettrace /diagnose` — Root cause diagnosis based on scenario details
- `@nettrace /stream 5` — Deep dive into specific TCP stream
- `@nettrace /compare` — Compare client vs server captures
- `@nettrace /agent tls-specialist` — Switch analysis agent

## User Experience Flow
1. User installs extension from the VS Code Marketplace or from source
2. Opens a folder in VS Code
3. Drops a .pcap file in (or uses "Import Capture" command)
4. Extension auto-detects tshark, parses the file, populates sidebar
5. Streams tree shows conversations sorted by anomaly score (most suspicious first)
6. User types `@nettrace what's wrong?` in Copilot Chat
7. Gets streaming AI diagnosis with clickable followup suggestions

## Noise Filtering
Three layers:
1. **Built-in defaults** — ARP, mDNS, SSDP, NBNS, IGMP, LLMNR, CDP, LLDP, STP excluded by default
2. **Agent-level filters** — Each agent focuses on its protocol (TLS agent filters to port 443, etc.)
3. **User overrides** — Per-workspace JSON filters in `.nettrace/filters/`

## Distribution
- **VS Code Marketplace** for stable releases
- **GitHub repo** (`github.com/kkfrosty/nettraceagentix`) for source and pre-releases
- Requires GitHub Copilot subscription (for Language Model API access)
- Requires Wireshark/tshark installed on the machine

## What's NOT Built Yet (Future Work)
- Dynamic tool loader (JSON-defined tools auto-registering as LM tools at runtime)
- Webview panel for flow diagrams (SYN/ACK sequence visualization)
- VS Code Walkthrough (guided first-run experience)
- Advanced cross-capture correlation (packet-level matching by TCP seq/ack numbers)
- Prompt caching for multi-turn efficiency
- Redaction mode (strip sensitive payload data before sending to LLM)
- Agent packs (shareable Git repos of agents/tools/filters for specific protocols)

## Development
- **Language:** TypeScript
- **Build:** `npm run compile` or `npm run watch`
- **Test:** F5 in VS Code launches Extension Development Host
- **Package:** `npm run package` → produces `.vsix` file
- **All dependencies:** `@types/vscode`, `@types/node`, `typescript`, `@vscode/vsce`

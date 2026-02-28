# NetTrace Agentix

AI-powered network trace analysis for VS Code. Drop in a `.pcap` file, type `@nettrace what's wrong?` in Copilot Chat, and get expert-level network diagnosis — no Wireshark expertise required.

![VS Code](https://img.shields.io/badge/VS%20Code-%5E1.95.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-0.1.0-orange)

---

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [From Source (Build & Install)](#from-source-build--install)
  - [From VSIX File](#from-vsix-file)
- [Getting Started](#getting-started)
  - [1. Open a Workspace](#1-open-a-workspace)
  - [2. Add Capture Files](#2-add-capture-files)
  - [3. Open a Capture](#3-open-a-capture)
  - [4. Ask the AI](#4-ask-the-ai)
- [Features](#features)
  - [Chat Participant (@nettrace)](#chat-participant-nettrace)
  - [Capture Viewer](#capture-viewer)
  - [Sidebar Views](#sidebar-views)
  - [Agentic Tool Calling](#agentic-tool-calling)
  - [Client/Server Capture Comparison](#clientserver-capture-comparison)
  - [Analysis Agents](#analysis-agents)
  - [Knowledge Templates](#knowledge-templates)
- [Commands](#commands)
- [Configuration](#configuration)
  - [VS Code Settings](#vs-code-settings)
  - [Workspace Configuration (.nettrace/ folder)](#workspace-configuration-nettrace-folder)
- [Workspace Initialization Wizard](#workspace-initialization-wizard)
- [Example Workflows](#example-workflows)
  - [Quick Diagnosis](#quick-diagnosis)
  - [TLS Handshake Troubleshooting](#tls-handshake-troubleshooting)
  - [Client vs Server Comparison](#client-vs-server-comparison)
- [Architecture](#architecture)
- [Development](#development)
  - [Building from Source](#building-from-source)
  - [Running in Development](#running-in-development)
  - [Packaging](#packaging)
  - [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

Network Capture AI Diagnosis turns GitHub Copilot into a network analysis tool. It parses pcap/pcapng capture files using **tshark** (the Wireshark CLI) and feeds structured network data to an LLM through Copilot's Language Model API. The AI can then autonomously drill into specific TCP streams, apply Wireshark display filters, follow streams, and compare client/server captures — all through natural language conversation.

**Key capabilities:**

- Parse and analyze `.pcap`, `.pcapng`, and `.cap` files directly in VS Code
- Streams sorted by anomaly score — the most suspicious connections surface first
- AI autonomously calls tshark tools to drill deeper during analysis
- Compare simultaneous client-side and server-side captures
- Configuration-driven: add custom agents, tools, and filters via JSON files
- Knowledge templates inject domain expertise (known issues, security heuristics) into the LLM context

---

## Prerequisites

Before using this extension, you need:

| Requirement | Details |
|---|---|
| **VS Code** | Version 1.95.0 or later |
| **GitHub Copilot** | Active subscription with [GitHub Copilot Chat](https://marketplace.visualstudio.com/items?itemName=GitHub.copilot-chat) extension installed |
| **Wireshark / tshark** | tshark is the CLI component of Wireshark. [Download Wireshark](https://www.wireshark.org/download.html) — tshark is included in the installation |
| **Node.js** | Version 18+ (only needed if building from source) |

### Verifying tshark

After installing Wireshark, verify tshark is accessible:

```bash
tshark --version
```

If tshark is not on your PATH, the extension will check standard install locations automatically:

- **Windows:** `C:\Program Files\Wireshark\tshark.exe`
- **macOS:** `/Applications/Wireshark.app/Contents/MacOS/tshark`, `/usr/local/bin/tshark`
- **Linux:** `/usr/bin/tshark`, `/usr/local/bin/tshark`

You can also manually configure the path in VS Code settings (see [Configuration](#vs-code-settings)).

---

## Installation

### From Source (Build & Install)

1. **Clone the repository:**

   ```bash
   git clone https://github.com/kkfrosty/nettraceagentix.git
   cd nettraceagentix
   ```

2. **Install dependencies:**

   ```bash
   npm install
   ```

3. **Compile the TypeScript:**

   ```bash
   npm run compile
   ```

4. **Package as a VSIX:**

   ```bash
   npm run package
   ```

   This produces a `.vsix` file in the project root (e.g., `network-capture-ai-diagnosis-0.1.0.vsix`).

5. **Install the VSIX in VS Code:**

   ```bash
   code --install-extension network-capture-ai-diagnosis-0.1.0.vsix
   ```

   Or in VS Code: **Extensions** sidebar → `...` menu → **Install from VSIX...** → select the `.vsix` file.

6. **Reload VS Code** when prompted.

### From VSIX File

If you received a pre-built `.vsix` file:

1. Open VS Code
2. Go to **Extensions** (Ctrl+Shift+X)
3. Click the `...` menu at the top of the Extensions sidebar
4. Select **Install from VSIX...**
5. Browse to and select the `.vsix` file
6. Reload VS Code when prompted

---

## Getting Started

### 1. Open a Workspace

Open any folder in VS Code. This will be your analysis workspace.

### 2. Add Capture Files

You have several options:

- **Drag and drop** `.pcap`, `.pcapng`, or `.cap` files into the workspace folder in the Explorer
- Use the command **NetTrace: Import Capture File** (Ctrl+Shift+P → type "Import Capture")
- Place files in a `captures/` subdirectory within your workspace

The extension auto-detects capture files and parses them with tshark on arrival.

### 3. Open a Capture

In the **NetTrace** sidebar (network icon in the Activity Bar), you'll see your captures listed. Click the preview icon on any capture to open the **Capture Viewer** — an interactive webview showing packets, conversations, and statistics.

### 4. Ask the AI

With a capture open in the viewer, open **Copilot Chat** (Ctrl+Shift+I) and type:

```
@nettrace what's wrong with this capture?
```

The AI analyzes the active capture, highlights anomalies, and provides diagnosis. It can autonomously use tools to drill into specific streams, apply filters, and gather more data.

---

## Features

### Chat Participant (@nettrace)

The extension registers a `@nettrace` chat participant in Copilot Chat. Simply mention `@nettrace` followed by your question:

| Example | What it does |
|---|---|
| `@nettrace what's wrong?` | General analysis of the active capture |
| `@nettrace why are there so many retransmissions?` | Focused analysis on a specific issue |
| `@nettrace is the TLS handshake completing correctly?` | Protocol-specific question |
| `@nettrace compare client and server captures` | Cross-capture comparison |
| `@nettrace /summarize` | Capture summary with stats and anomaly highlights |
| `@nettrace /diagnose` | Root cause diagnosis using scenario context |
| `@nettrace /stream 5` | Deep dive into TCP stream index 5 |
| `@nettrace /compare` | Compare client vs server captures |
| `@nettrace /agent tls-specialist` | Switch to the TLS analysis agent |

### Capture Viewer

A richly interactive webview panel that shows:

- Packet list with timestamps, source/destination, protocol, and info
- Conversation statistics
- Ability to apply Wireshark display filters
- Click-to-analyze integration with Copilot Chat

### Sidebar Views

The **NetTrace** Activity Bar entry provides:

- **Captures** — All capture files in the workspace, organized by folder. Right-click for actions (analyze, parse, set as client/server, open in Wireshark).
- **Scenario Context** — Optional scenario metadata (scenario ID, symptom, topology, IPs) that gets injected into every LLM prompt for more targeted diagnosis.

### Agentic Tool Calling

During analysis, the LLM can autonomously call these tools to gather more data:

| Tool | Description |
|---|---|
| **Get TCP Stream Detail** | Full packet-level detail for a specific TCP stream |
| **Get Packet Range** | Fetch packets by frame number range (pagination for large captures) |
| **Get Expert Info** | Wireshark expert info — errors, warnings, notes |
| **Apply Display Filter** | Apply any Wireshark display filter and return matching packets |
| **Get Conversations** | List all TCP/UDP/IP conversations with byte counts, durations, anomalies |
| **Follow TCP Stream** | Reconstruct application-layer payload (like Wireshark's Follow Stream) |
| **Compare Captures** | Compare client-side and server-side captures for discrepancies |

The AI starts with a high-level summary and drills into specific streams on its own when it detects something suspicious.

### Client/Server Capture Comparison

If you have simultaneous captures from both ends of a connection:

1. Right-click a capture in the sidebar → **Set as Client Capture**
2. Right-click another capture → **Set as Server Capture**
3. Ask `@nettrace /compare` or `@nettrace compare these captures`

The extension correlates packets between captures to find what's missing, delayed, or modified in transit.

> **Tip:** Place client captures in a folder named `client/` and server captures in a folder named `server/` — the extension auto-detects the roles from folder names.

### Analysis Agents

Agents are specialized AI personas with tailored prompts, tools, and filters:

| Agent | Focus |
|---|---|
| **General Analyzer** | Any traffic type (built-in default) |
| **TLS/SSL Specialist** | Certificate issues, cipher suites, handshake failures |
| **DNS Troubleshooter** | NXDOMAIN, slow lookups, server failures |
| **VoIP/SIP Analyzer** | SIP call flows, RTP quality, registration failures |

Select an agent via the command **NetTrace: Select Analysis Agent** or use the `/agent` command in chat.

You can also create custom agents — see [Workspace Configuration](#workspace-configuration-nettrace-folder).

### Knowledge Templates

The `.nettrace/knowledge/` directory in your workspace contains markdown files that are automatically injected into the LLM context during analysis:

- **known-issues/** — Firewall appliance quirks, Windows TCP stack behaviors (always loaded)
- **security/** — Patterns for identifying security-relevant anomalies (loaded when suspicious packets are detected)
- **wisdom/** — Common false positives to avoid misdiagnosis (always loaded)

Add or edit `.md` files in these folders to customize the AI's knowledge. Changes take effect immediately via hot-reload — no restart needed.

---

## Commands

All commands are available via the Command Palette (Ctrl+Shift+P) under the **NetTrace** category:

| Command | Description |
|---|---|
| **NetTrace: Initialize Workspace** | Run the setup wizard to create `.nettrace/` configuration |
| **NetTrace: Import Capture File** | Browse and import `.pcap`/`.pcapng`/`.cap` files |
| **NetTrace: Parse Capture** | Re-parse a capture file with tshark |
| **NetTrace: Analyze with AI** | Open Copilot Chat with a summarize prompt for a capture |
| **NetTrace: Analyze All Captures** | Analyze all loaded captures at once |
| **NetTrace: Open Capture Viewer** | Open the interactive packet viewer for a capture |
| **NetTrace: Chat with AI about Traces** | Open Copilot Chat with the `@nettrace` participant |
| **NetTrace: Edit Scenario Context** | Edit scenario details (symptom, IPs, topology) |
| **NetTrace: Select Analysis Agent** | Switch the active analysis agent |
| **NetTrace: Apply Display Filter** | Apply a Wireshark display filter to the active viewer |
| **NetTrace: Set as Client Capture** | Mark a capture as the client-side trace |
| **NetTrace: Set as Server Capture** | Mark a capture as the server-side trace |
| **NetTrace: Open in Wireshark** | Open the capture in Wireshark for advanced analysis |
| **NetTrace: Close Capture** | Close the active capture viewer |
| **NetTrace: Reload Configuration** | Hot-reload all `.nettrace/` JSON config files |

---

## Configuration

### VS Code Settings

These settings are available under `nettrace.*` in VS Code Settings (Ctrl+,):

| Setting | Type | Default | Description |
|---|---|---|---|
| `nettrace.tsharkPath` | string | `""` (auto-detect) | Path to tshark executable. Leave empty to auto-detect. |
| `nettrace.wiresharkPath` | string | `""` | Path to Wireshark executable for "Open in Wireshark" feature. |
| `nettrace.defaultAgent` | string | `"general"` | Default analysis agent when none is specified. |
| `nettrace.autoParseOnAdd` | boolean | `true` | Automatically parse capture files when added to workspace. |
| `nettrace.maxPacketsPerStream` | number | `1000` | Maximum packets per stream included in LLM context. |
| `nettrace.excludeProtocols` | string[] | `["arp", "mdns", "ssdp", ...]` | Protocols excluded from analysis by default. |

Default excluded protocols: `arp`, `mdns`, `ssdp`, `nbns`, `igmp`, `llmnr`, `cdp`, `lldp`, `stp`

### Workspace Configuration (.nettrace/ folder)

For advanced configuration, create a `.nettrace/` directory in your workspace root. The extension watches these files and hot-reloads changes automatically.

```
.nettrace/
├── config.json          # Workspace-level settings
├── scenario.json        # Scenario context injected into every prompt
├── agents/              # Custom analysis agents
│   ├── tls-specialist.json
│   ├── dns-troubleshooter.json
│   └── voip-analyzer.json
├── tools/               # Custom tool definitions
│   └── custom-tool.json
└── filters/             # Reusable filter profiles
    └── exclude-noise.json
```

#### config.json

```json
{
  "tsharkPath": "",
  "tokenBudget": {
    "maxInputTokens": 900000,
    "reserveForResponse": 100000
  },
  "defaultAgent": "general",
  "excludeProtocols": ["arp", "mdns", "ssdp"]
}
```

#### scenario.json

Providing scenario context helps the AI give more targeted diagnosis:

```json
{
  "scenarioId": "SR-2026-12345",
  "symptom": "TLS handshake timeout to api.contoso.com",
  "summary": "Customer reports intermittent 503 errors when connecting to the API endpoint",
  "topology": {
    "clientIP": "10.0.1.50",
    "serverIP": "40.112.72.205",
    "description": "Client → Corporate Proxy → Azure Front Door → App Service"
  },
  "notes": "Issue started after firewall rule change on Feb 10"
}
```

#### Custom Agents

Create JSON files in `.nettrace/agents/` to define specialized analysis agents:

```json
{
  "name": "tls-specialist",
  "displayName": "TLS/SSL Specialist",
  "description": "Expert analysis of TLS handshakes, certificates, and cipher suites",
  "persona": "You are an expert TLS/SSL protocol analyst...",
  "tools": ["nettrace-getStreamDetail", "nettrace-followStream", "nettrace-applyFilter"],
  "filters": {
    "displayFilter": "ssl || tls",
    "focusPorts": [443, 8443]
  }
}
```

---

## Workspace Initialization Wizard

Run **NetTrace: Initialize Workspace** to launch an interactive wizard that:

1. Asks what kind of traffic you're analyzing (General, Web/TLS, VoIP/SIP, DNS, Custom)
2. Asks if you have matched client + server captures
3. Optionally collects scenario details (scenario ID, symptom)
4. Creates the `.nettrace/` folder structure with appropriate agents and configuration

This is optional — the extension works without it — but provides a better starting point for focused analysis.

---

## Example Workflows

### Quick Diagnosis

```
1. Drop a .pcap file into your workspace
2. Wait for auto-parse (status bar notification)
3. Click the capture in the NetTrace sidebar to open the viewer
4. Open Copilot Chat → @nettrace what's wrong with this capture?
5. Follow the AI's suggestions for deeper analysis
```

### TLS Handshake Troubleshooting

```
1. Import your capture file
2. Run "NetTrace: Initialize Workspace" → select "Web / TLS"
3. Edit Scenario Context with the server hostname and IPs
4. Open the capture viewer
5. @nettrace /agent tls-specialist
6. @nettrace analyze the TLS handshakes — are there certificate or cipher issues?
```

### Client vs Server Comparison

```
1. Place client capture in a client/ subfolder
2. Place server capture in a server/ subfolder
3. Open both captures (extension auto-detects roles from folder names)
4. Open either capture in the viewer
5. @nettrace /compare — what packets are missing between client and server?
```

---

## Architecture

The extension follows a three-layer design:

```
┌─────────────────────────────────────────────────────────┐
│                   VS Code Extension                      │
├──────────────┬──────────────────┬────────────────────────┤
│  Parsing     │  Context         │  Presentation          │
│  Layer       │  Assembly        │  Layer                 │
│              │  Engine          │                        │
│  tsharkRun-  │  contextAssem-   │  @nettrace Chat        │
│  ner.ts      │  bler.ts         │  Participant           │
│              │                  │  Capture Viewer        │
│  Spawns      │  Token budget    │  Sidebar TreeViews     │
│  tshark CLI  │  management      │  LM Tools              │
│  processes   │  (~900K usable)  │                        │
│              │  Priority-ranked │                        │
│  Parallel    │  streams (anom-  │  Commands, Menus,      │
│  execution   │  aly score)      │  Configuration         │
└──────────────┴──────────────────┴────────────────────────┘
         │                │                    │
         ▼                ▼                    ▼
    Binary pcap     Structured prompt     GitHub Copilot
    files           for LLM              Language Model API
```

1. **Parsing Layer** — Spawns tshark as a child process to convert binary pcap files into structured text. Runs multiple tshark commands in parallel for speed.
2. **Context Assembly Engine** — Manages the token budget, prioritizes anomalous streams, and structures the prompt for maximum diagnostic value. Knowledge templates are conditionally injected based on capture signals.
3. **Presentation Layer** — The `@nettrace` chat participant, capture viewer webview, sidebar tree views, and Language Model Tools that allow the AI to autonomously gather more data.

**No separate API keys required** — the extension uses `vscode.lm.selectChatModels()` to access the same models your Copilot subscription provides.

---

## Development

### Building from Source

```bash
git clone https://github.com/kkfrosty/nettraceagentix.git
cd nettraceagentix
npm install
npm run compile
```

### Running in Development

1. Open the project in VS Code
2. Press **F5** to launch the Extension Development Host
3. In the new VS Code window, open a folder with `.pcap` files
4. Use the extension normally — changes are reflected after recompile

For continuous compilation during development:

```bash
npm run watch
```

Or use the built-in VS Code task: **Terminal → Run Build Task** (Ctrl+Shift+B) which runs the `watch` script.

### Packaging

```bash
npm run package
```

This runs `npx @vscode/vsce package` and produces a `.vsix` file you can distribute.

### Project Structure

```
src/
├── extension.ts                    # Entry point — activation, commands, auto-discovery
├── types.ts                        # All shared TypeScript interfaces
├── configLoader.ts                 # Loads .nettrace/ JSON config with hot-reload watchers
├── contextAssembler.ts             # Token budgeting, priority ranking, prompt assembly
├── workspaceInitializer.ts         # Workspace scaffolding wizard
├── parsing/
│   └── tsharkRunner.ts             # tshark execution engine (all pcap parsing)
├── participant/
│   └── nettraceParticipant.ts      # @nettrace chat participant handler
├── views/
│   ├── capturesTreeProvider.ts     # Sidebar: capture files
│   ├── streamsTreeProvider.ts      # Internal: TCP streams sorted by anomaly score
│   ├── scenarioDetailsTreeProvider.ts  # Sidebar: scenario context
│   ├── agentsTreeProvider.ts       # Agent management
│   └── captureWebviewPanel.ts      # Interactive capture viewer
└── tools/
    └── lmTools.ts                  # Language Model Tools the AI calls during analysis

NetTraceAIAnalysisWorkspace/         # Working workspace for capture analysis
├── .nettrace/                       # Extension configuration (auto-created)
│   ├── knowledge/                   # Domain knowledge injected into LLM context
│   │   ├── known-issues/            # Platform/device-specific known issues
│   │   ├── security/                # Security analysis heuristics
│   │   └── wisdom/                  # False positive avoidance guidance
│   ├── agents/                      # Custom analysis agent definitions
│   ├── config.json                  # Workspace settings
│   └── scenario.json                    # Scenario context for analysis
└── captures/                        # Drop .pcap files here
```

---

## Troubleshooting

### tshark not found

The extension needs tshark (included with Wireshark) to parse capture files. If you see a warning:

1. Install [Wireshark](https://www.wireshark.org/download.html) (includes tshark)
2. Ensure tshark is on your system PATH, **or**
3. Set the full path in VS Code settings: `nettrace.tsharkPath`

### "No capture is open" when chatting

The `@nettrace` participant requires an active capture in the viewer:

1. Click on a capture file in the **NetTrace** sidebar
2. Or run **NetTrace: Open Capture Viewer** from the Command Palette
3. Then return to Copilot Chat and ask your question

### Extension not activating

The extension activates when it detects:
- Any `.pcap`, `.pcapng`, or `.cap` file in the workspace
- A `.nettrace/config.json` file
- Or when you run a NetTrace command manually

If nothing happens, try running **NetTrace: Import Capture File** from the Command Palette.

### Copilot Chat not showing @nettrace

Ensure:
- GitHub Copilot Chat extension is installed and active
- You have an active GitHub Copilot subscription
- The extension has loaded (check the **NetTrace** output channel: View → Output → select "NetTrace")

### Large captures are slow

For very large captures (100MB+):
- The extension caps packet data per stream to keep within the token budget
- Use the **Scenario Context** to narrow the AI's focus
- Apply display filters to reduce noise: `@nettrace apply filter tcp.port == 443`
- Switch to a specialized agent that filters to relevant traffic only

---

## License

[MIT](LICENSE)

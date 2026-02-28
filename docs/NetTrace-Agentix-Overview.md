# NetTrace Agentix

*~15 min presentation + ~15 min live demo*

---

# The Problem

- Reading packet captures requires **years** of networking experience in understanding protocols such as TCP and then services such as DNS, HTTP etc which few have without extensive experience with networking.
- Network cases get **escalated and queued**, adding time to resolution
- Customers collect traces as instructed but **can't interpret them** — they wait for a specialist

> Every support case that touches networking can become just as much of a scheduling problem, as a technical one.

---

# AI Network Capture Analysis

### A VS Code extension that turns GitHub Copilot into an expert network analyst

**How it works:**

1. User adds a `.pcap` into the workspace used for the extension in VS Code
2. Extension parses the capture using TShark so the packets are displayed in an editor with Wireshark-like features
3. A user can add details about the capture and use the Analyze button
4. Or a user types `@nettrace analyze the selected capture for network connection issues` in Copilot Chat
5. AI delivers structured root cause analysis — and drills deeper on its own. The user can interact back and forth to ask questions
6. Knowledge templates let users teach the agent domain-specific behavior and known issues

### Why VS Code

- **Zero cost, universal access** — Anyone with VS Code and a GitHub Copilot subscription can use this. Large context models (1M+ tokens) are included with Copilot — no additional AI compute cost. Wireshark/tshark is free open source. The extension is available on the VS Code Marketplace or as a `.vsix` file.

- **MCP service integration** — VS Code supports Model Context Protocol (MCP) servers, enabling the AI to reach out to live services during analysis. When the AI detects an issue (e.g., a TLS cipher mismatch or firewall timeout), it can query documentation sources for the relevant details and recommend the exact steps to resolve it — diagnosis and remediation in one workflow.

- **Built-in file and document parsing** — GitHub Copilot in VS Code can natively ingest workspace files: product documentation, release notes, runbooks, even source code. This means teams can drop reference material alongside their captures and the AI incorporates it automatically — **no AI Search indexes, no custom RAG pipelines, no vector databases to build and maintain**. The workspace *is* the knowledge base.

- **Rich extension ecosystem** — VS Code provides TreeViews, Webviews, Chat Participants, commands, and status indicators. This gives us a full diagnostic UI (sidebar anomaly ranking, interactive packet viewer, case context panels) that a standalone CLI tool or MCP server alone cannot offer.

- **Extensible tooling platform** — Beyond this extension, engineers already use VS Code for terminal access, SSH to remote machines, cloud resource management, and Git workflows. Network analysis becomes part of an environment they already live in — not another tool to context-switch into.

**There is nothing to purchase beyond an existing GitHub Copilot subscription.** VS Code and Wireshark/tshark are free.

---

# Why Now — The 1M Token Context Window

Previous AI approaches to network analysis failed because captures didn't fit in the context window.

| Approach | Limit | Result |
|---|---|---|
| Earlier models | 8K–128K tokens | Sees a fraction of the capture — misses cross-stream issues |
| Summarize first | Any | Lossy — removes the exact details needed for diagnosis |
| **Large context models via Copilot** | **1M tokens** | **Full capture + domain knowledge + conversation — all at once** |

For the first time, an LLM can do what a human expert does: **see the whole picture simultaneously** — every connection, every protocol, every anomaly.

---

# Not Just Chat — The AI Investigates Autonomously

The extension gives the AI **7 diagnostic tools** it calls on its own during analysis:

- **Get Stream Detail / Packet Range** — inspect specific connections or frame ranges
- **Get Expert Info** — pull Wireshark's built-in error and warning detection
- **Apply Display Filter** — focus on specific traffic (port 443, retransmissions, etc.)
- **Follow Stream** — reconstruct application-layer data (HTTP, TLS handshakes)
- **Compare Captures** — correlate client-side and server-side traces to find what's lost in transit

The AI starts broad and narrows autonomously — exactly like a senior network engineer.

It also carries **embedded domain knowledge**: TCP behaviors, firewall vendor quirks (Palo Alto, Cisco, F5, cloud-based firewalls), security heuristics, and guidance on common false positives — the equivalent of a 20-year veteran reviewing every analysis.

---

# Impact

| Metric | Before | After |
|---|---|---|
| **Who can analyze captures** | ~5-10% of engineers | **Anyone with VS Code + Copilot** |
| **Time to first diagnosis** | Hours to days (waiting for specialist) | **Minutes** |
| **Escalation rate** | Most network cases escalate | Frontline can triage — fewer escalations |
| **New hire ramp-up** | Months of mentoring | AI explains its reasoning — instant learning |
| **Customer self-service** | Not feasible | Customer runs extension locally — deflects cases |
| **Incremental cost** | Senior engineer time | **$0 — covered by existing Copilot subscription** |

---

# Get Involved

1. **Try it** — Install from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=CognitiveAgentics.nettrace-agentix) or build from [source](https://github.com/kkfrosty/nettraceagentix)
2. **Contribute** — Submit issues, PRs, or custom agents on [GitHub](https://github.com/kkfrosty/nettraceagentix)
3. **Knowledge contributions** — Domain experts can add known issues and heuristics to the knowledge templates
4. **Custom agents** — Create and share specialized analysis agents for your domain (TLS, DNS, VoIP, etc.)

### What's next on the roadmap

MVP is **complete and functional today**. Planned enhancements: visual flow diagrams, redaction mode for sensitive payloads, shareable agent packs for teams.

---

# Summary

| | |
|---|---|
| **What** | VS Code extension — turns Copilot into an expert network analyst |
| **Cost** | **$0 beyond Copilot subscription** — VS Code and Wireshark are free |
| **Impact** | 10-20x more people can analyze captures; minutes instead of days to diagnosis |
| **Risk** | Near zero — lightweight extension, no infrastructure, no new data paths |
| **Status** | MVP complete — available on VS Code Marketplace |

---

# Live Demo

*Let's see it in action...*

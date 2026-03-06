# NetTrace Agentix Presentation Script

## 1. Opening And Goal (1-2 minutes)
1. Introduce NetTrace Agentix as a VS Code extension that combines tshark packet parsing with GitHub Copilot-powered diagnosis.
2. Explain the value proposition: support engineers can move from raw packet captures to root-cause insights faster, without being Wireshark experts.
3. Set audience expectations for the demo flow:
   1. Installation and prerequisites.
   2. Capture analysis features.
   3. Agents and knowledge files.
   4. AI analysis + manual self-inspection.
   5. Live capture and suspicious traffic detection.

## 2. Installation Walkthrough (3-5 minutes)
1. State prerequisites:
   1. VS Code.
   2. GitHub Copilot + Copilot Chat enabled.
   3. Wireshark/tshark installed.
2. Show tshark verification in terminal:
   1. Run `tshark --version`.
   2. Confirm tshark is on PATH (or mention configured path in settings).
3. Show extension install path:
   1. Install from Marketplace or from VSIX.
   2. If from source, summarize: `npm install`, `npm run compile`, `npm run package`, then install generated VSIX.
4. Open a workspace and confirm NetTrace view appears in the Activity Bar.

## 3. Capture Features Tour (5-7 minutes)
1. Add one or more `.pcap`/`.pcapng` files to the workspace.
2. In the NetTrace sidebar, show:
   1. Captures list.
   2. Stream-centric workflow (anomalies bubble up).
   3. Scenario/context panels if configured.
3. Open a capture in the Capture Viewer and narrate:
   1. Packet list (time, source, destination, protocol, info).
   2. Filtering workflow using Wireshark display filters.
   3. Packet detail and byte-level data panes.
4. Emphasize analyst productivity:
   1. Fast triage in-editor.
   2. No context switching between tools for common tasks.

## 4. How Agents Work (5 minutes)
1. Explain that `@nettrace` is a Copilot Chat participant specialized for packet analysis.
2. Show command-style interactions:
   1. `@nettrace /summarize`
   2. `@nettrace /diagnose`
   3. `@nettrace /stream 5`
3. Explain agent behavior in plain language:
   1. Starts broad, then drills down autonomously.
   2. Can call analysis tools (stream details, expert info, conversations, follow stream, filter application, compare captures).
4. Show switching agents (if available) with `@nettrace /agent <agent-name>`.
5. Explain outcome: each agent can focus on a protocol domain (for example TLS, DNS, or VoIP).

## 5. Knowledge Files And Why They Matter (4 minutes)
1. Introduce `.nettrace/knowledge/` as reusable analyst intelligence.
2. Explain what goes into knowledge files:
   1. Known incident signatures.
   2. Environment-specific network expectations.
   3. Common false positives and interpretation hints.
3. Show how enabling/disabling knowledge changes assistant context.
4. Position this as institutional memory: better consistency across analysts and incident response sessions.

## 6. Demo: Analyze A Capture With AI (6-8 minutes)
1. Open a real capture file from the workspace.
2. In Copilot Chat, run:
   1. `@nettrace what's wrong with this capture?`
3. Narrate the returned diagnosis:
   1. Primary symptoms.
   2. Most suspicious streams.
   3. Recommended next checks.
4. Ask one follow-up that forces deeper reasoning:
   1. `@nettrace which stream is most likely root cause and why?`
5. Optional depth command:
   1. `@nettrace /stream <index>`

## 7. Demo: Inspect The Capture Yourself (4-6 minutes)
1. Pivot from AI output to manual validation in the viewer.
2. Apply focused filters based on AI findings (examples):
   1. `tcp.stream eq <index>`
   2. `dns`
   3. `tcp.analysis.retransmission`
3. Open packet details and bytes to prove the finding directly from packets.
4. Reinforce trust model:
   1. AI accelerates triage.
   2. Analyst remains in control and can verify evidence at packet level.

## 8. Live Trace + Suspicious Traffic Detection (8-10 minutes)
1. Start live capture from command palette:
   1. `NetTrace: Start Live Capture`
2. Select interface (for example Wi-Fi or Ethernet).
3. Optional: set BPF filter to narrow scope (for example `port 443` or `host <target-ip>`).
4. Begin capture and generate a small amount of traffic (web browse, DNS query, app login, or scripted test traffic).
5. Stop capture and immediately analyze using AI.
6. Prompt examples for suspicious activity checks:
   1. `@nettrace analyze this trace for suspicious traffic`
   2. `@nettrace identify unusual connections, scanning behavior, or beaconing indicators`
   3. `@nettrace prioritize the top 3 risks and explain confidence`
7. Show final output as an incident-ready summary:
   1. Suspicious indicators.
   2. Evidence streams/packets.
   3. Recommended containment or next forensic actions.

## 9. Closing (2 minutes)
1. Recap the full workflow:
   1. Install quickly.
   2. Analyze historical captures.
   3. Use domain agents + knowledge files.
   4. Validate manually.
   5. Run live capture for real-time investigations.
2. End with a practical call to action:
   1. Pilot with one support/security workflow this week.
   2. Add team knowledge files for repeatable diagnoses.
   3. Standardize on a short runbook using the prompts shown.

## 10. Quick Backup Prompts (Use If Demo Needs Recovery)
1. `@nettrace /summarize`
2. `@nettrace /diagnose`
3. `@nettrace list the most anomalous streams`
4. `@nettrace what evidence supports your conclusion?`
5. `@nettrace what should I check next in the viewer?`

## 11. Presenter Notes
1. Keep one known-good capture and one intentionally noisy/suspicious capture ready.
2. Pre-verify tshark and Copilot Chat before starting the session.
3. If live capture permissions fail, pivot to a pre-recorded live capture file and continue the same analysis narrative.
4. Keep the message consistent: NetTrace Agentix improves speed to insight while preserving analyst-level verification.

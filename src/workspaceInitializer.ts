import * as vscode from 'vscode';
import * as path from 'path';
import { NetTraceConfig, ScenarioDetails } from './types';

/**
 * Handles workspace initialization — creating the .nettrace/ folder structure
 * and scaffolding default configuration files.
 */
export class WorkspaceInitializer {
    private rootUri: vscode.Uri;
    private outputChannel: vscode.OutputChannel;

    constructor(rootUri: vscode.Uri, outputChannel: vscode.OutputChannel) {
        this.rootUri = rootUri;
        this.outputChannel = outputChannel;
    }

    /**
     * Check if the storage root is initialized (has a config.json).
     */
    async isInitialized(): Promise<boolean> {
        const configUri = vscode.Uri.joinPath(this.rootUri, '.nettrace', 'config.json');
        try {
            await vscode.workspace.fs.stat(configUri);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Prompt the user to initialize the workspace if not already done.
     */
    async promptInitialize(): Promise<boolean> {
        const action = await vscode.window.showInformationMessage(
            'This workspace is not set up for NetTrace. Initialize it for network capture analysis?',
            'Initialize',
            'Not Now'
        );

        if (action === 'Initialize') {
            return await this.initializeWorkspace();
        }
        return false;
    }

    /**
     * Run the full workspace initialization wizard.
     */
    async initializeWorkspace(): Promise<boolean> {
        const rootUri = this.rootUri;

        // Step 1: What kind of traffic?
        const trafficType = await vscode.window.showQuickPick(
            [
                { label: 'General', description: 'Any network traffic', detail: 'Includes general-purpose analyzer agent' },
                { label: 'Web / TLS', description: 'HTTPS, TLS, HTTP traffic', detail: 'Adds TLS specialist agent with certificate analysis tools' },
                { label: 'VoIP / SIP', description: 'SIP signaling, RTP streams', detail: 'Adds VoIP analyzer agent with SIP/RTP tools' },
                { label: 'DNS', description: 'DNS resolution issues', detail: 'Adds DNS troubleshooter agent' },
                { label: 'Custom', description: 'Start with minimal config', detail: 'Just creates the folder structure, no pre-configured agents' },
            ],
            { placeHolder: 'What kind of traffic are you analyzing?', title: 'NetTrace: Initialize Workspace' }
        );

        if (!trafficType) { return false; }

        // Step 2: Client/server captures?
        const hasMatchedCaptures = await vscode.window.showQuickPick(
            [
                { label: 'Single capture point', description: 'One capture file to analyze' },
                { label: 'Matched client + server', description: 'I have captures from both ends to compare' },
            ],
            { placeHolder: 'Do you have matching captures from both sides?', title: 'NetTrace: Capture Setup' }
        );

        if (!hasMatchedCaptures) { return false; }
        const isClientServer = hasMatchedCaptures.label.includes('Matched');

        // Step 3: Scenario details (optional)
        const scenarioId = await vscode.window.showInputBox({
            prompt: 'Scenario/ticket number (optional)',
            placeHolder: 'e.g., SR-2026-12345',
            title: 'NetTrace: Scenario Details',
        });

        const symptom = await vscode.window.showInputBox({
            prompt: 'What is the reported symptom? (optional)',
            placeHolder: 'e.g., TLS handshake timeout to api.contoso.com',
            title: 'NetTrace: Scenario Details',
        });

        // Create folder structure
        await this.createFolderStructure(rootUri, isClientServer);

        // Create config
        await this.createConfig(rootUri, trafficType.label, isClientServer);

        // Create scenario details
        if (scenarioId || symptom) {
            await this.createScenarioDetails(rootUri, scenarioId, symptom);
        }

        // Create agents based on traffic type
        await this.createAgents(rootUri, trafficType.label);

        // Create default filter
        await this.createDefaultFilters(rootUri);

        // Create knowledge base with starter content
        await this.createKnowledgeBase(rootUri);

        this.outputChannel.appendLine(`[WorkspaceInitializer] Workspace initialized: ${rootUri.fsPath}`);

        vscode.window.showInformationMessage(
            'NetTrace workspace initialized! Drop your capture files into the captures/ folder.',
            'Import Capture'
        ).then(action => {
            if (action === 'Import Capture') {
                vscode.commands.executeCommand('nettrace.importCapture');
            }
        });

        return true;
    }

    // ─── Scaffold Creators ────────────────────────────────────────────────

    private async createFolderStructure(rootUri: vscode.Uri, isClientServer: boolean): Promise<void> {
        const dirsToCreate = [
            '.nettrace',
            '.nettrace/agents',
            '.nettrace/tools',
            '.nettrace/filters',
            '.nettrace/templates',
            '.nettrace/knowledge',
            '.nettrace/knowledge/wisdom',
            '.nettrace/knowledge/security',
            '.nettrace/knowledge/known-issues',
            'analysis',
        ];

        if (isClientServer) {
            dirsToCreate.push('captures/client', 'captures/server');
        } else {
            dirsToCreate.push('captures');
        }

        for (const dir of dirsToCreate) {
            const dirUri = vscode.Uri.joinPath(rootUri, dir);
            try {
                await vscode.workspace.fs.createDirectory(dirUri);
            } catch {
                // Already exists
            }
        }
    }

    private async createConfig(rootUri: vscode.Uri, trafficType: string, isClientServer: boolean): Promise<void> {
        const agentMap: Record<string, string> = {
            'General': 'general',
            'Web / TLS': 'tls-specialist',
            'VoIP / SIP': 'voip-analyzer',
            'DNS': 'dns-troubleshooter',
            'Custom': 'general',
        };

        const config: NetTraceConfig = {
            captureDirectories: ['captures'],
            outputDirectory: 'analysis',
            defaultAgent: agentMap[trafficType] || 'general',
            defaultFilters: {
                excludeProtocols: ['arp', 'mdns', 'ssdp', 'nbns', 'igmp', 'llmnr', 'cdp', 'lldp', 'stp'],
                maxPacketsPerStream: 1000,
            },
            tokenBudget: {
                maxInputTokens: 900000,
                reserveForResponse: 100000,
                summaryBudget: 5000,
                perStreamBudget: 50000,
            },
        };

        if (isClientServer) {
            config.captureMapping = {
                mode: 'client-server',
                pairs: [],
            };
        }

        const configUri = vscode.Uri.joinPath(rootUri, '.nettrace', 'config.json');
        await vscode.workspace.fs.writeFile(configUri, Buffer.from(JSON.stringify(config, null, 2)));
    }

    private async createScenarioDetails(rootUri: vscode.Uri, scenarioId?: string, symptom?: string): Promise<void> {
        const scenarioDetails: ScenarioDetails = {};
        if (scenarioId) { scenarioDetails.scenarioId = scenarioId; }
        if (symptom) { scenarioDetails.symptom = symptom; }
        scenarioDetails.topology = { description: '', clientIP: '', serverIP: '', relevantPorts: [] };
        scenarioDetails.notes = '';

        const scenarioUri = vscode.Uri.joinPath(rootUri, '.nettrace', 'scenario.json');
        await vscode.workspace.fs.writeFile(scenarioUri, Buffer.from(JSON.stringify(scenarioDetails, null, 2)));
    }

    private async createAgents(rootUri: vscode.Uri, trafficType: string): Promise<void> {
        // TLS specialist
        if (trafficType === 'Web / TLS' || trafficType === 'General') {
            const tlsAgent = {
                name: 'tls-specialist',
                displayName: 'TLS/SSL Specialist',
                description: 'Expert at diagnosing TLS handshake failures, certificate issues, and cipher problems',
                icon: 'lock',
                systemPrompt: `You are an expert TLS/SSL network analyst. Focus on:
- Certificate chain validation and expiry
- Cipher suite negotiation and mismatches
- TLS handshake failures and alert messages
- Protocol version mismatches (TLS 1.0/1.1/1.2/1.3)
- Key exchange issues
- SNI (Server Name Indication) problems
- Certificate transparency and pinning issues

Always reference specific packet numbers and timestamps.
Explain cipher suite names in plain terms.
When you find certificate issues, specify the exact expiry date and subject.`,
                autoFilters: {
                    displayFilter: 'tls || ssl || tcp.port == 443',
                    excludeProtocols: ['arp', 'mdns', 'dns', 'icmp'],
                },
                tools: [
                    'nettrace-getStreamDetail',
                    'nettrace-getExpertInfo',
                    'nettrace-applyFilter',
                    'nettrace-followStream',
                ],
                contextPriority: {
                    prioritySignals: [
                        'tls.alert_message',
                        'tls.handshake.type == 1',
                        'tls.handshake.type == 2',
                        'tls.handshake.type == 11',
                    ],
                    alwaysInclude: ['tls.handshake'],
                    maxStreamsToAnalyze: 20,
                },
                followups: [
                    { label: 'Check certificates', prompt: 'Are any certificates expired or about to expire?' },
                    { label: 'Cipher analysis', prompt: 'What cipher suites were negotiated? Are any weak or deprecated?' },
                    { label: 'Handshake failures', prompt: 'Show me all TLS handshake failures and their alert messages' },
                    { label: 'Protocol versions', prompt: 'What TLS versions are being used? Any downgrades?' },
                ],
            };

            const agentUri = vscode.Uri.joinPath(rootUri, '.nettrace', 'agents', 'tls-specialist.json');
            await vscode.workspace.fs.writeFile(agentUri, Buffer.from(JSON.stringify(tlsAgent, null, 2)));
        }

        // DNS troubleshooter
        if (trafficType === 'DNS' || trafficType === 'General') {
            const dnsAgent = {
                name: 'dns-troubleshooter',
                displayName: 'DNS Troubleshooter',
                description: 'Specializes in DNS resolution failures, slow lookups, and NXDOMAIN issues',
                icon: 'globe',
                systemPrompt: `You are a DNS troubleshooting expert. Focus on:
- DNS query/response pairs — identify unanswered queries
- NXDOMAIN and SERVFAIL responses
- Slow DNS resolution (high latency between query and response)
- DNS server selection and failover behavior
- CNAME chains and resolution depth
- DNSSEC validation issues
- DNS-over-HTTPS/TLS detection

Present DNS lookups as query→response pairs with timing.
Highlight any DNS lookups that took abnormally long.`,
                autoFilters: {
                    displayFilter: 'dns',
                    excludeProtocols: ['arp', 'mdns', 'ssdp'],
                },
                tools: [
                    'nettrace-applyFilter',
                    'nettrace-getExpertInfo',
                    'nettrace-getStreamDetail',
                ],
                followups: [
                    { label: 'Failed lookups', prompt: 'Show all DNS queries that got NXDOMAIN or SERVFAIL responses' },
                    { label: 'Slow lookups', prompt: 'Which DNS queries took the longest to resolve?' },
                    { label: 'DNS servers', prompt: 'What DNS servers are being queried and are any failing?' },
                ],
            };

            const agentUri = vscode.Uri.joinPath(rootUri, '.nettrace', 'agents', 'dns-troubleshooter.json');
            await vscode.workspace.fs.writeFile(agentUri, Buffer.from(JSON.stringify(dnsAgent, null, 2)));
        }

        // VoIP analyzer
        if (trafficType === 'VoIP / SIP') {
            const voipAgent = {
                name: 'voip-analyzer',
                displayName: 'VoIP/SIP Analyzer',
                description: 'Specializes in SIP signaling, RTP quality, and call flow analysis',
                icon: 'call-outgoing',
                systemPrompt: `You are a VoIP network analyst specializing in SIP and RTP. Focus on:
- SIP call flow sequences (INVITE → 100 Trying → 180 Ringing → 200 OK → ACK → BYE)
- SIP error responses (4xx, 5xx, 6xx)
- Registration failures (REGISTER → 401 → REGISTER w/auth → 200)
- RTP stream quality metrics (jitter, packet loss, codec identification)
- NAT traversal issues (SDP vs actual RTP endpoints)
- SRTP/ZRTP encryption

Present SIP call flows as step-by-step sequences.
Identify calls that fail and explain at what stage they fail.
For RTP, calculate jitter and loss percentage.`,
                autoFilters: {
                    displayFilter: 'sip || rtp || rtcp',
                    groupBy: 'sip.Call-ID',
                },
                tools: [
                    'nettrace-applyFilter',
                    'nettrace-getStreamDetail',
                    'nettrace-followStream',
                    'nettrace-getExpertInfo',
                ],
                followups: [
                    { label: 'Call flows', prompt: 'Show me the SIP call flows — are any calls failing?' },
                    { label: 'RTP quality', prompt: 'What is the RTP stream quality? Any jitter or packet loss?' },
                    { label: 'Registration', prompt: 'Are SIP registrations succeeding? Show any auth failures.' },
                ],
            };

            const agentUri = vscode.Uri.joinPath(rootUri, '.nettrace', 'agents', 'voip-analyzer.json');
            await vscode.workspace.fs.writeFile(agentUri, Buffer.from(JSON.stringify(voipAgent, null, 2)));
        }
    }

    private async createDefaultFilters(rootUri: vscode.Uri): Promise<void> {
        const noiseFilter = {
            name: 'exclude-noise',
            description: 'Excludes common background protocols that are rarely relevant to support cases',
            excludeProtocols: ['arp', 'mdns', 'ssdp', 'nbns', 'igmp', 'llmnr', 'cdp', 'lldp', 'stp', 'browser'],
            excludeTrafficTypes: ['broadcast', 'multicast'],
        };

        const filterUri = vscode.Uri.joinPath(rootUri, '.nettrace', 'filters', 'exclude-noise.json');
        await vscode.workspace.fs.writeFile(filterUri, Buffer.from(JSON.stringify(noiseFilter, null, 2)));
    }

    /**
     * Create the knowledge base with starter content.
     * Users can edit these files or add new .md files to customize the agent's knowledge.
     *
     * Structure:
     *   wisdom/       — Always injected (false positives, capture artifacts, expert tips)
     *   security/     — Only injected when security-relevant anomalies are detected
     *   known-issues/ — Always injected (vendor bugs, OS behaviors, known gotchas)
     */
    private async createKnowledgeBase(rootUri: vscode.Uri): Promise<void> {
        // Try to load from bundled templates first, fall back to inline content
        const templatePairs: Array<{ category: string; filename: string; content: string }> = [
            {
                category: 'wisdom',
                filename: 'analysis-false-positives.md',
                content: await this.loadTemplateOrDefault(rootUri, 'wisdom/analysis-false-positives.md',
                    this.getWisdomTemplate()),
            },
            {
                category: 'security',
                filename: 'security-heuristics.md',
                content: await this.loadTemplateOrDefault(rootUri, 'security/security-heuristics.md',
                    this.getSecurityTemplate()),
            },
            {
                category: 'known-issues',
                filename: 'windows-tcp.md',
                content: await this.loadTemplateOrDefault(rootUri, 'known-issues/windows-tcp.md',
                    this.getWindowsTcpTemplate()),
            },
            {
                category: 'known-issues',
                filename: 'firewall-appliance-quirks.md',
                content: await this.loadTemplateOrDefault(rootUri, 'known-issues/firewall-appliance-quirks.md',
                    this.getFirewallTemplate()),
            },
        ];

        for (const { category, filename, content } of templatePairs) {
            const fileUri = vscode.Uri.joinPath(rootUri, '.nettrace', 'knowledge', category, filename);
            try {
                // Don't overwrite existing files — user may have customized them
                await vscode.workspace.fs.stat(fileUri);
                this.outputChannel.appendLine(`[WorkspaceInitializer] Knowledge file exists, skipping: ${category}/${filename}`);
            } catch {
                await vscode.workspace.fs.writeFile(fileUri, Buffer.from(content));
                this.outputChannel.appendLine(`[WorkspaceInitializer] Created knowledge file: ${category}/${filename}`);
            }
        }

        // Create a README explaining the knowledge base
        const readmeUri = vscode.Uri.joinPath(rootUri, '.nettrace', 'knowledge', 'README.md');
        try {
            await vscode.workspace.fs.stat(readmeUri);
        } catch {
            await vscode.workspace.fs.writeFile(readmeUri, Buffer.from(this.getKnowledgeReadme()));
        }
    }

    private async loadTemplateOrDefault(_rootUri: vscode.Uri, _templatePath: string, defaultContent: string): Promise<string> {
        // Knowledge templates are created inline below and written to .nettrace/knowledge/.
        // Users customize by editing those files directly — no separate template folder needed.
        return defaultContent;
    }

    private getKnowledgeReadme(): string {
        return `# NetTrace Knowledge Base

This folder contains markdown files that teach the analysis agent about common patterns,
false positives, and known issues. The agent reads these before analyzing your capture.

## Folder Structure

- **wisdom/** — Always loaded. Contains expert knowledge about false positives, capture
  artifacts, and things that look wrong but aren't. Edit these when the agent flags
  something that shouldn't be flagged.

- **security/** — Conditionally loaded. Only injected when the capture contains
  security-relevant anomalies (malformed packets, IP fragments, suspicious TCP flags).
  If your capture is just a client not getting a response, this won't activate.

- **known-issues/** — Always loaded. Vendor-specific bugs, OS behaviors, firewall
  quirks, and other "it's not a bug, it's a feature" situations.

## How to Customize

1. **Agent getting it wrong?** Edit the relevant .md file to add guidance.
2. **New pattern to teach?** Create a new .md file in the appropriate folder.
3. **Changes take effect immediately** — the extension hot-reloads on file save.

## Examples

### Teaching the agent about a specific firewall behavior
Create \`known-issues/checkpoint-quirks.md\`:
\`\`\`markdown
# Known Issues — Check Point Firewalls
## SmartDefense TCP Sequence Verification
Check Point's SmartDefense feature verifies TCP sequence numbers and may drop
packets it considers "out of window." This can cause legitimate retransmissions
to be dropped, making packet loss appear worse than it actually is.
\`\`\`

### Correcting a false positive
Edit \`wisdom/analysis-false-positives.md\` and add:
\`\`\`markdown
### Our Load Balancer Sends RST on Health Check Failure
Our F5 sends RST to the server when a health check fails. This looks like
a connection error but is expected behavior. The server IP is 10.0.1.50.
\`\`\`
`;
    }

    private getWisdomTemplate(): string {
        return `# Analysis False Positives & Expert Guidance

## Common False Positives — Do NOT Flag These as Problems

### TCP RST After FIN Is Normal
A TCP RST sent after a proper FIN/FIN-ACK handshake is a common optimization.
This is NOT a connection error or attack.

### Wireshark Mislabels Retransmissions in NIC Teaming / NAT / Mirroring
When traffic passes through NIC teaming, NAT gateways, or SPAN/mirror ports,
Wireshark sees duplicate packets and flags them as retransmissions.
Check for SAME content with DIFFERENT MACs or sub-millisecond timing.

### Container / Kubernetes Environments Multiply Packets
In AKS/EKS/GKE, packets traverse pod veth → bridge → host NIC (2-3x duplication).
Sub-millisecond duplicates are capture artifacts, not retransmissions.

### Duplicate ACKs ≤ 3 Are Normal
TCP fast retransmit triggers at 3 DupACKs. Small numbers are expected behavior.

### RST to Closed Port Is Expected
Server sends RST when client connects to a port with no listener.
Standard TCP behavior (RFC 793).

## Firewall Behaviors That Look Wrong But May Be Expected
- Firewalls inject RST to both sides when blocking — looks like endpoint reset
- MSS clamping when VPN/tunnel is in path
- Stateful timeout drops after idle period (30s-1hr depending on vendor)
- DPI adds latency visible as inter-packet gaps
`;
    }

    private getSecurityTemplate(): string {
        return `# Security Analysis Heuristics

Activated when the capture contains malformed packets, fragments, or suspicious flags.

## Protocol Violations Are Assumed Hostile
Malformed packets with field contradictions are CRITICAL. Legitimate software
does not produce malformed packets.

EXCEPTION: If ALL packets have bad checksums, it's NIC offload, not an attack.

## Fragmentation Is Suspicious by Default
IP fragments are rare in modern networks. Investigate any fragments found:
- Overlapping offsets (teardrop signature)
- Fragments < 256 bytes
- Inconsistent total sizes

## Expert Info Errors Are Critical in Security Context
When malformed/fragmented traffic is present, expert errors are elevated findings.
Ask: "What legitimate system would produce this?"
`;
    }

    private getWindowsTcpTemplate(): string {
        return `# Known Issues — Windows TCP/IP Stack

## Windows TCP RST Behavior
- RST for packets to TIME_WAIT connections (RFC-compliant, generates extra RSTs)
- RST instead of FIN when SO_LINGER timeout=0 (intentional fast teardown)

## TCP Chimney / Offload (Legacy)
On Windows 2008 R2/2012, TCP Chimney can make packets invisible to captures.
Check: netsh int tcp show global

## TCP Auto-Tuning
Window auto-tuning causes large window swings (64KB → 16MB). Normal behavior.
Disabled auto-tuning + high bandwidth = throughput bottleneck.

## Windows Firewall (WFP)
May drop packets silently (no RST, no ICMP). Check: netsh wfp show state

## SMB Behaviors
- Multichannel = multiple TCP connections (intentional, not a leak)
- SMB signing adds per-packet latency
- Dialect negotiation can cause RSTs
`;
    }

    private getFirewallTemplate(): string {
        return `# Known Issues — Firewalls & Network Appliances

## Stateful Firewall Timeouts
TCP established ~1hr, half-open 30-120s, UDP 30-60s.
After timeout: next packet dropped or RST'd.
Diagnosis: look for idle gap before failure.

## Asymmetric Routing + Stateful Firewalls
Return traffic through different firewall = no state = dropped.
Symptoms: SYN out, no SYN-ACK back; intermittent drops.

## Azure NSG / Firewall
- Flow tracking timeout: 4 minutes idle TCP
- Load Balancer RSTs on health probe failure
- SNAT exhaustion: SYN with no response

## VPN Issues
- IPSec reduces MTU by 50-80 bytes; PMTUD broken if ICMP blocked
- SSL VPN TCP-in-TCP causes retransmission amplification
`;
    }
}

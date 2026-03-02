import * as vscode from 'vscode';
import * as path from 'path';
import { CaptureFile, TcpStream, AgentDefinition, ScenarioDetails, AssembledContext, TokenBudgetConfig, CaptureSignals, KnowledgeEntry } from './types';
import { TsharkRunner } from './parsing/tsharkRunner';
import { ConfigLoader } from './configLoader';

/**
 * Assembles the context (prompt) to send to the LLM.
 * Manages the token budget, prioritizes anomalous streams,
 * and structures the prompt for maximum diagnostic value.
 */
export class ContextAssembler {
    private outputChannel: vscode.OutputChannel;

    // Approximate chars per token (conservative estimate)
    private static readonly CHARS_PER_TOKEN = 4;

    constructor(
        private tsharkRunner: TsharkRunner,
        private configLoader: ConfigLoader,
        outputChannel: vscode.OutputChannel
    ) {
        this.outputChannel = outputChannel;
    }

    /**
     * Build the full context for an LLM request.
     */
    async assembleContext(
        captures: CaptureFile[],
        streams: TcpStream[],
        agent: AgentDefinition,
        userQuery: string,
        model?: vscode.LanguageModelChat
    ): Promise<AssembledContext> {
        // Use the actual model's context window if available, otherwise fall back to config
        const modelMax = model?.maxInputTokens;
        const budget = this.getTokenBudget();
        const maxTokens = modelMax || budget.maxInputTokens || 900000;
        const reserveForResponse = Math.min(budget.reserveForResponse || 100000, Math.floor(maxTokens * 0.1));
        const availableTokens = maxTokens - reserveForResponse;

        this.outputChannel.appendLine(`[ContextAssembler] Model context window: ${modelMax ? modelMax + ' tokens (from model)' : 'using config default'}, available: ${availableTokens}`);

        // 1. System prompt (always included)
        const systemPrompt = this.buildSystemPrompt(agent);
        let usedTokens = this.estimateTokens(systemPrompt);

        // 2. Scenario context (always included)
        const scenarioContext = this.buildScenarioContext();
        usedTokens += this.estimateTokens(scenarioContext);

        // 3 & 4. Capture summary + knowledge context — run in parallel (both make tshark calls
        //          but are completely independent of each other, so no reason to serialize)
        this.outputChannel.appendLine(`[ContextAssembler] Building capture summary and knowledge context in parallel...`);
        const [captureSummary, knowledgeResult] = await Promise.all([
            this.buildCaptureSummary(captures),
            this.buildKnowledgeContext(captures, streams, agent),
        ]);
        const knowledgeContext = knowledgeResult.content;
        const knowledgeManifest = knowledgeResult.manifest;
        usedTokens += this.estimateTokens(captureSummary) + this.estimateTokens(knowledgeContext);

        // 5. Stream details — conversation index with anomaly scores
        //    This is a compact list, not full packet data. Cap at 50K tokens.
        const streamBudget = Math.min(availableTokens - usedTokens - 50000, 50000);
        const streamDetails = await this.buildStreamDetails(captures, streams, agent, streamBudget);
        usedTokens += this.estimateTokens(streamDetails);

        // 6. Packet data — includes ALL packets if they fit, otherwise samples
        //    This gets the remaining budget (the largest allocation)
        //    If the agent defines autoFilters.displayFilter, pre-filter packets to relevant traffic
        const packetBudget = availableTokens - usedTokens - this.estimateTokens(userQuery) - 5000; // 5K buffer
        const agentDisplayFilter = agent.autoFilters?.displayFilter;
        const packetResult = await this.buildPacketDataWithCoverage(captures, packetBudget, streams, agentDisplayFilter);
        usedTokens += this.estimateTokens(packetResult.data);

        // 7. User query tokens
        usedTokens += this.estimateTokens(userQuery);

        this.outputChannel.appendLine(`[ContextAssembler] Context assembled: ~${usedTokens} tokens used of ${availableTokens} available`);
        this.outputChannel.appendLine(`[ContextAssembler] Packet data: ${packetResult.data.length} chars (~${this.estimateTokens(packetResult.data)} tokens)`);
        this.outputChannel.appendLine(`[ContextAssembler] Coverage: ${packetResult.coverage.mode} — ${packetResult.coverage.packetsIncluded}/${packetResult.coverage.totalPackets} packets`);
        if (knowledgeContext) {
            this.outputChannel.appendLine(`[ContextAssembler] Knowledge context: ${knowledgeContext.length} chars (~${this.estimateTokens(knowledgeContext)} tokens)`);
        }

        return {
            systemPrompt,
            captureSummary,
            streamDetails,
            scenarioContext,
            packetData: packetResult.data,
            knowledgeContext,
            knowledgeManifest,
            estimatedTokens: usedTokens,
            coverage: packetResult.coverage,
        };
    }

    /**
     * Assemble context for a specific stream deep-dive.
     */
    async assembleStreamContext(
        captureFile: string,
        streamIndex: number,
        agent: AgentDefinition
    ): Promise<string> {
        const detail = await this.tsharkRunner.getStreamDetail(captureFile, streamIndex);
        const followed = await this.tsharkRunner.followStream(captureFile, streamIndex);

        return `## Detailed Analysis: TCP Stream ${streamIndex}

### Packet-Level Detail
\`\`\`
${detail}
\`\`\`

### Reconstructed Application Data (Follow Stream)
\`\`\`
${followed}
\`\`\`
`;
    }

    // ─── Public accessors for lightweight follow-up context ───────────────

    /** Build the system prompt (public for follow-up turns). */
    buildSystemPromptPublic(agent: AgentDefinition): string {
        return this.buildSystemPrompt(agent);
    }

    /** Build the capture summary with expert info (public for follow-up turns). */
    async buildCaptureSummaryPublic(captures: CaptureFile[]): Promise<string> {
        return this.buildCaptureSummary(captures);
    }

    /** Build the scenario context (public for follow-up turns). */
    buildScenarioContextPublic(): string {
        return this.buildScenarioContext();
    }

    /** Build the knowledge context (public for follow-up turns). */
    async buildKnowledgeContextPublic(captures: CaptureFile[], streams: TcpStream[], agent: AgentDefinition): Promise<string> {
        const result = await this.buildKnowledgeContext(captures, streams, agent);
        return result.content;
    }

    // ─── Prompt Builders ──────────────────────────────────────────────────

    /**
     * Build packet data with coverage tracking.
     */
    private async buildPacketDataWithCoverage(
        captures: CaptureFile[],
        tokenBudget: number,
        streams: TcpStream[] = [],
        agentDisplayFilter?: string
    ): Promise<{ data: string; coverage: { mode: 'complete' | 'sampled'; totalPackets: number; packetsIncluded: number; uncoveredRanges?: Array<[number, number]> } }> {
        if (captures.length === 0 || tokenBudget <= 0) {
            return { data: '', coverage: { mode: 'complete', totalPackets: 0, packetsIncluded: 0 } };
        }

        const totalPackets = captures.reduce((sum, c) => sum + (c.summary?.packetCount || 0), 0);

        if (agentDisplayFilter) {
            this.outputChannel.appendLine(`[ContextAssembler] Agent autoFilter active: "${agentDisplayFilter}" — pre-filtering packets`);
        }

        // Try full inclusion first
        const fullPacketData = await this.tryBuildFullPacketData(captures, tokenBudget, agentDisplayFilter);
        if (fullPacketData) {
            return {
                data: fullPacketData,
                coverage: { mode: 'complete', totalPackets, packetsIncluded: totalPackets },
            };
        }

        // Fall back to sampling
        const sampledResult = await this.buildSampledPacketData(captures, tokenBudget, streams, agentDisplayFilter);
        return {
            data: sampledResult.data,
            coverage: {
                mode: 'sampled',
                totalPackets,
                packetsIncluded: sampledResult.packetsIncluded,
                uncoveredRanges: sampledResult.uncoveredRanges,
            },
        };
    }

    /**
     * Build packet data section — smart-sized based on capture size.
     */
    private async buildPacketData(captures: CaptureFile[], tokenBudget: number, streams: TcpStream[] = []): Promise<string> {
        const result = await this.buildPacketDataWithCoverage(captures, tokenBudget, streams);
        return result.data;
    }

    /**
     * Try to include ALL packet list data if it fits within the token budget.
     * Returns the full packet section if it fits, or undefined if too large.
     *
     * We include the compact packet list (frame | time | src | dst | proto | len | info)
     * but NOT expert info or verbose dissections — those are available via tools.
     */
    private async tryBuildFullPacketData(captures: CaptureFile[], tokenBudget: number, agentDisplayFilter?: string): Promise<string | undefined> {
        const totalPackets = captures.reduce((sum, c) => sum + (c.summary?.packetCount || 0), 0);

        // Quick pre-check: if we know the packet count and it's clearly too large, skip the fetch
        // ~110 chars/packet average in compact format (frame|time|src|dst|proto|len|info)
        if (totalPackets > 0) {
            const estimatedTokens = Math.ceil((totalPackets * 110) / ContextAssembler.CHARS_PER_TOKEN);
            if (estimatedTokens > tokenBudget) {
                this.outputChannel.appendLine(
                    `[ContextAssembler] Full packet data estimated at ~${estimatedTokens} tokens ` +
                    `(${totalPackets} packets) — exceeds budget of ${tokenBudget}. Using sampling.`
                );
                return undefined;
            }
        }

        // Fetch all packets and check actual size
        let packetData = '## Packet Data (Complete)\n\n';
        packetData += 'All packets from the capture are included below.\n';
        packetData += 'Format: frame.number | time_relative | source | destination | protocol | frame.len | info\n\n';

        for (const capture of captures) {
            const roleLabel = capture.role ? ` [${capture.role.toUpperCase()} SIDE]` : '';
            packetData += `### ${capture.name}${roleLabel}\n`;

            try {
                const rawPackets = await this.tsharkRunner.getPacketsCompact(capture.filePath, agentDisplayFilter || '');

                if (!rawPackets || !rawPackets.trim()) {
                    packetData += '*No packet data could be read from this capture.*\n\n';
                    continue;
                }

                // Check if actual data fits within budget
                const actualTokens = this.estimateTokens(rawPackets);
                if (this.estimateTokens(packetData) + actualTokens > tokenBudget) {
                    this.outputChannel.appendLine(
                        `[ContextAssembler] Actual packet data for ${capture.name} is ~${actualTokens} tokens ` +
                        `— exceeds budget of ${tokenBudget}. Falling back to sampling.`
                    );
                    return undefined;
                }

                packetData += '```\n' + rawPackets + '\n```\n\n';

                const lineCount = rawPackets.split('\n').filter(l => l.trim()).length;
                this.outputChannel.appendLine(
                    `[ContextAssembler] Included ALL ${lineCount} packets from ${capture.name} ` +
                    `(~${actualTokens} tokens — fits within budget of ${tokenBudget})`
                );

            } catch (e) {
                packetData += `*Error reading packets: ${e}*\n\n`;
            }
        }

        packetData += '*All packets shown. Use tools for deeper inspection (stream detail, follow stream, expert info).*\n\n';
        return packetData;
    }

    /**
     * Build sampled packet data for large captures that don't fit in the budget.
     * Returns the packet data string plus coverage tracking info.
     */
    private async buildSampledPacketData(captures: CaptureFile[], tokenBudget: number, streams: TcpStream[], agentDisplayFilter?: string): Promise<{ data: string; packetsIncluded: number; uncoveredRanges: Array<[number, number]> }> {
        const totalAllPackets = captures.reduce((sum, c) => sum + (c.summary?.packetCount || 0), 0);

        let packetData = '## Sampled Packet Data\n\n';
        if (agentDisplayFilter) {
            packetData += `**Agent filter active:** \`${agentDisplayFilter}\` — showing only matching traffic.\n`;
        }
        packetData += `This capture has ${totalAllPackets.toLocaleString()} packets — too large to include all at once.\n`;
        packetData += 'The sample below covers key sections. **Uncovered frame ranges are listed below — you MUST use nettrace-getPacketRange to review them.**\n';
        packetData += 'Format: frame.number | time_relative | source | destination | protocol | frame.len | info\n\n';

        const budgetPerCapture = Math.floor(tokenBudget / Math.max(captures.length, 1));
        const scenarioFilter = this.buildScenarioContextFilter();
        let totalIncluded = 0;
        const allUncoveredRanges: Array<[number, number]> = [];

        for (const capture of captures) {
            const roleLabel = capture.role ? ` [${capture.role.toUpperCase()} SIDE]` : '';
            packetData += `### ${capture.name}${roleLabel}\n`;
            let captureBudgetUsed = 0;
            const coveredRanges: Array<[number, number]> = []; // Track which frame ranges we've included

            try {
                const totalPackets = capture.summary?.packetCount || 0;

                // --- Section A: First 200 packets (connection establishment, early traffic) ---
                const firstN = Math.min(200, totalPackets);
                const firstPackets = await this.tsharkRunner.getPacketRange(capture.filePath, 1, firstN, agentDisplayFilter);
                if (firstPackets && firstPackets.trim()) {
                    packetData += `\n#### First ${firstN} packets (of ${totalPackets} total)\n`;
                    packetData += '```\n' + firstPackets + '\n```\n\n';
                    captureBudgetUsed += this.estimateTokens(firstPackets);
                    coveredRanges.push([1, firstN]);
                }

                // --- Section B: Last 100 packets (how it ends) ---
                if (totalPackets > firstN + 100) {
                    const lastStart = Math.max(totalPackets - 99, firstN + 1);
                    const lastPackets = await this.tsharkRunner.getPacketRange(capture.filePath, lastStart, totalPackets, agentDisplayFilter);
                    if (lastPackets && lastPackets.trim()) {
                        packetData += `#### Last 100 packets\n`;
                        packetData += '```\n' + lastPackets + '\n```\n\n';
                        captureBudgetUsed += this.estimateTokens(lastPackets);
                        coveredRanges.push([lastStart, totalPackets]);
                    }
                }

                // --- Section C: Scenario-context-filtered sample ---
                if (scenarioFilter && captureBudgetUsed < budgetPerCapture * 0.6) {
                    try {
                        const maxScenarioPackets = Math.min(500, Math.floor((budgetPerCapture * 0.2) / 30));
                        const filteredSample = await this.tsharkRunner.applyFilter(
                            capture.filePath, scenarioFilter, maxScenarioPackets
                        );
                        if (filteredSample && filteredSample.trim()) {
                            const lineCount = filteredSample.trim().split('\n').filter(l => l.trim()).length;
                            packetData += `#### Scenario-relevant packets (filter: \`${scenarioFilter}\`) — ${lineCount} shown\n`;
                            packetData += '```\n' + filteredSample + '\n```\n\n';
                            captureBudgetUsed += this.estimateTokens(filteredSample);
                            // Scenario-filtered packets are scattered — don't add to covered ranges
                        }
                    } catch (e) {
                        this.outputChannel.appendLine(`[ContextAssembler] Scenario filter error: ${e}`);
                    }
                }

                // --- Section D: All anomalous streams — include as many as budget allows ---
                const captureStreams = streams
                    .filter(s => s.captureFile === capture.filePath && s.anomalyScore > 0)
                    .sort((a, b) => b.anomalyScore - a.anomalyScore);

                if (captureStreams.length > 0 && captureBudgetUsed < budgetPerCapture * 0.8) {
                    packetData += `#### Packets from ${captureStreams.length} anomalous stream(s) (sorted by severity)\n\n`;

                    for (const stream of captureStreams) {
                        if (captureBudgetUsed >= budgetPerCapture * 0.9) { break; }

                        try {
                            const streamSample = await this.tsharkRunner.applyFilter(
                                capture.filePath,
                                `tcp.stream eq ${stream.index}`,
                                100
                            );
                            if (streamSample && streamSample.trim()) {
                                const sampleTokens = this.estimateTokens(streamSample);
                                if (captureBudgetUsed + sampleTokens > budgetPerCapture * 0.95) { break; }

                                const anomalyList = stream.anomalies.map(a => a.type).join(', ');
                                packetData += `**Stream ${stream.index}** (score: ${stream.anomalyScore}, anomalies: ${anomalyList}) — ` +
                                    `${stream.source} ↔ ${stream.destination} | ${stream.packetCount} pkts\n`;
                                packetData += '```\n' + streamSample + '\n```\n\n';
                                captureBudgetUsed += sampleTokens;
                            }
                        } catch (e) {
                            this.outputChannel.appendLine(`[ContextAssembler] Error sampling stream ${stream.index}: ${e}`);
                        }
                    }
                }

                // --- Section E: Fill remaining budget with evenly-spaced middle samples ---
                // After A/B/C/D, there is often significant token budget left unused (especially on
                // small-context models where sections C/D may not fire). Rather than leaving the
                // budget empty, sample the middle of the capture in evenly-spaced windows so the
                // LLM has representative mid-session traffic for its initial analysis. Uncovered
                // gaps are still listed below so the LLM can use tools to drill in further.
                const TOKENS_PER_PACKET_EST = 30; // ~110 chars/packet ÷ 4 chars/token, conservatively rounded
                const MAX_FILL_BATCHES = 6;        // Hard cap — each batch = 1 extra tshark call on the file
                const FILL_BATCH_SIZE = 500;       // Packets per middle-fill batch
                const lastStartForMiddle = Math.max(totalPackets - 99, firstN + 1);
                const middleRegionStart = firstN + 1;
                const middleRegionEnd = lastStartForMiddle - 1;
                const remainingBudgetForFill = budgetPerCapture - captureBudgetUsed;

                if (remainingBudgetForFill > 10000 && middleRegionEnd > middleRegionStart + FILL_BATCH_SIZE) {
                    const packetsCanFit = Math.floor((remainingBudgetForFill * 0.85) / TOKENS_PER_PACKET_EST);
                    const numFillBatches = Math.min(
                        Math.max(1, Math.floor(packetsCanFit / FILL_BATCH_SIZE)),
                        MAX_FILL_BATCHES
                    );
                    const middleSize = middleRegionEnd - middleRegionStart;
                    const fillStep = Math.floor(middleSize / (numFillBatches + 1));

                    this.outputChannel.appendLine(
                        `[ContextAssembler] Section E: ${remainingBudgetForFill} tokens remaining, ` +
                        `can fit ~${packetsCanFit} packets → ${numFillBatches} evenly-spaced batch(es) of ${FILL_BATCH_SIZE} through frames ${middleRegionStart}–${middleRegionEnd}`
                    );

                    packetData += `\n#### Representative mid-capture samples (${numFillBatches} batch${numFillBatches > 1 ? 'es' : ''} of up to ${FILL_BATCH_SIZE} packets, evenly spaced)\n\n`;

                    for (let i = 1; i <= numFillBatches && captureBudgetUsed < budgetPerCapture * 0.92; i++) {
                        const batchStart = middleRegionStart + (i * fillStep);
                        const batchEnd = Math.min(batchStart + FILL_BATCH_SIZE - 1, middleRegionEnd);
                        if (batchStart > middleRegionEnd) { break; }

                        try {
                            const batchPackets = await this.tsharkRunner.getPacketRange(
                                capture.filePath, batchStart, batchEnd, agentDisplayFilter
                            );
                            if (batchPackets && batchPackets.trim()) {
                                const batchTokens = this.estimateTokens(batchPackets);
                                if (captureBudgetUsed + batchTokens > budgetPerCapture * 0.95) { break; }

                                const pct = Math.round((batchStart / totalPackets) * 100);
                                packetData += `##### Frames ${batchStart.toLocaleString()}\u2013${batchEnd.toLocaleString()} (~${pct}% through capture)\n`;
                                packetData += '```\n' + batchPackets + '\n```\n\n';
                                captureBudgetUsed += batchTokens;
                                coveredRanges.push([batchStart, batchEnd]);
                            }
                        } catch (e) {
                            this.outputChannel.appendLine(`[ContextAssembler] Section E batch ${i} error: ${e}`);
                        }
                    }
                } else {
                    this.outputChannel.appendLine(
                        `[ContextAssembler] Section E skipped: remainingBudget=${remainingBudgetForFill}, middleSize=${middleRegionEnd - middleRegionStart}`
                    );
                }

                // --- Gap map: tell the model exactly which frame ranges it hasn't seen ---
                const uncoveredRanges = this.computeUncoveredRanges(coveredRanges, totalPackets);
                if (uncoveredRanges.length > 0) {
                    packetData += `\n#### ⚠️ Uncovered frame ranges — use nettrace-getPacketRange to review these\n`;
                    packetData += 'These sections have NOT been examined yet. Page through them with getPacketRange (max 500 per call):\n\n';
                    for (const [start, end] of uncoveredRanges) {
                        const count = end - start + 1;
                        packetData += `- Frames **${start}–${end}** (${count.toLocaleString()} packets)\n`;
                    }
                    packetData += '\n';
                }

                this.outputChannel.appendLine(
                    `[ContextAssembler] Sampled packets from ${capture.name}: ` +
                    `~${captureBudgetUsed} tokens used of ${budgetPerCapture} budget ` +
                    `(${totalPackets} total packets, ${uncoveredRanges.length} uncovered ranges)`
                );

                allUncoveredRanges.push(...uncoveredRanges);
                // Estimate included packets from covered ranges
                for (const [s, e] of coveredRanges) {
                    totalIncluded += (e - s + 1);
                }

            } catch (e) {
                packetData += `*Error reading packets: ${e}*\n\n`;
                this.outputChannel.appendLine(`[ContextAssembler] Error reading packets from ${capture.name}: ${e}`);
            }
        }

        return { data: packetData, packetsIncluded: totalIncluded, uncoveredRanges: allUncoveredRanges };
    }

    /**
     * Compute which frame ranges are NOT covered by the sampled data.
     */
    private computeUncoveredRanges(coveredRanges: Array<[number, number]>, totalPackets: number): Array<[number, number]> {
        if (totalPackets === 0) { return []; }

        // Sort covered ranges by start
        const sorted = [...coveredRanges].sort((a, b) => a[0] - b[0]);

        const uncovered: Array<[number, number]> = [];
        let nextExpected = 1;

        for (const [start, end] of sorted) {
            if (start > nextExpected) {
                uncovered.push([nextExpected, start - 1]);
            }
            nextExpected = Math.max(nextExpected, end + 1);
        }

        // Gap after the last covered range
        if (nextExpected <= totalPackets) {
            uncovered.push([nextExpected, totalPackets]);
        }

        return uncovered;
    }

    /**
     * Build a Wireshark display filter from scenario context.
     * If the scenario specifies relevant IPs and/or ports, generate a filter
     * so the initial sample focuses on traffic the user cares about.
     */
    private buildScenarioContextFilter(): string | undefined {
        const scenarioDetails = this.configLoader.getScenarioDetails();
        if (!scenarioDetails) { return undefined; }

        const parts: string[] = [];

        // Filter by relevant IPs
        const ips: string[] = [];
        if (scenarioDetails.topology?.clientIP) { ips.push(scenarioDetails.topology.clientIP); }
        if (scenarioDetails.topology?.serverIP) { ips.push(scenarioDetails.topology.serverIP); }

        if (ips.length > 0) {
            const ipFilters = ips.map(ip => `ip.addr == ${ip}`);
            parts.push(`(${ipFilters.join(' || ')})`);
        }

        // Filter by relevant ports
        if (scenarioDetails.topology?.relevantPorts?.length) {
            const portFilters = scenarioDetails.topology.relevantPorts.map(p => `tcp.port == ${p} || udp.port == ${p}`);
            parts.push(`(${portFilters.join(' || ')})`);
        }

        if (parts.length === 0) { return undefined; }

        // Combine with AND — show traffic that matches IPs AND ports if both specified
        const filter = parts.join(' && ');
        this.outputChannel.appendLine(`[ContextAssembler] Built scenario context filter: ${filter}`);
        return filter;
    }

    private buildSystemPrompt(agent: AgentDefinition): string {
        return `${agent.systemPrompt}

## Data Provided
You have REAL packet data parsed from a capture file via tshark.
Each packet line: frame.number | time_relative | source | destination | protocol | frame.len | info

If you see "## Packet Data (Complete)" — ALL packets are included. Analyze them directly.

If you see "## Sampled Packet Data" — only a portion is included. The header tells you exactly
which frame ranges are covered and which are NOT. You MUST use **nettrace-getPacketRange** to
systematically page through the uncovered ranges. Do not skip sections — issues can be anywhere
in the capture.

### Large Capture Analysis Workflow
1. Analyze the sampled packets and streams provided
2. Check the "Uncovered frame ranges" list in the sample header
3. Use **nettrace-getPacketRange** to fetch each uncovered range (up to 500 frames per call)
4. For each batch, note any anomalies then move to the next range
5. After reviewing all ranges, synthesize your findings

The capture summary includes Wireshark's expert frequency breakdown (retransmissions, RSTs, etc.).
The conversation list shows all TCP streams ranked by anomaly score.

Use real packet numbers, IPs, and timestamps in your analysis. Do NOT guess or hallucinate details.

## Tool Usage — Prefer nettrace-* Tools
**Always prefer the nettrace-* tools for packet analysis.** They are better than raw terminal commands because:
- **nettrace-applyFilter** and **nettrace-setDisplayFilter** automatically update the Capture Viewer panel the user is looking at
- **nettrace-runTshark** runs any tshark command and returns structured output (no need for a terminal)
- Tool results are managed (truncated, budgeted) to stay within the context window
- The capture file path is provided automatically — you don't need to know it

**nettrace-runTshark** is your universal escape hatch — it accepts any tshark CLI arguments, so there
is no tshark operation you cannot perform through tools. Prefer it over raw terminal commands.

Every tshark operation can be done through your tools:
- Filtering → **nettrace-applyFilter** or **nettrace-setDisplayFilter**
- Protocol stats → **nettrace-runTshark** with appropriate args
- Stream reconstruction → **nettrace-followStream**
- Custom analysis → **nettrace-runTshark** (accepts any tshark arguments)

If a tool returns 0 results or an error, that is normal — it means no packets matched that filter
or the filter syntax was incorrect. Try a different filter or broaden the expression.

## Available Tools
| Tool | When to Use |
|------|-------------|
| **nettrace-getStreamDetail** | Deep dive into a specific TCP stream (flags, seq/ack, timing) |
| **nettrace-followStream** | Reconstruct application-layer payload (HTTP, TLS handshake) |
| **nettrace-applyFilter** | Find packets matching a Wireshark display filter — also updates the viewer panel |
| **nettrace-getPacketRange** | Page through a large capture by frame range (up to 500 per call) |
| **nettrace-getConversations** | Conversation list (only if you need UDP or IP level) |
| **nettrace-compareCaptures** | Compare client vs server captures |
| **nettrace-setDisplayFilter** | Push a display filter to the capture viewer panel (changes what the user sees) |
| **nettrace-runTshark** | Run any custom tshark command (field extraction, statistics, protocol decoding) |
| **nettrace-createAgent** | Create a new specialized analysis agent (JSON file in .nettrace/agents/) |
| **nettrace-createKnowledge** | Create a knowledge file to teach the AI about patterns/behaviors |

### Display Filter & Viewer Panel
When the user asks to "filter", "show", or "focus on" specific traffic, you MUST:
1. Use **nettrace-setDisplayFilter** to update the capture viewer panel the user is looking at
2. Optionally use **nettrace-applyFilter** if you also need the filtered data for analysis
   (nettrace-applyFilter updates the viewer panel by default AND returns data to you)

**Always use standard Wireshark display filter syntax.** Common filters:
- Protocol: \`dns\`, \`http\`, \`tls\`, \`tcp\`, \`udp\`, \`icmp\`, \`arp\`
- Port: \`tcp.port == 443\`, \`udp.port == 53\`
- IP address: \`ip.addr == 10.0.0.1\`, \`ip.src == 192.168.1.1\`
- HTTP: \`http.request\`, \`http.response.code == 200\`, \`http.host contains "example"\`
- DNS: \`dns.qry.name contains "google"\`, \`dns.flags.rcode != 0\`
- TLS: \`tls.handshake\`, \`tls.handshake.type == 1\` (Client Hello)
- TCP analysis: \`tcp.analysis.retransmission\`, \`tcp.analysis.zero_window\`, \`tcp.flags.reset == 1\`
- Combine: \`dns || http\`, \`tcp.port == 80 && ip.addr == 10.0.0.1\`
- NOT: \`!(arp || dns)\`, \`!tcp.port == 22\`

### Custom Tshark Commands
Use **nettrace-runTshark** for any analysis not covered by the specific tools above. You can extract
specific protocol fields, run IO statistics, compute RTT, or use any tshark capability. Examples:
- DNS queries: \`-Y dns -T fields -e dns.qry.name -e dns.qry.type -e dns.flags.rcode\`
- TLS versions: \`-Y tls.handshake.type==1 -T fields -e ip.src -e tls.handshake.version\`
- IO stats: \`-q -z io,stat,1\`
- Protocol hierarchy: \`-q -z io,phs\`

### Agent & Knowledge Creation
When a user asks you to create a specialized agent or teach the AI about specific patterns, use
**nettrace-createAgent** or **nettrace-createKnowledge**. Agents change HOW the AI analyzes
(persona, tools, filters). Knowledge changes WHAT the AI knows (facts, rules, patterns).

Each tool response adds to the context — be efficient but thorough.

## Response Guidelines
- Reference specific packet numbers, stream indices, and timestamps from the data
- Flag connection failures, TLS rejections, unexpected RSTs, and protocol errors as issues
- Explain findings in terms a support engineer can act on
- Provide clear remediation steps when you identify a root cause
- When you apply a filter for the user, confirm what filter was applied and that their viewer is updated
`;
    }

    private buildScenarioContext(): string {
        const scenarioDetails = this.configLoader.getScenarioDetails();
        if (!scenarioDetails || (!scenarioDetails.summary && !scenarioDetails.symptom)) {
            return '';
        }

        let context = '## Scenario Context\n';
        if (scenarioDetails.scenarioId) { context += `**Scenario ID:** ${scenarioDetails.scenarioId}\n`; }
        if (scenarioDetails.summary) { context += `**Summary:** ${scenarioDetails.summary}\n`; }
        if (scenarioDetails.symptom) { context += `**Reported Symptom:** ${scenarioDetails.symptom}\n`; }
        if (scenarioDetails.topology) {
            if (scenarioDetails.topology.description) {
                context += `**Network Topology:** ${scenarioDetails.topology.description}\n`;
            }
            if (scenarioDetails.topology.clientIP) {
                context += `**Client IP:** ${scenarioDetails.topology.clientIP}\n`;
            }
            if (scenarioDetails.topology.serverIP) {
                context += `**Server IP:** ${scenarioDetails.topology.serverIP}\n`;
            }
            if (scenarioDetails.topology.relevantPorts?.length) {
                context += `**Relevant Ports:** ${scenarioDetails.topology.relevantPorts.join(', ')}\n`;
            }
        }
        if (scenarioDetails.notes) { context += `**Notes:** ${scenarioDetails.notes}\n`; }
        context += '\n';

        return context;
    }

    private async buildCaptureSummary(captures: CaptureFile[]): Promise<string> {
        if (captures.length === 0) { return '## Capture Summary\nNo captures loaded.\n\n'; }

        let summary = '## Capture Summary\n\n';

        for (const capture of captures) {
            const roleLabel = capture.role ? ` [${capture.role.toUpperCase()} SIDE]` : '';
            summary += `### ${capture.name}${roleLabel}\n`;

            if (capture.summary) {
                const s = capture.summary;
                summary += `- **Packets:** ${s.packetCount}\n`;
                summary += `- **Duration:** ${s.durationSeconds.toFixed(2)}s\n`;
                summary += `- **TCP Streams:** ${s.tcpStreamCount}\n`;

                // Protocol breakdown (top 10)
                const protocols = Object.entries(s.protocolBreakdown)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 10);
                if (protocols.length > 0) {
                    summary += `- **Protocols:** ${protocols.map(([p, c]) => `${p}(${c})`).join(', ')}\n`;
                }

                // Expert info — include the full frequency summary (compact, ~30 lines)
                try {
                    const expertInfo = await this.tsharkRunner.getExpertInfo(capture.filePath);
                    if (expertInfo && expertInfo.trim()) {
                        summary += `\n#### Expert Analysis Summary (Wireshark)\n`;
                        summary += '```\n' + expertInfo.trim() + '\n```\n';

                        // When expert info reports ERRORS (not just warnings), auto-fetch
                        // verbose protocol dissection for those frames. This surfaces critical
                        // details like fragment overlap, conflicting data, and protocol violations
                        // that the compact packet list doesn't show.
                        if (s.expertInfo && s.expertInfo.errors > 0) {
                            const errorDetails = await this.getErrorFrameDetails(capture);
                            if (errorDetails) {
                                summary += errorDetails;
                            }
                        }
                    }
                } catch (e) {
                    // Fall back to counts if expert info fails
                    if (s.expertInfo) {
                        const ei = s.expertInfo;
                        if (ei.errors > 0 || ei.warnings > 0) {
                            summary += `- **Expert Info:** ${ei.errors} errors, ${ei.warnings} warnings, ${ei.notes} notes\n`;
                        }
                    }
                    this.outputChannel.appendLine(`[ContextAssembler] Expert info error: ${e}`);
                }
            } else {
                summary += '- *(not yet parsed)*\n';
            }
            summary += '\n';
        }

        return summary;
    }

    /**
     * When expert info reports errors, fetch verbose protocol dissection (-V) for
     * the specific error frames. This surfaces details like:
     * - Fragment overlap / conflicting data (teardrop attacks)
     * - Protocol field violations (malformed packets)
     * - Reassembly failures
     *
     * These details are invisible in the compact packet list but critical for
     * correct diagnosis. Only fetches up to 10 error frames to stay compact.
     */
    private async getErrorFrameDetails(capture: CaptureFile): Promise<string | undefined> {
        try {
            // Find frame numbers that have expert errors
            // Use expert.severity == error to find them
            const errorFramesOutput = await this.tsharkRunner.runCustomCommand(
                capture.filePath,
                ['-T', 'fields', '-e', 'frame.number', '-Y', '_ws.expert.severity == "Error"', '-c', '10']
            );

            let frameNumbers: number[] = [];
            if (errorFramesOutput && errorFramesOutput.trim()) {
                frameNumbers = errorFramesOutput.trim().split('\n')
                    .map(s => parseInt(s.trim()))
                    .filter(n => !isNaN(n));
            }

            // If the expert severity filter didn't work (some capture formats),
            // try to find frames mentioned in the expert info text
            if (frameNumbers.length === 0) {
                // Fallback: get verbose output for the first few frames that look unusual
                // by checking for common error indicators in the info column
                const badFrames = await this.tsharkRunner.runCustomCommand(
                    capture.filePath,
                    ['-T', 'fields', '-e', 'frame.number',
                     '-Y', '_ws.col.Info contains "BAD" || _ws.col.Info contains "Malformed" || _ws.col.Info contains "overlap"',
                     '-c', '10']
                );
                if (badFrames && badFrames.trim()) {
                    frameNumbers = badFrames.trim().split('\n')
                        .map(s => parseInt(s.trim()))
                        .filter(n => !isNaN(n));
                }
            }

            if (frameNumbers.length === 0) {
                this.outputChannel.appendLine('[ContextAssembler] No error frames found for verbose detail');
                return undefined;
            }

            this.outputChannel.appendLine(`[ContextAssembler] Fetching verbose detail for ${frameNumbers.length} error frame(s): ${frameNumbers.join(', ')}`);

            // Also include the frame immediately before each error frame for context
            const framesToFetch = new Set<number>();
            for (const f of frameNumbers) {
                if (f > 1) { framesToFetch.add(f - 1); }
                framesToFetch.add(f);
            }

            let details = '\n#### Detailed Protocol Dissection (Error Frames)\n';
            details += 'Verbose Wireshark dissection for frames with expert errors. Look for fragment overlap, conflicting data, protocol violations.\n\n';

            for (const frameNum of Array.from(framesToFetch).sort((a, b) => a - b)) {
                try {
                    const verbose = await this.tsharkRunner.getPacketDetail(capture.filePath, frameNum);
                    if (verbose && verbose.trim()) {
                        // Cap each frame's verbose output at 5K chars
                        const capped = verbose.length > 5000
                            ? verbose.substring(0, 5000) + '\n... (truncated)'
                            : verbose;
                        details += `**Frame ${frameNum}:**\n\`\`\`\n${capped.trim()}\n\`\`\`\n\n`;
                    }
                } catch (e) {
                    this.outputChannel.appendLine(`[ContextAssembler] Error getting detail for frame ${frameNum}: ${e}`);
                }
            }

            return details;
        } catch (e) {
            this.outputChannel.appendLine(`[ContextAssembler] Error fetching error frame details: ${e}`);
            return undefined;
        }
    }

    private async buildStreamDetails(
        captures: CaptureFile[],
        streams: TcpStream[],
        agent: AgentDefinition,
        tokenBudget: number
    ): Promise<string> {
        if (streams.length === 0) { return ''; }

        const prioritySignals = agent.contextPriority?.prioritySignals || [];
        const alwaysInclude = agent.contextPriority?.alwaysInclude || [];

        // Sort by anomaly score (highest first), but boost streams matching agent priority signals
        const sorted = [...streams]
            .filter(s => !s.excluded)
            .map(s => {
                let boost = 0;
                // Boost streams whose anomaly types match the agent's priority signals
                if (prioritySignals.length > 0) {
                    for (const anomaly of s.anomalies) {
                        if (prioritySignals.includes(anomaly.type)) {
                            boost += 10;
                        }
                    }
                }
                // Boost streams whose appProtocol matches alwaysInclude
                if (alwaysInclude.length > 0 && s.appProtocol) {
                    if (alwaysInclude.some(p => s.appProtocol!.toLowerCase().includes(p.toLowerCase()))) {
                        boost += 20; // Always-include gets highest priority
                    }
                }
                return { stream: s, effectiveScore: s.anomalyScore + boost };
            })
            .sort((a, b) => b.effectiveScore - a.effectiveScore)
            .map(s => s.stream);

        const maxStreams = agent.contextPriority?.maxStreamsToAnalyze || 20;
        const perStreamBudget = this.getTokenBudget().perStreamBudget || 50000;

        let details = '## Stream Analysis\n\n';
        let usedTokens = this.estimateTokens(details);
        let processedCount = 0;

        // Anomalous streams get full detail
        for (const stream of sorted) {
            if (processedCount >= maxStreams) { break; }
            if (usedTokens >= tokenBudget) { break; }

            const hasAnomalies = stream.anomalyScore > 0;

            if (hasAnomalies) {
                // Full detail for anomalous streams
                details += `### Stream ${stream.index} (Anomaly Score: ${stream.anomalyScore}) ⚠️\n`;
                details += `**${stream.source} ↔ ${stream.destination}**\n`;
                details += `Packets: ${stream.packetCount} | Bytes: ${stream.totalBytes} | Duration: ${stream.durationSeconds.toFixed(2)}s\n`;

                if (stream.anomalies.length > 0) {
                    details += 'Anomalies:\n';
                    for (const anomaly of stream.anomalies) {
                        details += `  - ${anomaly.description}\n`;
                    }
                }
                details += '\n';
            } else {
                // Summary only for clean streams
                details += `### Stream ${stream.index} ✓\n`;
                details += `${stream.source} ↔ ${stream.destination} | ${stream.packetCount} pkts | ${stream.totalBytes} bytes | ${stream.durationSeconds.toFixed(2)}s\n\n`;
            }

            usedTokens = this.estimateTokens(details);
            processedCount++;
        }

        if (processedCount < sorted.length) {
            details += `\n*${sorted.length - processedCount} additional streams not shown (within token budget). Use the stream detail tool to inspect specific streams.*\n`;
        }

        return details;
    }

    // ─── Knowledge Base & Conditional Advisors ────────────────────────────

    /**
     * Build the knowledge context section.
     * - Analysis wisdom and known-issues are ALWAYS included (lightweight, prevents false positives)
     * - Security heuristics are ONLY included when capture signals indicate something suspicious
     * - The agent can opt out of specific advisors via excludeAdvisors
     */
    private async buildKnowledgeContext(
        captures: CaptureFile[],
        streams: TcpStream[],
        agent: AgentDefinition
    ): Promise<{ content: string; manifest: { wisdomFiles: string[]; securityFiles: string[]; securityTriggered: boolean } }> {
        const excludedAdvisors = agent.excludeAdvisors || [];
        let content = '';
        const wisdomFiles: string[] = [];
        const securityFiles: string[] = [];
        let securityTriggered = false;

        // User-provided knowledge files only — no built-in wisdom injection.
        // The model is an expert network analyst. Injecting "don't flag X as a problem"
        // guidance causes it to dismiss real issues (e.g., TLS rejections, RSTs that matter).
        // Users can add their own .md files in .nettrace/knowledge/ to adjust behavior
        // for specific scenarios they encounter.
        if (!excludedAdvisors.includes('wisdom')) {
            const wisdomEntries = this.configLoader.getAlwaysOnKnowledge();
            if (wisdomEntries.length > 0) {
                content += '## Additional Analysis Knowledge\n';
                content += 'The following guidance was provided for this workspace. Apply it where relevant.\n\n';
                for (const entry of wisdomEntries) {
                    content += entry.content + '\n\n';
                    wisdomFiles.push(path.basename(entry.source));
                }
            }
            // No built-in wisdom fallback — let the model use its own expertise
        }

        // Conditional: security heuristics — only when the capture has suspicious signals.
        // These are ESCALATION rules (malformed = critical, fragments = suspicious).
        // They tell the model to take things MORE seriously, never to dismiss findings.
        if (!excludedAdvisors.includes('security')) {
            // User-provided security files are ALWAYS injected — the user explicitly placed
            // them in .nettrace/knowledge/ meaning "use these for this workspace".
            // No signal scan needed; skip it to avoid unnecessary tshark queries.
            const securityEntries = this.configLoader.getSecurityKnowledge();
            if (securityEntries.length > 0) {
                securityTriggered = true;
                content += '## Security Analysis Knowledge\n';
                content += 'The following security guidance was provided for this workspace. Apply it where relevant.\n\n';
                for (const entry of securityEntries) {
                    content += entry.content + '\n\n';
                    securityFiles.push(path.basename(entry.source));
                }
                this.outputChannel.appendLine(
                    `[ContextAssembler] User security knowledge injected: ${securityFiles.join(', ')}`
                );
            } else {
                // No user security files — fall back to built-in heuristics only when
                // the capture contains actual suspicious signals (avoids noise on clean traces).
                const signals = await this.detectCaptureSignals(captures);

                if (signals.securityAnomalyCount > 0) {
                    securityTriggered = true;
                    this.outputChannel.appendLine(
                        `[ContextAssembler] Security signals detected (${signals.securityAnomalyCount} triggers: ${Array.from(signals.anomalyTypes).join(', ')}). Injecting built-in security heuristics.`
                    );
                    content += this.getBuiltInSecurityHeuristics(signals);
                    securityFiles.push('built-in security heuristics');
                } else {
                    this.outputChannel.appendLine('[ContextAssembler] No user security files and no signals detected — skipping security heuristics.');
                }
            }
        }

        return { content, manifest: { wisdomFiles, securityFiles, securityTriggered } };
    }

    /**
     * Scan all captures for security-relevant signals.
     * Returns a merged CaptureSignals object.
     */
    private async detectCaptureSignals(captures: CaptureFile[]): Promise<CaptureSignals> {
        const merged: CaptureSignals = {
            hasMalformedPackets: false,
            hasFragments: false,
            hasChecksumErrors: false,
            hasSuspiciousFlags: false,
            hasIcmpErrors: false,
            hasTlsAlerts: false,
            securityAnomalyCount: 0,
            anomalyTypes: new Set(),
        };

        for (const capture of captures) {
            try {
                const signals = await this.tsharkRunner.getCaptureSignals(capture.filePath);
                if (signals.hasMalformedPackets) { merged.hasMalformedPackets = true; }
                if (signals.hasFragments) { merged.hasFragments = true; }
                if (signals.hasChecksumErrors) { merged.hasChecksumErrors = true; }
                if (signals.hasSuspiciousFlags) { merged.hasSuspiciousFlags = true; }
                if (signals.hasIcmpErrors) { merged.hasIcmpErrors = true; }
                if (signals.hasTlsAlerts) { merged.hasTlsAlerts = true; }
                merged.securityAnomalyCount += signals.securityAnomalyCount;
                for (const t of signals.anomalyTypes) { merged.anomalyTypes.add(t); }
            } catch (e) {
                this.outputChannel.appendLine(`[ContextAssembler] Failed to scan signals for ${capture.name}: ${e}`);
            }
        }

        return merged;
    }

    /**
     * Built-in analysis wisdom — always injected.
     * Covers common false positives, known quirks, and expert-level knowledge
     * that prevents the agent from misinterpreting normal network behavior.
     */
    private getBuiltInWisdom(): string {
        return `## Expert Analysis Knowledge

### Common False Positives — Do NOT Flag These as Problems
1. **RST after FIN/FIN-ACK is NORMAL.** A TCP RST sent after a proper FIN handshake is a common optimization — the sender is cleaning up the connection. This is NOT a connection error.
2. **Wireshark mislabels retransmissions in NIC teaming / NAT environments.** When traffic passes through NIC teaming (LBFO, bonding) or NAT gateways, Wireshark sees duplicate packets and flags them as "retransmissions." Check whether packets have the SAME content but DIFFERENT MACs or slightly different timing — if so, it's a capture artifact, not real retransmissions.
3. **Container/AKS environments multiply packets.** In Kubernetes (AKS, EKS, GKE), a single packet can appear 2-3x in a capture because it traverses pod veth → bridge → host NIC. If you see exact duplicate packets with sub-millisecond timing, consider the capture point before flagging retransmissions.
4. **Duplicate ACKs ≤ 3 are normal.** TCP uses duplicate ACKs as a signaling mechanism (fast retransmit triggers at 3). A small number of dup ACKs is expected behavior, not a problem.
5. **RST to closed port is expected.** When a client connects to a port that's not listening, the server sends RST. This is normal TCP behavior, not an attack.
6. **TCP window size variations are not errors.** Window scaling and window size changes are normal flow control. Only flag zero-window events as potential issues.

### Environment-Specific Awareness
- **Multiple DHCP servers** on a segment can be intentional (redundancy) or problematic (rogue DHCP). Check whether the offered configurations conflict before flagging as an issue.
- **Gratuitous ARP** is normal for failover clusters, VRRP/HSRP, and IP moves. Only flag if the MAC-to-IP mapping contradicts expected topology.
- **TCP keepalives** (small packets at regular intervals on idle connections) are normal. Don't flag as anomalies.
- **TTL variations** between packets to the same destination can indicate load balancers or anycast, not always routing issues.
- **Out-of-order packets** in small quantities (< 1% of stream) are normal on multi-path networks (ECMP, SD-WAN). Only flag when paired with retransmissions.

### Firewall and Middlebox Behaviors That Look Wrong But May Be Expected
- Firewalls may inject RST packets to both sides when blocking — this looks like the endpoint reset the connection but was actually the firewall.
- Some firewalls/proxies modify TCP window size, MSS, or remove TCP options. If you see MSS clamping, check whether a firewall or VPN is in the path.
- Stateful firewalls may drop packets for "established" connections after a timeout, causing the next packet to be silently dropped or RST'd. Look for connection idle time before the failure.
- Deep packet inspection (DPI) can introduce latency visible as inter-packet gaps that look like server processing delay.

### When to Be Concerned vs. When to Note It
- **Concern:** Hundreds of retransmissions in a short stream, zero-window persisting for seconds, RST without prior communication, patterns that worsen over time
- **Note but don't alarm:** Occasional retransmissions (< 1%), single RST after completed exchange, minor out-of-order on WAN links, standard TCP keepalives

`;
    }

    /**
     * Built-in security heuristics — only injected when capture signals indicate
     * malformed packets, fragments, suspicious flags, or other security-relevant anomalies.
     */
    private getBuiltInSecurityHeuristics(signals: CaptureSignals): string {
        let heuristics = '## Security Analysis (Activated by Capture Signals)\n\n';
        heuristics += `**Trigger:** This capture contains ${Array.from(signals.anomalyTypes).join(', ')} anomalies that warrant security-focused analysis.\n\n`;

        heuristics += `### Principle 1: Protocol Violations Are Assumed Hostile
Any packet where a protocol field contradicts another field is a CRITICAL finding.
- Length mismatches (stated vs actual payload size)
- Impossible flag combinations (e.g., SYN+FIN, SYN+RST)
- Header values that would cause overflow (offset * size > maximum)
- Checksums that don't match
**WHY:** Legitimate software does not produce malformed packets. Malformed = intentional or hardware failure.

### Principle 2: Fragmentation Is Suspicious by Default
IP fragmentation is rare in modern networks (PMTUD/MSS negotiation handles it).
Flag as SUSPICIOUS and investigate if you see:
- Any IP fragments at all (increasingly uncommon post-2005)
- Fragments smaller than 256 bytes (almost never legitimate)
- Multiple fragments with inconsistent total sizes
- Fragments where offsets would cause overlap (classic teardrop/Rose attack signature)
- Fragments to/from hosts that also have normal-sized packets
**WHY:** Fragmentation is the basis for an entire class of attacks (teardrop, ping of death, jolt, Rose, fragment overlap, tiny fragment).

### Principle 3: Subnet Anomalies Suggest Spoofing
If a packet's source IP belongs to a different subnet than other traffic from the same physical segment, flag as LIKELY SPOOFED.
**WHY:** Legitimate hosts don't change subnets mid-conversation.

### Principle 4: Timing Correlation Reveals Intent
If reconnaissance activity (DNS lookups, port scans, ARP sweeps) is followed within seconds by anomalous traffic to the discovered target, flag the entire sequence as an ATTACK CHAIN.
**WHY:** The recon→exploit pattern is universal across attack methodologies.

### Principle 5: Expert Info Errors in This Context Are Critical
Wireshark expert "errors" on malformed/fragmented traffic indicate packets that violate protocol specifications.
In the presence of malformed packets, NEVER treat expert errors as secondary findings.
Always ask: "What would CAUSE a legitimate system to produce this?" If the answer is "nothing reasonable" → it is an attack or severe misconfiguration.

### Principle 6: Absence Is Evidence
No TCP connections completing in a capture where connections are expected = something is PREVENTING them.
Consider: DoS flooding, ARP poisoning, firewall drops, or attack traffic crowding out legitimate traffic.

`;
        return heuristics;
    }

    // ─── Token Budget ─────────────────────────────────────────────────────

    private getTokenBudget(): TokenBudgetConfig {
        const config = this.configLoader.getConfig();
        return config.tokenBudget || {
            maxInputTokens: 900000,
            reserveForResponse: 100000,
            summaryBudget: 5000,
            perStreamBudget: 50000,
        };
    }

    private estimateTokens(text: string): number {
        return Math.ceil(text.length / ContextAssembler.CHARS_PER_TOKEN);
    }
}

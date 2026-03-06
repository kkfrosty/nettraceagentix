import * as vscode from 'vscode';
import * as path from 'path';
import { TsharkRunner } from '../parsing/tsharkRunner';
import { ConfigLoader } from '../configLoader';
import { ContextAssembler } from '../contextAssembler';
import { CapturesTreeProvider } from '../views/capturesTreeProvider';
import { AgentsTreeProvider } from '../views/agentsTreeProvider';
import { StreamsTreeProvider } from '../views/streamsTreeProvider';
import { CaptureWebviewPanel } from '../views/captureWebviewPanel';
import { LiveCaptureWebviewPanel } from '../views/liveCaptureWebviewPanel';
import { resolveOpenCaptures } from '../captureRouting';
import { AgentDefinition, AssembledContext, CaptureFile } from '../types';

/**
 * The @nettrace Chat Participant.
 *
 * Simple: user opens a capture in the viewer, then types @nettrace <question>.
 * No slash commands. The AI analyzes the active capture and responds.
 */
export class NetTraceParticipant {
    private participant: vscode.ChatParticipant;
    private outputChannel: vscode.OutputChannel;

    constructor(
        private context: vscode.ExtensionContext,
        private tsharkRunner: TsharkRunner,
        private configLoader: ConfigLoader,
        private contextAssembler: ContextAssembler,
        private capturesTree: CapturesTreeProvider,
        private agentsTree: AgentsTreeProvider,
        private streamsTree: StreamsTreeProvider,
        outputChannel: vscode.OutputChannel
    ) {
        this.outputChannel = outputChannel;

        this.participant = vscode.chat.createChatParticipant(
            'nettrace.participant',
            this.handleRequest.bind(this)
        );

        this.participant.iconPath = vscode.Uri.joinPath(context.extensionUri, 'media', 'nettrace-icon.svg');

        this.participant.followupProvider = {
            provideFollowups: this.provideFollowups.bind(this),
        };

        context.subscriptions.push(this.participant);
    }

    /**
     * Main request handler — called when user types @nettrace <message>
     */
    private async handleRequest(
        request: vscode.ChatRequest,
        context: vscode.ChatContext,
        stream: vscode.ChatResponseStream,
        token: vscode.CancellationToken
    ): Promise<vscode.ChatResult> {
        this.outputChannel.appendLine(`[ChatParticipant] Request: "${request.prompt}"`);
        let { prompt: userPrompt, captureFileOverride } = this.extractCaptureOverride(request.prompt);
        if (captureFileOverride) {
            this.outputChannel.appendLine(`[ChatParticipant] Capture override from prompt: ${captureFileOverride}`);
        }

        // Gate: tshark must be available
        if (!this.tsharkRunner.isAvailable()) {
            stream.markdown('⚠️ **tshark is not available.** Install [Wireshark](https://www.wireshark.org/download.html) to enable capture analysis.\n\nAfter installing, restart VS Code.');
            return { metadata: { command: 'error' } };
        }

        // Deterministic blocking workflow for "capture for N seconds, then analyze".
        // This keeps the chat turn open with progress updates instead of returning early.
        const timedWorkflow = await this.tryRunTimedCaptureAndAnalyzeWorkflow(userPrompt, stream, token);
        if (timedWorkflow === null) {
            return { metadata: { command: 'capture-control' } };
        }
        if (timedWorkflow) {
            userPrompt = timedWorkflow.analysisPrompt;
            captureFileOverride = timedWorkflow.captureFileOverride;
            stream.markdown('🔎 Capture complete. Starting analysis now...\n\n');
        } else {
            // Deterministic capture-control fast path: execute explicit start/stop/status
            // requests directly instead of entering the model/tool loop.
            const controlResult = await this.tryHandleCaptureControlIntent(userPrompt, stream);
            if (controlResult) {
                return controlResult;
            }

            const filterResult = await this.tryHandleFilterIntent(request, context, stream, token, userPrompt);
            if (filterResult) {
                return filterResult;
            }
        }

        // Determine which captures to analyze — dual-capture mode if both roles assigned
        const { captures: capturesToAnalyze, mode: captureMode } = await this.getCapturesToAnalyze(captureFileOverride);

        if (capturesToAnalyze.length === 0) {
            // No capture is currently open in a viewer panel.
            // Instead of hard-blocking with an error, run in "no-capture" mode so agent
            // tools (e.g., nettrace-startCapture) can still be invoked by the model.
            // This fixes the case where GHC is asked to start a live capture BEFORE
            // any panel is open — the old code would fall back to allCaptures[0] and
            // wastefully assemble full context for the wrong file.
            this.outputChannel.appendLine('[ChatParticipant] No capture open — proceeding in no-capture mode');
            return await this.handleNoCaptureRequest(request, context, stream, token, userPrompt);
        }

        // Primary capture: client in dual mode, or the only capture in single mode
        const primaryCapture = capturesToAnalyze[0];

        if (captureMode === 'dual') {
            this.outputChannel.appendLine(
                `[ChatParticipant] Dual-capture mode: ` +
                capturesToAnalyze.map(c => `${c.name} [${c.role}]`).join(', ')
            );
        } else {
            this.outputChannel.appendLine(`[ChatParticipant] Analyzing: ${primaryCapture.name}`);
        }

        try {
            const agent = this.agentsTree.getActiveAgent();

            // Ensure all captures have been parsed before analysis.
            // Track which were freshly parsed — if any capture is new to this
            // conversation, the model has never seen its packet data and we
            // MUST use the full first-turn path even if there's chat history.
            let anyFreshlyParsed = false;
            for (const capture of capturesToAnalyze) {
                if (!capture.parsed || !capture.summary) {
                    anyFreshlyParsed = true;
                    const roleLabel = capture.role ? ` [${capture.role}]` : '';
                    this.outputChannel.appendLine(`[ChatParticipant] Capture not yet parsed, parsing summary for ${capture.name}...`);
                    stream.progress(`Parsing ${capture.name}${roleLabel}...`);
                    try {
                        capture.summary = await this.tsharkRunner.getCaptureSummary(capture.filePath);
                        capture.parsed = true;
                        this.capturesTree.refresh();
                        this.outputChannel.appendLine(`[ChatParticipant] Parsed: ${capture.summary.packetCount} packets, ${capture.summary.tcpStreamCount} TCP streams`);
                    } catch (e) {
                        this.outputChannel.appendLine(`[ChatParticipant] Failed to parse capture summary: ${e}`);
                        stream.markdown(`⚠️ **Failed to parse capture:** ${e instanceof Error ? e.message : String(e)}\n\nMake sure tshark can read this file.`);
                        return { metadata: { command: 'error' } };
                    }
                }
            }

            // Only use lightweight follow-up path when BOTH conditions are true:
            // 1. There IS previous chat history (user has spoken to @nettrace before)
            // 2. ALL captures were already parsed — the model received their full
            //    packet data in a previous turn. If any capture was freshly parsed
            //    this turn, the model has never seen its data (e.g., user asked
            //    to "start a capture" first, then asks to analyze the result).
            const isFollowUp = context.history.length > 0 && !anyFreshlyParsed;
            this.outputChannel.appendLine(
                `[ChatParticipant] isFollowUp=${isFollowUp} (history=${context.history.length}, freshlyParsed=${anyFreshlyParsed})`
            );

            // Get streams for all captures — vital for anomaly-aware context assembly
            let captureStreams = this.streamsTree.getStreams().filter(s =>
                capturesToAnalyze.some(c => c.filePath === s.captureFile)
            );

            // Parse streams for any capture that doesn't have cached streams yet
            for (const capture of capturesToAnalyze) {
                const alreadyCached = captureStreams.some(s => s.captureFile === capture.filePath);
                if (!alreadyCached) {
                    const roleLabel = capture.role ? ` [${capture.role}]` : '';
                    this.outputChannel.appendLine(`[ChatParticipant] No cached streams for ${capture.name}, parsing conversations...`);
                    stream.progress(`Parsing TCP conversations for ${capture.name}${roleLabel}...`);
                    try {
                        const newStreams = await this.tsharkRunner.getConversations(capture.filePath);
                        const unrelated = this.streamsTree.getStreams().filter(s => s.captureFile !== capture.filePath);
                        this.streamsTree.setStreams([...unrelated, ...newStreams]);
                        captureStreams = [...captureStreams, ...newStreams];
                        this.outputChannel.appendLine(`[ChatParticipant] Parsed ${newStreams.length} streams for ${capture.name}`);
                    } catch (e) {
                        this.outputChannel.appendLine(`[ChatParticipant] Failed to parse streams for ${capture.name}: ${e}`);
                    }
                }
            }

            let assembledContext;

            if (isFollowUp) {
                // ── Follow-up turn: lightweight context ───────────────────
                // The conversation history already contains the model's previous analysis.
                // Don't re-send all packet data — just provide the capture summary + expert info
                // so the model remembers what capture it's looking at. If the user asks about
                // specific packets, the model can use tools to fetch them on demand.
                const followUpLabel = captureMode === 'dual'
                    ? capturesToAnalyze.map(c => `${c.name} [${c.role}]`).join(' + ')
                    : primaryCapture.name;
                stream.progress(`Follow-up on ${followUpLabel}...`);
                this.outputChannel.appendLine(`[ChatParticipant] Follow-up turn — using lightweight context (no packet data re-send)`);

                const systemPrompt = this.contextAssembler.buildSystemPromptPublic(agent);
                const captureSummary = await this.contextAssembler.buildCaptureSummaryPublic(capturesToAnalyze);
                const scenarioContext = this.contextAssembler.buildScenarioContextPublic();
                const knowledgeContext = await this.contextAssembler.buildKnowledgeContextPublic(capturesToAnalyze, captureStreams, agent);

                const cpt = NetTraceParticipant.CHARS_PER_TOKEN;
                const lightweightTokens =
                    Math.ceil(systemPrompt.length / cpt) +
                    Math.ceil(captureSummary.length / cpt) +
                    Math.ceil(scenarioContext.length / cpt) +
                    Math.ceil(knowledgeContext.length / cpt);

                const totalPacketsFollowUp = capturesToAnalyze.reduce(
                    (sum, c) => sum + (c.summary?.packetCount || 0), 0
                );
                assembledContext = {
                    systemPrompt,
                    captureSummary,
                    streamDetails: '', // Not needed — model has this from previous turn
                    scenarioContext,
                    packetData: '',    // Not needed — model has its analysis. Use tools if it needs to revisit.
                    knowledgeContext,
                    estimatedTokens: lightweightTokens,
                    coverage: { mode: 'complete' as const, totalPackets: totalPacketsFollowUp, packetsIncluded: totalPacketsFollowUp },
                };
            } else {
                // ── First turn: full context with all packets ─────────────
                const firstTurnLabel = captureMode === 'dual'
                    ? capturesToAnalyze.map(c => `${c.name} [${c.role}]`).join(' + ')
                    : primaryCapture.name;
                stream.progress(`Analyzing ${firstTurnLabel}...`);
                assembledContext = await this.contextAssembler.assembleContext(
                    capturesToAnalyze, captureStreams, agent, userPrompt, request.model
                );
            }

            return await this.sendToModel(request, context, stream, token, assembledContext, userPrompt, capturesToAnalyze, agent, !isFollowUp);
        } catch (error) {
            this.outputChannel.appendLine(`[ChatParticipant] Error: ${error}`);
            if (error instanceof vscode.LanguageModelError) {
                stream.markdown(`⚠️ **Model error:** ${error.message}`);
            } else {
                stream.markdown(`❌ **Error during analysis:** ${error instanceof Error ? error.message : String(error)}`);
            }
            return { metadata: { command: 'error' } };
        }
    }

    // ─── Model Communication ──────────────────────────────────────────────

    private static readonly MAX_TOOL_ROUNDTRIPS = 25;
    private static readonly CHARS_PER_TOKEN = 3;

    private estimateMessageTokens(messages: vscode.LanguageModelChatMessage[]): number {
        let totalChars = 0;
        for (const msg of messages) {
            // LanguageModelChatMessage.content is always an array of parts
            if (Array.isArray(msg.content)) {
                for (const part of msg.content) {
                    if (part instanceof vscode.LanguageModelTextPart) {
                        totalChars += part.value.length;
                    } else if (part instanceof vscode.LanguageModelToolResultPart) {
                        for (const rp of part.content) {
                            if (rp instanceof vscode.LanguageModelTextPart) {
                                totalChars += rp.value.length;
                            }
                        }
                    } else if (part instanceof vscode.LanguageModelToolCallPart) {
                        totalChars += JSON.stringify(part.input).length + (part.name?.length || 0);
                    }
                }
            }
        }
        return Math.ceil(totalChars / NetTraceParticipant.CHARS_PER_TOKEN);
    }

    private resolveTools(toolNames: string[]): vscode.LanguageModelChatTool[] {
        const registeredTools = vscode.lm.tools;
        const resolved: vscode.LanguageModelChatTool[] = [];

        for (const name of toolNames) {
            const toolInfo = registeredTools.find(t => t.name === name);
            if (toolInfo) {
                resolved.push({
                    name: toolInfo.name,
                    description: toolInfo.description,
                    inputSchema: toolInfo.inputSchema,
                });
            } else {
                this.outputChannel.appendLine(`[ChatParticipant] Warning: tool "${name}" not found in vscode.lm.tools`);
            }
        }

        return resolved;
    }

    private isDisplayFilterIntent(prompt: string): boolean {
        const p = prompt.trim().toLowerCase();
        if (!p) { return false; }
        if (this.isAnalyzeIntent(p)) { return false; }

        return /^(?:please\s+)?(?:apply|set|change|update|use|clear|remove)\s+(?:the\s+|a\s+)?(?:(?:wireshark|display)\s+)?filter\b/.test(p)
            || /^(?:please\s+)?(?:(?:wireshark|display)\s+)?filter\b/.test(p)
            || /^show\s+only\b/.test(p);
    }

    // ── Message Sanitization ──────────────────────────────────────────────
    // Ensures the messages array conforms to the LLM API's strict rules:
    //   1. Strict role alternation (user, assistant, user, ...)
    //   2. First message is always User
    //   3. Every tool_result references a tool_use in the immediately preceding assistant message
    //   4. Every tool_use has a corresponding tool_result in the immediately following user message
    // Prevents 400 errors like "unexpected tool_use_id found in tool_result blocks".

    private sanitizeMessagesForApi(
        messages: vscode.LanguageModelChatMessage[]
    ): vscode.LanguageModelChatMessage[] {
        if (messages.length === 0) { return []; }

        // ── Step 1: Merge consecutive same-role messages ──────────────────
        // The Claude API rejects non-alternating roles. Even if VS Code's proxy
        // attempts to merge them, the result can be unpredictable when tool_result
        // or tool_use parts are involved. We take control of the merge here.
        const merged: vscode.LanguageModelChatMessage[] = [];
        for (const msg of messages) {
            const last = merged[merged.length - 1];
            if (last && last.role === msg.role) {
                const existingParts = [...last.content];
                const newParts = [...msg.content];
                const allParts = [...existingParts, ...newParts];

                if (msg.role === vscode.LanguageModelChatMessageRole.User) {
                    const userParts = allParts.filter(
                        p => p instanceof vscode.LanguageModelTextPart || p instanceof vscode.LanguageModelToolResultPart
                    ) as (vscode.LanguageModelTextPart | vscode.LanguageModelToolResultPart)[];
                    merged[merged.length - 1] = vscode.LanguageModelChatMessage.User(userParts);
                } else {
                    const assistantParts = allParts.filter(
                        p => p instanceof vscode.LanguageModelTextPart || p instanceof vscode.LanguageModelToolCallPart
                    ) as (vscode.LanguageModelTextPart | vscode.LanguageModelToolCallPart)[];
                    merged[merged.length - 1] = vscode.LanguageModelChatMessage.Assistant(assistantParts);
                }
                this.outputChannel.appendLine(
                    `[Sanitize] Merged consecutive ${msg.role === vscode.LanguageModelChatMessageRole.User ? 'User' : 'Assistant'} messages`
                );
            } else {
                merged.push(msg);
            }
        }

        // ── Step 2: Ensure first message is User ──────────────────────────
        if (merged.length > 0 && merged[0].role !== vscode.LanguageModelChatMessageRole.User) {
            merged.unshift(vscode.LanguageModelChatMessage.User('Begin analysis.'));
            this.outputChannel.appendLine('[Sanitize] Prepended User message to fix first-message role');
        }

        // ── Step 3: Validate tool_use / tool_result pairing ──────────────
        for (let i = 0; i < merged.length; i++) {
            const msg = merged[i];
            const parts = [...msg.content];

            if (msg.role === vscode.LanguageModelChatMessageRole.Assistant) {
                // Collect tool_use callIds from this assistant message
                const toolCallIds = new Set<string>();
                for (const p of parts) {
                    if (p instanceof vscode.LanguageModelToolCallPart) {
                        toolCallIds.add(p.callId);
                    }
                }

                if (toolCallIds.size > 0) {
                    if (i + 1 < merged.length && merged[i + 1].role === vscode.LanguageModelChatMessageRole.User) {
                        const nextParts = [...merged[i + 1].content];
                        const resultIds = new Set<string>();
                        for (const p of nextParts) {
                            if (p instanceof vscode.LanguageModelToolResultPart) {
                                resultIds.add(p.callId);
                            }
                        }

                        // Remove tool_results that don't match any tool_use in this assistant message
                        let stripped = 0;
                        const cleanedParts = nextParts.filter(p => {
                            if (p instanceof vscode.LanguageModelToolResultPart) {
                                if (!toolCallIds.has(p.callId)) {
                                    stripped++;
                                    return false;
                                }
                            }
                            return true;
                        });

                        // Pad missing tool_results for tool_uses that have no result
                        const missingIds: string[] = [];
                        const cleanedResultIds = new Set(
                            cleanedParts
                                .filter(p => p instanceof vscode.LanguageModelToolResultPart)
                                .map(p => (p as vscode.LanguageModelToolResultPart).callId)
                        );
                        for (const id of toolCallIds) {
                            if (!cleanedResultIds.has(id)) {
                                missingIds.push(id);
                                cleanedParts.push(new vscode.LanguageModelToolResultPart(id, [
                                    new vscode.LanguageModelTextPart('Error: Tool call was not completed (cancelled or failed).')
                                ]));
                            }
                        }

                        if (stripped > 0 || missingIds.length > 0) {
                            const userParts = cleanedParts.filter(
                                p => p instanceof vscode.LanguageModelTextPart || p instanceof vscode.LanguageModelToolResultPart
                            ) as (vscode.LanguageModelTextPart | vscode.LanguageModelToolResultPart)[];
                            merged[i + 1] = vscode.LanguageModelChatMessage.User(userParts);
                            if (stripped > 0) {
                                this.outputChannel.appendLine(`[Sanitize] Removed ${stripped} orphaned tool_result(s) from message ${i + 1}`);
                            }
                            if (missingIds.length > 0) {
                                this.outputChannel.appendLine(`[Sanitize] Added ${missingIds.length} missing tool_result(s) to message ${i + 1}`);
                            }
                        }
                    } else {
                        // No following User message with tool_results — strip tool_uses
                        // so the API doesn't expect results that will never come.
                        const cleaned = parts.filter(p => !(p instanceof vscode.LanguageModelToolCallPart));
                        if (cleaned.length === 0) {
                            cleaned.push(new vscode.LanguageModelTextPart('(Analysis in progress)'));
                        }
                        const assistantParts = cleaned.filter(
                            p => p instanceof vscode.LanguageModelTextPart || p instanceof vscode.LanguageModelToolCallPart
                        ) as (vscode.LanguageModelTextPart | vscode.LanguageModelToolCallPart)[];
                        merged[i] = vscode.LanguageModelChatMessage.Assistant(assistantParts);
                        this.outputChannel.appendLine(
                            `[Sanitize] Stripped ${toolCallIds.size} unresolved tool_call(s) from assistant message ${i}`
                        );
                    }
                }
            } else if (msg.role === vscode.LanguageModelChatMessageRole.User) {
                // Check for tool_results in User messages not preceded by an assistant with tool_uses
                const hasToolResults = parts.some(p => p instanceof vscode.LanguageModelToolResultPart);
                if (hasToolResults) {
                    const prevMsg = i > 0 ? merged[i - 1] : null;
                    let prevHasToolCalls = false;
                    if (prevMsg && prevMsg.role === vscode.LanguageModelChatMessageRole.Assistant) {
                        prevHasToolCalls = prevMsg.content.some(p => p instanceof vscode.LanguageModelToolCallPart);
                    }

                    if (!prevHasToolCalls) {
                        // Orphaned tool_results — strip them
                        const cleaned = parts.filter(p => !(p instanceof vscode.LanguageModelToolResultPart));
                        if (cleaned.length === 0) {
                            cleaned.push(new vscode.LanguageModelTextPart('(Previous tool interaction completed)'));
                        }
                        const userParts = cleaned.filter(
                            p => p instanceof vscode.LanguageModelTextPart || p instanceof vscode.LanguageModelToolResultPart
                        ) as (vscode.LanguageModelTextPart | vscode.LanguageModelToolResultPart)[];
                        merged[i] = vscode.LanguageModelChatMessage.User(userParts);
                        this.outputChannel.appendLine(`[Sanitize] Stripped orphaned tool_result(s) from user message ${i}`);
                    }
                }
            }
        }

        // ── Final assertion: messages[0] must be text-only User ───────────
        // The Claude API (via Copilot proxy) requires the first message to be a
        // user message with text content. If it has tool_result blocks, the API
        // will reject with "unexpected tool_use_id". This is our last line of
        // defense — if something above failed to clean properly, force-strip here.
        if (merged.length > 0) {
            const first = merged[0];
            const firstParts = [...first.content];
            const hasToolContent = firstParts.some(
                p => p instanceof vscode.LanguageModelToolResultPart ||
                     p instanceof vscode.LanguageModelToolCallPart
            );
            if (hasToolContent) {
                this.outputChannel.appendLine(
                    `[Sanitize] CRITICAL: messages[0] contained tool content! Force-stripping.`
                );
                const textOnly = firstParts.filter(p => p instanceof vscode.LanguageModelTextPart);
                if (textOnly.length === 0) {
                    textOnly.push(new vscode.LanguageModelTextPart('Analyze the network capture.'));
                }
                merged[0] = vscode.LanguageModelChatMessage.User(
                    textOnly as vscode.LanguageModelTextPart[]
                );
            }

            // Also ensure first message is User role
            if (first.role !== vscode.LanguageModelChatMessageRole.User) {
                this.outputChannel.appendLine(
                    `[Sanitize] CRITICAL: messages[0] was not User role! Prepending text User message.`
                );
                merged.unshift(vscode.LanguageModelChatMessage.User('Analyze the network capture.'));
            }
        }

        return merged;
    }

    /**
     * Log the message structure for debugging, then send to the model.
     * Unlike the previous sendToModelApi approach, this does NOT re-sanitize —
     * we trust the single sanitize pass before the tool loop and the loop's own
     * correct construction. Re-sanitizing on every send created new message
     * objects that could confuse the VS Code proxy.
     */
    private async logAndSend(
        model: vscode.LanguageModelChat,
        messages: vscode.LanguageModelChatMessage[],
        options: vscode.LanguageModelChatRequestOptions,
        token: vscode.CancellationToken,
        label: string
    ): Promise<vscode.LanguageModelChatResponse> {
        this.outputChannel.appendLine(`[SendToModel] ${label} — sending ${messages.length} messages:`);
        for (let i = 0; i < messages.length; i++) {
            const msg = messages[i];
            const role = msg.role === vscode.LanguageModelChatMessageRole.User ? 'User' : 'Assistant';
            const parts = Array.isArray(msg.content) ? msg.content : [];
            const desc = parts.map(p => {
                if (p instanceof vscode.LanguageModelTextPart) { return `Text(${p.value.length})`; }
                if (p instanceof vscode.LanguageModelToolResultPart) { return `ToolResult(${p.callId})`; }
                if (p instanceof vscode.LanguageModelToolCallPart) { return `ToolCall(${p.name}/${p.callId})`; }
                return `Unknown(${(p as any)?.constructor?.name || typeof p})`;
            }).join(', ');
            this.outputChannel.appendLine(`  [${i}] ${role}: [${desc}]`);
        }

        return model.sendRequest(messages, options, token);
    }

    private async sendToModel(
        request: vscode.ChatRequest,
        chatContext: vscode.ChatContext,
        stream: vscode.ChatResponseStream,
        token: vscode.CancellationToken,
        context: AssembledContext,
        userMessage: string,
        captures: CaptureFile[],
        agent: AgentDefinition,
        isFirstTurn: boolean
    ): Promise<vscode.ChatResult> {
        const model = request.model;
        const modelMax = model.maxInputTokens;
        this.outputChannel.appendLine(`[ChatParticipant] Model: ${model.name}, maxInput: ${modelMax}, context: ~${context.estimatedTokens} tokens`);

        const liveStatus = LiveCaptureWebviewPanel.getActivePanel()?.getStatusSnapshot();

        // Build coverage string and stats line
        const pct = modelMax > 0 ? Math.round((context.estimatedTokens / modelMax) * 100) : 0;
        const coverageInfo = context.coverage
            ? captures.length === 0
                ? (() => {
                    if (!liveStatus?.hasSession) {
                        return '\ud83e\uddf0 No capture preloaded yet (tool-driven mode)';
                    }

                    const livePackets = liveStatus.packetCount || 0;
                    const status = liveStatus.sessionStatus;
                    if ((status === 'starting' || status === 'capturing') && livePackets === 0) {
                        return '\u23f3 Live capture is running — waiting for first packets';
                    }
                    if (status === 'stopping') {
                        return '\u23f3 Live capture is stopping — finalizing capture file';
                    }
                    if (livePackets > 0) {
                        return `\ud83d\udce1 Live capture has ${livePackets.toLocaleString()} packet${livePackets === 1 ? '' : 's'} available`;
                    }
                    return '\ud83d\udce1 Live capture session is ready';
                })()
                : context.coverage.mode === 'complete'
                    ? `\u2705 All ${context.coverage.totalPackets.toLocaleString()} packets loaded`
                    : (() => {
                        // Sampled mode: the initial load is intentionally sized to leave room in the
                        // tool loop for range-paging calls. Surface this as a coverage plan, not a
                        // limitation — "pre-loaded X%, tools will cover the rest" is more accurate
                        // than implying only X% of the capture will be analyzed.
                        const numRanges = context.coverage.uncoveredRanges?.length || 0;
                        const uncoveredPct = context.coverage.totalPackets > 0
                            ? Math.round(((context.coverage.totalPackets - context.coverage.packetsIncluded) / context.coverage.totalPackets) * 100)
                            : 0;
                        const rangeNote = numRanges > 0
                            ? ` \u00b7 \ud83d\udd0d tools scanning remaining ${uncoveredPct}% via ${numRanges} range pass${numRanges > 1 ? 'es' : ''}`
                            : '';
                        return `\ud83d\udcca Pre-loaded ${context.coverage.packetsIncluded.toLocaleString()} of ${context.coverage.totalPackets.toLocaleString()} packets${rangeNote}`;
                    })()
            : '';
        const captureLabel = captures.length > 1
            ? captures.map(c => `${c.name}${c.role ? ` [${c.role}]` : ''}`).join(' + ')
            : captures.length === 1
                ? captures[0].name
                : (() => {
                    if (!liveStatus?.hasSession) {
                        return 'no capture selected yet';
                    }
                    const livePackets = liveStatus.packetCount || 0;
                    const liveFile = liveStatus.captureFile ? path.basename(liveStatus.captureFile) : undefined;
                    if (livePackets === 0 && (liveStatus.sessionStatus === 'starting' || liveStatus.sessionStatus === 'capturing')) {
                        return 'active live capture (collecting packets)';
                    }
                    if (liveFile) {
                        return `live capture (${liveFile})`;
                    }
                    return 'active live capture';
                })();
        const statsLine = `*Using **${model.name}** \u2014 ~${Math.round(context.estimatedTokens / 1000)}K of ${Math.round(modelMax / 1000)}K tokens (${pct}%) \u00b7 ${coverageInfo} \u00b7 analyzing ${captureLabel}*`;

        if (isFirstTurn) {
            // \u2500\u2500 First-turn header: agent identity + knowledge documents in use \u2500\u2500
            const agentLabel = agent.displayName || agent.name;
            const agentDesc = agent.description ? ` \u2014 *${agent.description}*` : '';

            const manifest = context.knowledgeManifest;
            let knowledgeLine = '';
            if (manifest) {
                const allFiles = [...manifest.wisdomFiles, ...manifest.securityFiles];
                if (allFiles.length > 0) {
                    const fileLinks = allFiles.map(f => `\`${f}\``).join(' \u00b7 ');
                    const securityNote = manifest.securityTriggered ? ' \u00b7 \u26a0\ufe0f *Security heuristics activated by capture signals*' : '';
                    knowledgeLine = `\n**Knowledge:** ${fileLinks}${securityNote}`;
                } else {
                    knowledgeLine = `\n*No knowledge documents \u2014 using model\'s built-in expertise*`;
                }
            }

            stream.markdown(`**Agent:** ${agentLabel}${agentDesc}${knowledgeLine}\n${statsLine}\n\n---\n\n`);
            if (captures.length > 1) {
                stream.markdown(
                    `> 🔄 **Dual-capture mode** — analyzing CLIENT and SERVER traces simultaneously. ` +
                    `Tools can target either capture using the \`captureFile\` parameter shown in each capture's summary below.\n\n`
                );
            }
        } else {
            // Follow-up turns: compact status line only
            stream.markdown(`${statsLine}\n\n`);
        }

        // ── Build messages with strict role alternation ─────────────────────
        // The Claude API requires:
        //   1. Strictly alternating user/assistant messages
        //   2. First message must be user role with text content (NOT tool_result)
        //   3. Every tool_result must reference a tool_use in the immediately preceding
        //      assistant message
        //
        // VS Code's Copilot proxy may extract the first User message as the Claude
        // "system" parameter. If that happens, the second message becomes messages[0]
        // in the Claude API. We must ensure that even after such extraction, the
        // remaining messages start with a text-only User and maintain alternation.
        //
        // Strategy:
        //   - Combine context + user query into ONE User message (no consecutive Users)
        //   - Build clean history with proper alternation
        //   - After all construction, sanitize in-place before the tool loop starts

        const contextParts = [context.systemPrompt];

        // Include scenario context and capture summary metadata
        const metaContent = [context.scenarioContext, context.captureSummary, context.streamDetails]
            .filter(s => s.length > 0)
            .join('\n');
        if (metaContent) { contextParts.push(metaContent); }

        // Include knowledge context (analysis wisdom, conditional security heuristics)
        if (context.knowledgeContext && context.knowledgeContext.length > 0) {
            contextParts.push(context.knowledgeContext);
        }

        // Include actual packet data — this is the real trace content
        if (context.packetData && context.packetData.length > 0) {
            contextParts.push(context.packetData);
        }

        // Build the initial messages array — context is ALWAYS the first message
        // and must be a text-only User message. We add a separator to keep the
        // context distinct from the user's actual question.
        const contextBlock = contextParts.join('\n\n---\n\n');

        let messages: vscode.LanguageModelChatMessage[] = [];

        if (chatContext.history.length === 0) {
            // ── First turn: combine context + user query in ONE User message ──
            // This ensures messages[0] is a single text-only User message.
            // No consecutive Users. No merge needed. Clean for any proxy behavior.
            messages.push(vscode.LanguageModelChatMessage.User(
                contextBlock + '\n\n---\n\n## User Query\n\n' + userMessage
            ));
        } else {
            // ── Follow-up turn: context, then history, then user query ────────
            messages.push(vscode.LanguageModelChatMessage.User(contextBlock));

            // Conversation history for multi-turn — extract text-only content.
            // Drop any tool_use/tool_result artifacts from previous turns to prevent
            // orphaned tool blocks in the API request.
            // ALWAYS insert an Assistant message for every response turn — skipping
            // empty responses would create consecutive User messages.
            for (const turn of chatContext.history) {
                if (turn instanceof vscode.ChatRequestTurn) {
                    messages.push(vscode.LanguageModelChatMessage.User(turn.prompt));
                } else if (turn instanceof vscode.ChatResponseTurn) {
                    let responseText = '';
                    for (const part of turn.response) {
                        if (part instanceof vscode.ChatResponseMarkdownPart) {
                            responseText += part.value.value;
                        }
                    }
                    messages.push(vscode.LanguageModelChatMessage.Assistant(
                        responseText || '(Analysis performed using tool calls)'
                    ));
                }
            }

            // Ensure the last message before the user's prompt is not also User role
            const lastMsg = messages[messages.length - 1];
            if (lastMsg && lastMsg.role === vscode.LanguageModelChatMessageRole.User) {
                messages.push(vscode.LanguageModelChatMessage.Assistant(
                    'Understood. What would you like me to analyze?'
                ));
            }

            messages.push(vscode.LanguageModelChatMessage.User(userMessage));
        }

        // ── Sanitize in-place BEFORE the tool loop starts ─────────────────
        // This ensures the working messages array is always clean. The tool loop
        // pushes new entries to THIS sanitized array, keeping it consistent.
        messages = this.sanitizeMessagesForApi(messages);

        const toolNames = agent.tools || [];
        // Always include live-capture control tools regardless of active agent.
        const requiredTools = ['nettrace-startCapture', 'nettrace-stopCapture', 'nettrace-getLiveCaptureStatus'];
        const allToolNames = [...toolNames];
        for (const required of requiredTools) {
            if (!allToolNames.includes(required)) {
                allToolNames.push(required);
            }
        }
        const tools = this.resolveTools(allToolNames);

        // Log message structure for debugging API errors
        this.outputChannel.appendLine(`[ChatParticipant] Message structure after sanitize (${messages.length} messages):`);
        for (let i = 0; i < messages.length; i++) {
            const msg = messages[i];
            const role = msg.role === vscode.LanguageModelChatMessageRole.User ? 'User' : 'Assistant';
            const contentDesc = Array.isArray(msg.content)
                ? msg.content.map(p => {
                    if (p instanceof vscode.LanguageModelTextPart) { return `Text(${p.value.length} chars)`; }
                    if (p instanceof vscode.LanguageModelToolResultPart) { return `ToolResult(${p.callId})`; }
                    if (p instanceof vscode.LanguageModelToolCallPart) { return `ToolCall(${p.name})`; }
                    return 'Unknown';
                }).join(', ')
                : 'string';
            this.outputChannel.appendLine(`  [${i}] ${role}: ${contentDesc}`);
        }

        // ── Agentic tool-calling loop with token budget tracking ──────────
        // Track accumulated tokens to prevent exceeding the model's context limit.
        // The context assembler reserves a fraction of the model's context for tool-loop
        // overhead. We must use the SAME fraction here — not a flat 5% — or we'll be
        // more permissive than the assembler intended and risk overflowing on large captures.
        //
        // Reserve fractions (mirroring contextAssembler.ts):
        //   complete mode: 10%  — all packets loaded, tools are optional extras
        //   sampled mode:  15-35% depending on model size — tools MUST page uncovered ranges
        //
        // We derive the fraction from the coverage mode already in the assembled context.
        const isSampled = context.coverage?.mode === 'sampled';
        let toolReserveFraction: number;
        if (!isSampled) {
            toolReserveFraction = 0.10;
        } else if (modelMax < 200000) {
            toolReserveFraction = 0.35;
        } else if (modelMax > 500000) {
            toolReserveFraction = 0.15;
        } else {
            toolReserveFraction = 0.20;
        }
        // Subtract the assembler's reserve from the model max — that's our hard ceiling.
        // Then add a small margin (half the reserve) for the tool responses themselves.
        // Net effect: tool loop gets headroom WITHOUT exceeding what the assembler planned.
        const tokenLimit = Math.floor(modelMax * (1 - toolReserveFraction / 2));
        this.outputChannel.appendLine(
            `[ChatParticipant] Tool loop budget: mode=${isSampled ? 'sampled' : 'complete'}, ` +
            `reserve=${Math.round(toolReserveFraction * 100)}%, tokenLimit=${tokenLimit}`
        );
        let roundTrip = 0;

        while (roundTrip < NetTraceParticipant.MAX_TOOL_ROUNDTRIPS) {
            roundTrip++;
            if (token.isCancellationRequested) { break; }

            // Pre-flight check: estimate total tokens before sending
            const estimatedTokens = this.estimateMessageTokens(messages);

            // On round 1, validate with model's actual tokenizer as a safety net.
            // The context assembler calibrates packet data, but this catches any
            // remaining estimation errors before hitting the API.
            if (roundTrip === 1) {
                try {
                    const realCounts = await Promise.all(
                        messages.map(m => model.countTokens(m, token))
                    );
                    const realTotal = realCounts.reduce((a, b) => a + b, 0);
                    if (realTotal > modelMax) {
                        this.outputChannel.appendLine(
                            `[ChatParticipant] ⚠ Pre-flight: ${realTotal} real tokens exceeds model limit ${modelMax} ` +
                            `(char estimate was ${estimatedTokens}).`
                        );
                        stream.markdown(
                            `\n\n⚠️ **Context too large** (~${Math.round(realTotal / 1000)}K tokens, ` +
                            `model limit is ${Math.round(modelMax / 1000)}K). ` +
                            `Try a model with a larger context window or a smaller capture.\n`
                        );
                        return { metadata: { command: 'error' } };
                    }
                    this.outputChannel.appendLine(
                        `[ChatParticipant] Pre-flight: ${realTotal} real tokens ` +
                        `(char estimate ${estimatedTokens}), limit ${modelMax} — OK`
                    );
                } catch { /* countTokens unavailable — proceed with estimate */ }
            }

            const remainingBudget = tokenLimit - estimatedTokens;

            // On the FIRST roundtrip, always send with tools — the model needs them
            // to analyze the capture even if the context is large. The budget-cap
            // path should only trigger on subsequent roundtrips after tool results
            // have accumulated and genuinely exhausted the budget.
            //
            // Threshold: 10% of the model's total context OR 20K tokens, whichever is larger.
            // A flat 20K threshold is too small on 128K models where tool results can be 8-15K
            // each — it would cut off analysis after just 2-3 rounds. Using 10% of modelMax
            // ensures we always have room for at least one more meaningful tool exchange.
            const minRemainingBudget = Math.max(20000, Math.floor(modelMax * 0.10));
            if (remainingBudget < minRemainingBudget && roundTrip > 1) {
                // Budget near floor — not enough for a useful tool response.
                // Tell the model to wrap up with what it has.
                this.outputChannel.appendLine(
                    `[ChatParticipant] Token budget nearly exhausted (~${estimatedTokens} tokens used, limit ${tokenLimit}, ` +
                    `min threshold ${minRemainingBudget}). Sending final request without tools.`
                );
                stream.markdown('\n\n*Context limit approaching — finalizing analysis with data gathered so far.*\n\n');

                // Send one final request WITHOUT tools so the model wraps up
                messages = this.sanitizeMessagesForApi(messages);
                const finalResponse = await this.logAndSend(model, messages, {}, token, 'budget-cap final');
                for await (const part of finalResponse.stream) {
                    if (part instanceof vscode.LanguageModelTextPart) {
                        stream.markdown(part.value);
                    }
                }
                this.outputChannel.appendLine(`[ChatParticipant] Done (${roundTrip} round trip(s), budget-capped)`);
                break;
            }

            this.outputChannel.appendLine(
                `[ChatParticipant] Round ${roundTrip}: ~${estimatedTokens} tokens used, ~${remainingBudget} remaining`
            );

            // Re-sanitize before every send — the tool loop appends messages
            // that may create structural issues the proxy can't handle.
            messages = this.sanitizeMessagesForApi(messages);

            let chatResponse;
            try {
                chatResponse = await this.logAndSend(model, messages, { tools }, token, `round ${roundTrip}`);
            } catch (sendError: any) {
                // If we get a 400 error (often tool_use/tool_result mismatch),
                // retry WITHOUT tools as a fallback so the user still gets analysis
                const errMsg = sendError?.message || String(sendError);
                if (errMsg.includes('400') || errMsg.includes('invalid_request_error') || errMsg.includes('tool_use_id')) {
                    // Log the FULL message structure that caused the error for diagnosis
                    this.outputChannel.appendLine(
                        `[ChatParticipant] ═══ API ERROR (round ${roundTrip}) ═══\n` +
                        `  Error: ${errMsg}\n` +
                        `  Messages array (${messages.length} items) at time of failure:`
                    );
                    for (let i = 0; i < messages.length; i++) {
                        const m = messages[i];
                        const role = m.role === vscode.LanguageModelChatMessageRole.User ? 'User' : 'Assistant';
                        const parts = Array.isArray(m.content) ? m.content : [];
                        const desc = parts.map(p => {
                            if (p instanceof vscode.LanguageModelTextPart) { return `Text(${p.value.length})`; }
                            if (p instanceof vscode.LanguageModelToolResultPart) { return `ToolResult(id=${p.callId})`; }
                            if (p instanceof vscode.LanguageModelToolCallPart) { return `ToolCall(${p.name},id=${p.callId})`; }
                            return `Unknown(${(p as any)?.constructor?.name || typeof p})`;
                        }).join(', ');
                        this.outputChannel.appendLine(`    [${i}] ${role}: [${desc}]`);
                    }
                    this.outputChannel.appendLine(`  ═══ END ERROR DUMP ═══`);

                    stream.markdown('\n\n*Tool calling encountered an API error — analyzing without tools.*\n\n');
                    // Strip messages containing tool result/call parts, then sanitize
                    const textOnlyMessages = messages.filter(m => {
                        if (!Array.isArray(m.content)) { return true; }
                        return !m.content.some(p =>
                            p instanceof vscode.LanguageModelToolResultPart ||
                            p instanceof vscode.LanguageModelToolCallPart
                        );
                    });
                    const sanitizedFallback = this.sanitizeMessagesForApi(textOnlyMessages);
                    const fallbackResponse = await this.logAndSend(
                        model, sanitizedFallback, {}, token, 'error fallback'
                    );
                    for await (const part of fallbackResponse.stream) {
                        if (part instanceof vscode.LanguageModelTextPart) {
                            stream.markdown(part.value);
                        }
                    }
                    this.outputChannel.appendLine(`[ChatParticipant] Done (fallback, no tools)`);
                    break;
                }
                throw sendError;
            }

            const textParts: string[] = [];
            const toolCallParts: vscode.LanguageModelToolCallPart[] = [];

            for await (const part of chatResponse.stream) {
                if (part instanceof vscode.LanguageModelTextPart) {
                    stream.markdown(part.value);
                    textParts.push(part.value);
                } else if (part instanceof vscode.LanguageModelToolCallPart) {
                    toolCallParts.push(part);
                }
            }

            if (toolCallParts.length === 0) {
                this.outputChannel.appendLine(`[ChatParticipant] Done (${roundTrip} round trip(s))`);
                break;
            }

            this.outputChannel.appendLine(`[ChatParticipant] Round ${roundTrip}: ${toolCallParts.length} tool call(s)`);

            const assistantContent: (vscode.LanguageModelTextPart | vscode.LanguageModelToolCallPart)[] = [];
            if (textParts.length > 0) {
                assistantContent.push(new vscode.LanguageModelTextPart(textParts.join('')));
            }
            for (const tc of toolCallParts) {
                assistantContent.push(new vscode.LanguageModelToolCallPart(tc.callId, tc.name, tc.input));
            }
            messages.push(vscode.LanguageModelChatMessage.Assistant(assistantContent));

            // Calculate dynamic cap for tool responses based on remaining budget
            const postAssistTokens = this.estimateMessageTokens(messages);
            const budgetForTools = tokenLimit - postAssistTokens - 30000; // Reserve 30K for next model response
            const perToolBudget = Math.max(
                10000, // Minimum 10K chars per tool
                Math.floor((budgetForTools * NetTraceParticipant.CHARS_PER_TOKEN) / toolCallParts.length)
            );

            this.outputChannel.appendLine(
                `[ChatParticipant] Tool response budget: ~${budgetForTools} tokens total, ~${Math.floor(perToolBudget / NetTraceParticipant.CHARS_PER_TOKEN)} tokens per tool`
            );

            const toolResultParts: vscode.LanguageModelToolResultPart[] = [];

            for (const toolCall of toolCallParts) {
                if (token.isCancellationRequested) { break; }

                stream.progress(`Querying: ${toolCall.name}...`);
                this.outputChannel.appendLine(`[ChatParticipant] Tool "${toolCall.name}" input=${JSON.stringify(toolCall.input)}`);

                try {
                    const toolResult = await vscode.lm.invokeTool(toolCall.name, {
                        input: toolCall.input,
                        toolInvocationToken: request.toolInvocationToken,
                    }, token);

                    const resultContent: (vscode.LanguageModelTextPart | vscode.LanguageModelPromptTsxPart)[] = [];
                    for (const contentPart of toolResult.content) {
                        if (contentPart instanceof vscode.LanguageModelTextPart) {
                            // Apply dynamic cap to prevent blowing the budget
                            let text = contentPart.value;
                            if (text.length > perToolBudget) {
                                text = text.substring(0, perToolBudget) +
                                    `\n\n... (truncated to fit context budget — ${text.length} chars total, showing first ${perToolBudget})`;
                                this.outputChannel.appendLine(
                                    `[ChatParticipant] Truncated ${toolCall.name} response from ${contentPart.value.length} to ${perToolBudget} chars`
                                );
                            }
                            resultContent.push(new vscode.LanguageModelTextPart(text));
                        }
                    }
                    toolResultParts.push(new vscode.LanguageModelToolResultPart(toolCall.callId, resultContent));
                } catch (err) {
                    this.outputChannel.appendLine(`[ChatParticipant] Tool error: ${err}`);
                    toolResultParts.push(new vscode.LanguageModelToolResultPart(toolCall.callId, [
                        new vscode.LanguageModelTextPart(`Error: ${err instanceof Error ? err.message : String(err)}`),
                    ]));
                }
            }

            // ── Ensure every tool_call has a matching tool_result ─────────
            // If cancellation broke the inner loop, some tool calls won't have
            // results yet. The API requires 1:1 pairing — pad any missing ones.
            for (const toolCall of toolCallParts) {
                const hasResult = toolResultParts.some(r => r.callId === toolCall.callId);
                if (!hasResult) {
                    toolResultParts.push(new vscode.LanguageModelToolResultPart(toolCall.callId, [
                        new vscode.LanguageModelTextPart('Error: Tool execution was cancelled.'),
                    ]));
                    this.outputChannel.appendLine(
                        `[ChatParticipant] Padded missing result for cancelled tool ${toolCall.name} (${toolCall.callId})`
                    );
                }
            }

            messages.push(vscode.LanguageModelChatMessage.User(toolResultParts));
        }

        if (roundTrip >= NetTraceParticipant.MAX_TOOL_ROUNDTRIPS) {
            stream.markdown('\n\n*⚠️ Reached tool-call limit. Analysis is based on data gathered so far.*');
        }

        for (const capture of captures) {
            stream.reference(vscode.Uri.file(capture.filePath));
        }

        return { metadata: { command: 'analysis' } };
    }

    // ─── No-Capture Mode ──────────────────────────────────────────────────

    /**
     * Handle a request when no capture panel is currently open.
     *
     * Rather than blocking with an error, we give the model a minimal context
     * (system prompt + scenario) and full tool access. This allows it to:
     *   - Call nettrace-startCapture to open a live capture session
     *   - Advise the user to open an existing capture
     *   - Answer general network questions with its built-in knowledge
     */
    private async handleNoCaptureRequest(
        request: vscode.ChatRequest,
        chatContext: vscode.ChatContext,
        stream: vscode.ChatResponseStream,
        token: vscode.CancellationToken,
        userPrompt: string
    ): Promise<vscode.ChatResult> {
        const livePanel = LiveCaptureWebviewPanel.getActivePanel();
        const liveStatus = livePanel?.getStatusSnapshot();

        // Reliability fallback: if user explicitly asks to stop capture, do it directly.
        if (
            livePanel &&
            liveStatus?.hasSession &&
            this.isStopCaptureIntent(userPrompt) &&
            (liveStatus.sessionStatus === 'starting' || liveStatus.sessionStatus === 'capturing' || liveStatus.sessionStatus === 'stopping')
        ) {
            await vscode.commands.executeCommand('nettrace.stopLiveCapture');
            stream.markdown('⏹️ Stopping the live capture now. I will analyze once capture finalization completes.\n\n');
        }

        const agent = this.agentsTree.getActiveAgent();

        const systemPrompt = this.contextAssembler.buildSystemPromptPublic(agent);
        const scenarioContext = this.contextAssembler.buildScenarioContextPublic();

        const noCaptureNote = [
            '## No Capture Currently Open',
            '',
            'There is no network capture currently loaded in a viewer panel.',
            '',
            'Available actions:',
            '- Use `nettrace-startCapture` to open/start live capture (supports `durationSeconds` for auto-stop)',
            '- Use `nettrace-stopCapture` to stop an active live capture session',
            '- Use `nettrace-getLiveCaptureStatus` to check whether capture is running/stopping/stopped',
            '- Prompt the user to click a capture file in the **NetTrace** sidebar to open it',
            '- Prompt the user to run **NetTrace: Import Capture File** to load a .pcap/.pcapng file',
            '',
            'If the user asks to "capture for N seconds", call `nettrace-startCapture` with:',
            '- `autoStart: true`',
            '- `durationSeconds: N`',
            '',
            'If the user asks to stop capture now, call `nettrace-stopCapture`.',
            'If the user is asking to analyze an existing file, instruct them to open it first.',
        ].join('\n');

        const estimatedTokens =
            Math.ceil(systemPrompt.length / 4) +
            Math.ceil(scenarioContext.length / 4) +
            Math.ceil(noCaptureNote.length / 4);

        const assembledContext: import('../types').AssembledContext = {
            systemPrompt,
            captureSummary: noCaptureNote,
            streamDetails: '',
            scenarioContext,
            packetData: '',
            knowledgeContext: '',
            estimatedTokens,
            coverage: { mode: 'complete', totalPackets: 0, packetsIncluded: 0 },
        };

        return await this.sendToModel(
            request, chatContext, stream, token,
            assembledContext, userPrompt,
            /*captures=*/[], agent, /*isFirstTurn=*/true
        );
    }

    private async tryHandleFilterIntent(
        request: vscode.ChatRequest,
        chatContext: vscode.ChatContext,
        stream: vscode.ChatResponseStream,
        token: vscode.CancellationToken,
        userPrompt: string
    ): Promise<vscode.ChatResult | undefined> {
        if (!this.isDisplayFilterIntent(userPrompt)) {
            return undefined;
        }

        this.outputChannel.appendLine(`[ChatParticipant] Filter intent detected — using lightweight tool-only path`);
        stream.progress('Applying display filter...');

        const activeAgent = this.agentsTree.getActiveAgent();
        const filterAgent: AgentDefinition = {
            ...activeAgent,
            tools: ['nettrace-setDisplayFilter', 'nettrace-applyFilter'],
        };

        const filterModePrompt = [
            'You are handling a display-filter request for the active NetTrace capture panel.',
            'Do NOT analyze the whole capture and do NOT request full packet context.',
            'If the user wants to change what is shown in the viewer, call `nettrace-setDisplayFilter`.',
            'If the user explicitly asks for matching packets or filtered data returned in chat, call `nettrace-applyFilter` with `applyToPanel: true`.',
            'Translate natural-language requests into valid Wireshark display filter syntax when possible.',
            'After applying the filter, respond briefly with the filter that was used.',
        ].join('\n');

        const filterModeNote = [
            '## Filter Request Mode',
            '',
            'The user is asking to set or clear a Wireshark display filter in the active capture panel.',
            '',
            'Rules:',
            '- Prefer `nettrace-setDisplayFilter` for panel-only filter changes',
            '- Use `nettrace-applyFilter` only when the user explicitly wants filtered packet data back in chat',
            '- Do not load or summarize the whole trace for this request',
            '- If no capture panel is open, explain that clearly',
        ].join('\n');

        const estimatedTokens =
            Math.ceil(filterModePrompt.length / 4) +
            Math.ceil(filterModeNote.length / 4);

        const assembledContext: AssembledContext = {
            systemPrompt: filterModePrompt,
            captureSummary: filterModeNote,
            streamDetails: '',
            scenarioContext: '',
            packetData: '',
            knowledgeContext: '',
            estimatedTokens,
            coverage: { mode: 'complete', totalPackets: 0, packetsIncluded: 0 },
        };

        return await this.sendToModel(
            request,
            chatContext,
            stream,
            token,
            assembledContext,
            userPrompt,
            /*captures=*/[],
            filterAgent,
            /*isFirstTurn=*/true
        );
    }

    private isStopCaptureIntent(prompt: string): boolean {
        const p = prompt.toLowerCase();
        const asksToStop = /\b(stop|end|finish|terminate|halt)\b/.test(p);
        const captureContext = /\b(capture|capturing|trace|recording|sniff)\b/.test(p);
        return asksToStop && captureContext;
    }

    private isStartCaptureIntent(prompt: string): boolean {
        const p = prompt.toLowerCase();
        const asksToStart = /\b(start|begin|kick\s*off|initiate|run)\b/.test(p);
        const captureContext = /\b(capture|capturing|trace|recording|sniff)\b/.test(p);
        return asksToStart && captureContext;
    }

    private isStatusCaptureIntent(prompt: string): boolean {
        const p = prompt.toLowerCase();
        const asksStatus = /\b(status|progress|running|state|how\s+many\s+packets|how\s+long)\b/.test(p);
        const captureContext = /\b(capture|capturing|trace|recording|sniff)\b/.test(p);
        return asksStatus && captureContext;
    }

    private parseRequestedDurationSeconds(prompt: string): number | undefined {
        const p = prompt.toLowerCase();
        const m = p.match(/\b(?:for|after)\s+(\d+)\s*(seconds?|secs?|sec|minutes?|mins?|min|m|s)\b/);
        if (!m) {
            return undefined;
        }
        const value = Number.parseInt(m[1], 10);
        if (!Number.isFinite(value) || value <= 0) {
            return undefined;
        }
        const unit = m[2];
        if (unit.startsWith('m')) {
            return value * 60;
        }
        return value;
    }

    private isAnalyzeIntent(prompt: string): boolean {
        const p = prompt.toLowerCase();
        return /\b(analy[sz]e|analys[ei]s|anlysis|analzye|analize|diagnos[ei]s?|investigat(e|ion)|review|inspect|findings?|what'?s\s+wrong)\b/.test(p);
    }

    private async waitMs(ms: number, token: vscode.CancellationToken): Promise<boolean> {
        if (token.isCancellationRequested) {
            return false;
        }

        return await new Promise<boolean>((resolve) => {
            const timer = setTimeout(() => {
                disposable.dispose();
                resolve(true);
            }, ms);

            const disposable = token.onCancellationRequested(() => {
                clearTimeout(timer);
                disposable.dispose();
                resolve(false);
            });
        });
    }

    private async tryRunTimedCaptureAndAnalyzeWorkflow(
        prompt: string,
        stream: vscode.ChatResponseStream,
        token: vscode.CancellationToken
    ): Promise<{ captureFileOverride: string; analysisPrompt: string } | null | undefined> {
        const durationSeconds = this.parseRequestedDurationSeconds(prompt);
        const startIntent = this.isStartCaptureIntent(prompt);
        const analyzeIntent = this.isAnalyzeIntent(prompt);
        if (!startIntent || !analyzeIntent || !durationSeconds) {
            return undefined;
        }

        this.outputChannel.appendLine(`[ChatParticipant] Timed capture workflow: ${durationSeconds}s then analyze`);
        stream.progress(`Starting live capture for ${durationSeconds}s...`);

        await vscode.commands.executeCommand('nettrace.openLiveCapture', {
            autoStart: true,
            autoStopSeconds: durationSeconds,
            autoAnalyzeOnStop: false,
        });

        let status = LiveCaptureWebviewPanel.getActivePanel()?.getStatusSnapshot();
        let started = !!status?.hasSession && (status.sessionStatus === 'starting' || status.sessionStatus === 'capturing');

        for (let i = 0; i < 20 && !started; i++) {
            const ok = await this.waitMs(500, token);
            if (!ok) {
                stream.markdown('Capture request canceled before start completed.\n\n');
                return null;
            }
            status = LiveCaptureWebviewPanel.getActivePanel()?.getStatusSnapshot();
            started = !!status?.hasSession && (status.sessionStatus === 'starting' || status.sessionStatus === 'capturing');
        }

        if (!started) {
            stream.markdown('Could not confirm that live capture started.\n\n');
            return null;
        }

        for (let sec = 1; sec <= durationSeconds; sec++) {
            if (token.isCancellationRequested) {
                LiveCaptureWebviewPanel.getActivePanel()?.stopCapture();
                stream.markdown('Capture canceled. Sent stop signal.\n\n');
                return null;
            }

            status = LiveCaptureWebviewPanel.getActivePanel()?.getStatusSnapshot();
            const pktCount = status?.packetCount ?? 0;
            stream.progress(`Capturing... ${sec}/${durationSeconds}s (${pktCount.toLocaleString()} packets)`);

            const ok = await this.waitMs(1000, token);
            if (!ok) {
                LiveCaptureWebviewPanel.getActivePanel()?.stopCapture();
                stream.markdown('Capture canceled. Sent stop signal.\n\n');
                return null;
            }
        }

            stream.progress('Waiting for timed stop and capture finalization...');

        let captureFile = LiveCaptureWebviewPanel.getActiveCaptureFile();
        let stopped = false;

        for (let i = 0; i < 120; i++) {
            const ok = await this.waitMs(500, token);
            if (!ok) {
                stream.markdown('Canceled while waiting for capture finalization.\n\n');
                return null;
            }

            status = LiveCaptureWebviewPanel.getActivePanel()?.getStatusSnapshot();
            captureFile = status?.captureFile || captureFile;
            const state = status?.sessionStatus;
            if (state === 'stopped' || state === 'error') {
                stopped = true;
                break;
            }

            // The panel owns the primary timer-based stop. Only intervene if it
            // is still capturing shortly after the requested deadline.
            if (i === 2) {
                this.outputChannel.appendLine(
                    `[ChatParticipant] Timed stop has not completed yet: ` +
                    `status=${state ?? 'unknown'} — calling panel.stopCapture()`
                );
                const delayedPanel = LiveCaptureWebviewPanel.getActivePanel();
                if (delayedPanel) {
                    delayedPanel.stopCapture();
                } else {
                    await vscode.commands.executeCommand('nettrace.stopLiveCapture');
                }
            }

            if (i === 10) {
                this.outputChannel.appendLine(
                    `[ChatParticipant] Stop command has not completed yet: ` +
                    `status=${state ?? 'unknown'} — retrying nettrace.stopLiveCapture()`
                );
                const retryPanel = LiveCaptureWebviewPanel.getActivePanel();
                if (retryPanel) {
                    retryPanel.stopCapture();
                } else {
                    await vscode.commands.executeCommand('nettrace.stopLiveCapture');
                }
            }

            if (i === 20) {
                this.outputChannel.appendLine(
                    `[ChatParticipant] Stop command still has not completed: ` +
                    `status=${state ?? 'unknown'} — forcing stopAllLiveCaptures()`
                );
                this.tsharkRunner.stopAllLiveCaptures();
            }
        }

        if (!stopped) {
            stream.markdown(
                'Capture stop timed out while waiting for finalization. ' +
                'I sent a force-stop signal, but did not proceed to analysis to avoid reading a still-growing trace.\n\n'
            );
            return null;
        }

        if (!captureFile) {
            stream.markdown('Capture finalized but no output file path was resolved for analysis.\n\n');
            return null;
        }

        const lower = prompt.toLowerCase();
        const suspiciousIntent = /\b(suspicious|malicious|threat|beacon|c2|exfiltration|intrusion|attack)\b/.test(lower);
        const analysisPrompt = suspiciousIntent
            ? 'Analyze this capture for suspicious traffic, top risks, and supporting packet evidence.'
            : 'Analyze this capture and provide key findings, likely issues, and next steps.';

        return {
            captureFileOverride: captureFile,
            analysisPrompt,
        };
    }

    private async tryHandleCaptureControlIntent(
        prompt: string,
        stream: vscode.ChatResponseStream
    ): Promise<vscode.ChatResult | undefined> {
        const startIntent = this.isStartCaptureIntent(prompt);
        const stopIntent = this.isStopCaptureIntent(prompt);
        const statusIntent = this.isStatusCaptureIntent(prompt);
        const durationSeconds = this.parseRequestedDurationSeconds(prompt);
        const analyzeIntent = this.isAnalyzeIntent(prompt);

        // Start intent takes priority over stop intent for combined requests like:
        // "start capture for 1 minute, stop it, then analyze".
        if (startIntent) {
            const autoAnalyzeOnStop = !!durationSeconds && analyzeIntent;

            await vscode.commands.executeCommand('nettrace.openLiveCapture', {
                autoStart: true,
                autoStopSeconds: durationSeconds,
                autoAnalyzeOnStop,
            });

            const timerNote = durationSeconds
                ? ` Auto-stop timer set for **${durationSeconds}s**.`
                : '';
            const analyzeNote = autoAnalyzeOnStop
                ? ' I will automatically run analysis after the timer stop completes.'
                : ' I will not run analysis automatically unless you ask.';

            stream.markdown(
                `▶️ Started live capture.${timerNote}${analyzeNote}\n\n`
            );
            return { metadata: { command: 'capture-control' } };
        }

        // Stop intent: always honor immediately when live panel exists.
        if (stopIntent) {
            const panel = LiveCaptureWebviewPanel.getActivePanel();
            const status = panel?.getStatusSnapshot();
            if (!panel || !status?.hasSession) {
                stream.markdown('No live capture is active right now, so there is nothing to stop.\n\n');
                return { metadata: { command: 'capture-control' } };
            }

            await vscode.commands.executeCommand('nettrace.stopLiveCapture');
            stream.markdown('⏹️ Stop signal sent. Capture is being finalized now.\n\n');
            return { metadata: { command: 'capture-control' } };
        }

        // Status intent: return deterministic panel status without invoking the model.
        if (statusIntent) {
            const panel = LiveCaptureWebviewPanel.getActivePanel();
            const status = panel?.getStatusSnapshot();
            if (!panel || !status) {
                stream.markdown('No live capture panel is active.\n\n');
                return { metadata: { command: 'capture-control' } };
            }

            const fileLabel = status.captureFile ? `\`${path.basename(status.captureFile)}\`` : '(not written yet)';
            stream.markdown(
                `Live capture status: **${status.sessionStatus || 'idle'}**\n` +
                `- packets: **${status.packetCount.toLocaleString()}**\n` +
                `- elapsed: **${status.elapsedSeconds}s**\n` +
                `- file: ${fileLabel}\n\n`
            );
            return { metadata: { command: 'capture-control' } };
        }

        return undefined;
    }

    /**
     * Extract optional capture binding metadata from prompt text.
     * Marker format: [[nettrace:captureFile=<url-encoded-absolute-path>]]
     */
    private extractCaptureOverride(prompt: string): { prompt: string; captureFileOverride?: string } {
        const markerRe = /\[\[nettrace:captureFile=([^\]]+)\]\]/;
        const m = prompt.match(markerRe);
        if (!m) {
            return { prompt };
        }

        let decoded: string | undefined;
        try {
            decoded = decodeURIComponent(m[1]);
        } catch {
            decoded = m[1];
        }

        const cleanPrompt = prompt.replace(markerRe, '').replace(/\s{2,}/g, ' ').trim();
        return { prompt: cleanPrompt || 'Analyze this capture.', captureFileOverride: decoded };
    }

    // ─── Capture Selection ────────────────────────────────────────────────

    /**
     * Determine which captures to analyze.
     *
     * Single source of truth: CapturesTreeProvider.openInPanel tracks
     * which captures are open and in which panel type.
     *
     * Priority:
     * 1. Both client + server role captures assigned → dual-capture mode
     * 2. Unambiguous active capture (live > single viewer) from the tree
    * 3. Open panels fallback:
    *    - exactly 1 open panel  -> single-capture mode
    *    - exactly 2 open panels -> dual-capture mode
    *    - 3+ open panels        -> QuickPick (with safe fallback)
    * 4. Empty -> no-capture mode (handled by handleNoCaptureRequest)
     */
    private async getCapturesToAnalyze(captureFileOverride?: string): Promise<{ captures: CaptureFile[]; mode: 'single' | 'dual' }> {
        const allCaptures = this.capturesTree.getCaptures();

        // Explicit capture binding from panel-originated action always wins.
        if (captureFileOverride) {
            const bound = allCaptures.find(c => c.filePath === captureFileOverride);
            if (bound) {
                this.outputChannel.appendLine(`[ChatParticipant] Using bound capture from prompt: ${bound.filePath}`);
                return { captures: [bound], mode: 'single' };
            }

            this.outputChannel.appendLine(
                `[ChatParticipant] Bound capture not present in tree; synthesizing capture: ${captureFileOverride}`
            );
            return {
                captures: [{
                    filePath: captureFileOverride,
                    name: path.basename(captureFileOverride),
                    sizeBytes: 0,
                    parsed: false,
                    openInPanel: 'viewer',
                }],
                mode: 'single',
            };
        }

        const clientCapture = allCaptures.find(c => c.role === 'client');
        const serverCapture = allCaptures.find(c => c.role === 'server');

        // Dual-capture mode: both roles are explicitly assigned
        if (clientCapture && serverCapture) {
            return { captures: [clientCapture, serverCapture], mode: 'dual' };
        }

        const routing = resolveOpenCaptures(this.capturesTree, this.outputChannel, 'ChatParticipant');
        if (routing.activeCapture) {
            return { captures: [routing.activeCapture], mode: 'single' };
        }

        const openCaptures = routing.openCaptures;

        // Deterministic open-panel fallback: avoid dropping to no-capture when
        // captures are clearly open but no single panel is marked "active".
        if (openCaptures.length === 1) {
            const only = openCaptures[0];
            this.outputChannel.appendLine(`[ChatParticipant] Single open panel fallback: ${only.name}`);
            return { captures: [only], mode: 'single' };
        }

        if (openCaptures.length === 2) {
            this.outputChannel.appendLine(
                `[ChatParticipant] Two open panels fallback -> dual mode: ${openCaptures[0].name}, ${openCaptures[1].name}`
            );
            return { captures: [openCaptures[0], openCaptures[1]], mode: 'dual' };
        }

        // 3+ open captures but none unambiguous -> ask user which one.
        if (openCaptures.length > 2) {
            this.outputChannel.appendLine(
                `[ChatParticipant] ${openCaptures.length} captures open, none unambiguous — showing QuickPick`
            );
            type CapturePick = vscode.QuickPickItem & { filePath: string };
            const pick = await vscode.window.showQuickPick<CapturePick>(
                openCaptures.map(c => ({
                    label: c.name,
                    description: `${c.openInPanel === 'live' ? '⏺ live' : '👁 viewer'} — ${c.filePath}`,
                    filePath: c.filePath,
                })),
                {
                    placeHolder: 'Which capture should @nettrace analyze?',
                    title: 'NetTrace: Multiple captures are open — select one',
                }
            );
            if (!pick) {
                // Safe fallback: never degrade to no-capture when captures are open.
                this.outputChannel.appendLine(
                    `[ChatParticipant] QuickPick dismissed with ${openCaptures.length} open captures — using first open capture`
                );
                return { captures: [openCaptures[0]], mode: 'single' };
            }
            const chosen = allCaptures.find(c => c.filePath === pick.filePath);
            if (chosen) {
                this.outputChannel.appendLine(`[ChatParticipant] User chose: ${chosen.name}`);
                return { captures: [chosen], mode: 'single' };
            }
        }

        // No panel open — return empty so handleRequest delegates to handleNoCaptureRequest
        return { captures: [], mode: 'single' };
    }

    // ─── Followup Suggestions ─────────────────────────────────────────────

    private provideFollowups(
        result: vscode.ChatResult,
        context: vscode.ChatContext,
        token: vscode.CancellationToken
    ): vscode.ChatFollowup[] {
        if (result.metadata?.command === 'error' || result.metadata?.command === 'no-capture') {
            return [];
        }

        // Use the active agent's followups if defined, otherwise fall back to defaults
        const agent = this.agentsTree.getActiveAgent();
        if (agent.followups && agent.followups.length > 0) {
            return agent.followups.map(f => ({
                prompt: f.prompt,
                label: f.label,
                participant: 'nettrace.participant',
            }));
        }

        // Default followups when agent doesn't define any
        return [
            { prompt: 'Are there any retransmissions or packet loss?', label: 'Retransmissions', participant: 'nettrace.participant' },
            { prompt: 'Show me the expert info warnings and errors', label: 'Expert Info', participant: 'nettrace.participant' },
            { prompt: 'What are the top conversations by traffic volume?', label: 'Top Talkers', participant: 'nettrace.participant' },
            { prompt: 'Is there anything suspicious or abnormal?', label: 'Find Issues', participant: 'nettrace.participant' },
        ];
    }
}

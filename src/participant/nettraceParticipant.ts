import * as vscode from 'vscode';
import { TsharkRunner } from '../parsing/tsharkRunner';
import { ConfigLoader } from '../configLoader';
import { ContextAssembler } from '../contextAssembler';
import { CapturesTreeProvider } from '../views/capturesTreeProvider';
import { AgentsTreeProvider } from '../views/agentsTreeProvider';
import { StreamsTreeProvider } from '../views/streamsTreeProvider';
import { CaptureWebviewPanel } from '../views/captureWebviewPanel';
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

        // Gate: tshark must be available
        if (!this.tsharkRunner.isAvailable()) {
            stream.markdown('⚠️ **tshark is not available.** Install [Wireshark](https://www.wireshark.org/download.html) to enable capture analysis.\n\nAfter installing, restart VS Code.');
            return { metadata: { command: 'error' } };
        }

        // Determine which captures to analyze — dual-capture mode if both roles assigned
        const { captures: capturesToAnalyze, mode: captureMode } = this.getCapturesToAnalyze();

        if (capturesToAnalyze.length === 0) {
            stream.markdown(
                '📂 **No capture is open.**\n\n' +
                'To analyze a network trace:\n' +
                '1. Click on a capture file in the **NetTrace** sidebar\n' +
                '2. Or use **NetTrace: Import Capture File** to add one\n' +
                '3. The capture viewer will open — then come back here and ask your question\n\n' +
                'For **client/server dual-capture analysis**, right-click captures in the sidebar ' +
                'and choose **Set as Client Capture** / **Set as Server Capture**.'
            );
            stream.button({ command: 'nettrace.importCapture', title: '📂 Import Capture File' });
            return { metadata: { command: 'no-capture' } };
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
            const isFollowUp = context.history.length > 0;

            // Ensure all captures have been parsed before analysis
            for (const capture of capturesToAnalyze) {
                if (!capture.parsed || !capture.summary) {
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

                const lightweightTokens =
                    Math.ceil(systemPrompt.length / 4) +
                    Math.ceil(captureSummary.length / 4) +
                    Math.ceil(scenarioContext.length / 4) +
                    Math.ceil(knowledgeContext.length / 4);

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
                    capturesToAnalyze, captureStreams, agent, request.prompt, request.model
                );
            }

            return await this.sendToModel(request, context, stream, token, assembledContext, request.prompt, capturesToAnalyze, agent, !isFollowUp);
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
    private static readonly CHARS_PER_TOKEN = 4;

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

        // Build coverage string and stats line
        const pct = modelMax > 0 ? Math.round((context.estimatedTokens / modelMax) * 100) : 0;
        const coverageInfo = context.coverage
            ? context.coverage.mode === 'complete'
                ? `\u2705 All ${context.coverage.totalPackets.toLocaleString()} packets loaded`
                : `\ud83d\udcca Sampled ${context.coverage.packetsIncluded.toLocaleString()} of ${context.coverage.totalPackets.toLocaleString()} packets${(context.coverage.uncoveredRanges?.length || 0) > 0 ? ` \u00b7 AI will page through ${context.coverage.uncoveredRanges!.length} uncovered range${context.coverage.uncoveredRanges!.length > 1 ? 's' : ''} via tools` : ''}`
            : '';
        const captureLabel = captures.length > 1
            ? captures.map(c => `${c.name}${c.role ? ` [${c.role}]` : ''}`).join(' + ')
            : captures[0]?.name ?? 'unknown';
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
        // Some LLM APIs require alternating user/assistant messages and that
        // every tool_result has a matching tool_use in the immediately preceding
        // assistant message. We consolidate all initial context into a SINGLE user
        // message to avoid consecutive same-role messages that the proxy may
        // merge unpredictably.

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

        const messages: vscode.LanguageModelChatMessage[] = [
            vscode.LanguageModelChatMessage.User(contextParts.join('\n\n---\n\n')),
        ];

        // Conversation history for multi-turn
        // Only extract text content — drop any tool_use/tool_result artifacts
        // from previous turns to prevent orphaned tool blocks in the API request.
        for (const turn of chatContext.history) {
            if (turn instanceof vscode.ChatRequestTurn) {
                messages.push(vscode.LanguageModelChatMessage.User(turn.prompt));
                // Ensure alternation: if next turn is also User, insert a placeholder Assistant
            } else if (turn instanceof vscode.ChatResponseTurn) {
                let responseText = '';
                for (const part of turn.response) {
                    if (part instanceof vscode.ChatResponseMarkdownPart) {
                        responseText += part.value.value;
                    }
                }
                if (responseText) {
                    messages.push(vscode.LanguageModelChatMessage.Assistant(responseText));
                }
            }
        }

        // Ensure the last message before the user's prompt is not also User role
        // (would happen if history had a request with no captured response)
        const lastMsg = messages[messages.length - 1];
        const lastIsUser = lastMsg && (lastMsg.role === vscode.LanguageModelChatMessageRole.User);
        if (lastIsUser && chatContext.history.length > 0) {
            // Insert a minimal assistant acknowledgment to maintain alternation
            messages.push(vscode.LanguageModelChatMessage.Assistant('Understood. What would you like me to analyze?'));
        }

        messages.push(vscode.LanguageModelChatMessage.User(userMessage));

        const toolNames = this.agentsTree.getActiveAgent().tools || [];
        // Always include nettrace-startCapture so the LLM can start/set up a live
        // capture regardless of which analysis agent is active.
        const allToolNames = toolNames.includes('nettrace-startCapture')
            ? toolNames
            : [...toolNames, 'nettrace-startCapture'];
        const tools = this.resolveTools(allToolNames);

        // Log message structure for debugging API errors
        this.outputChannel.appendLine(`[ChatParticipant] Message structure (${messages.length} messages):`);
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
        // Use the same 10% reserve the context assembler used — NOT an additional 15%.
        // The assembler already budgeted within (maxTokens * 0.9), so we honor that boundary
        // and only need a small additional margin for tool responses accumulating.
        const tokenLimit = Math.floor(modelMax * 0.95); // 5% reserve for tool overhead; assembler already reserved 10%
        let roundTrip = 0;

        while (roundTrip < NetTraceParticipant.MAX_TOOL_ROUNDTRIPS) {
            roundTrip++;
            if (token.isCancellationRequested) { break; }

            // Pre-flight check: estimate total tokens before sending
            const estimatedTokens = this.estimateMessageTokens(messages);
            const remainingBudget = tokenLimit - estimatedTokens;

            // On the FIRST roundtrip, always send with tools — the model needs them
            // to analyze the capture even if the context is large. The budget-cap
            // path should only trigger on subsequent roundtrips after tool results
            // have accumulated and genuinely exhausted the budget.
            if (remainingBudget < 20000 && roundTrip > 1) {
                // Less than ~20K tokens left — not enough for a useful tool response.
                // Tell the model to wrap up with what it has.
                this.outputChannel.appendLine(
                    `[ChatParticipant] Token budget nearly exhausted (~${estimatedTokens} tokens used, limit ${tokenLimit}). ` +
                    `Sending final request without tools.`
                );
                stream.markdown('\n\n*Context limit approaching — finalizing analysis with data gathered so far.*\n\n');

                // Send one final request WITHOUT tools so the model wraps up
                const finalResponse = await model.sendRequest(messages, {}, token);
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

            let chatResponse;
            try {
                chatResponse = await model.sendRequest(messages, { tools }, token);
            } catch (sendError: any) {
                // If we get a 400 error (often tool_use/tool_result mismatch),
                // retry WITHOUT tools as a fallback so the user still gets analysis
                const errMsg = sendError?.message || String(sendError);
                if (errMsg.includes('400') || errMsg.includes('invalid_request_error') || errMsg.includes('tool_use_id')) {
                    this.outputChannel.appendLine(
                        `[ChatParticipant] Tool-related API error: ${errMsg}. Retrying without tools.`
                    );
                    stream.markdown('\n\n*Tool calling encountered an API error — analyzing without tools.*\n\n');
                    const fallbackResponse = await model.sendRequest(messages.filter(m => {
                        // Strip any messages containing tool result/call parts
                        if (!Array.isArray(m.content)) { return true; }
                        return !m.content.some(p =>
                            p instanceof vscode.LanguageModelToolResultPart ||
                            p instanceof vscode.LanguageModelToolCallPart
                        );
                    }), {}, token);
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

    // ─── Capture Selection ────────────────────────────────────────────────

    /**
     * Determine which captures to analyze.
     *
     * Priority:
     * 1. Both client + server role captures assigned → dual-capture mode
     * 2. Active webview panel capture → single mode
     * 3. First capture in tree → fallback single mode
     *
     * This is fully backward-compatible: if only one capture is open (or no
     * role tags are set), the returned array has exactly one element and the
     * rest of the flow is identical to the previous single-capture behavior.
     */
    private getCapturesToAnalyze(): { captures: CaptureFile[]; mode: 'single' | 'dual' } {
        const allCaptures = this.capturesTree.getCaptures();
        const clientCapture = allCaptures.find(c => c.role === 'client');
        const serverCapture = allCaptures.find(c => c.role === 'server');

        // Dual-capture mode: both roles are explicitly assigned
        if (clientCapture && serverCapture) {
            return { captures: [clientCapture, serverCapture], mode: 'dual' };
        }

        // Single mode: use whichever panel is currently focused in the viewer
        const activePath = CaptureWebviewPanel.getActiveCaptureFile();
        const activeCapture = activePath ? allCaptures.find(c => c.filePath === activePath) : undefined;
        if (activeCapture) {
            return { captures: [activeCapture], mode: 'single' };
        }

        // Final fallback: first capture in tree (matches original behavior)
        if (allCaptures.length > 0) {
            return { captures: [allCaptures[0]], mode: 'single' };
        }

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

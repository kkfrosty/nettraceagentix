import * as vscode from 'vscode';
import { TsharkRunner } from '../parsing/tsharkRunner';
import { CapturesTreeProvider } from '../views/capturesTreeProvider';
import { CaptureWebviewPanel } from '../views/captureWebviewPanel';
import { ConfigLoader } from '../configLoader';

/**
 * Registers Language Model Tools that the LLM can call during analysis.
 * These tools let the model autonomously drill into specific aspects of the capture.
 *
 * IMPORTANT: All tool responses are capped to prevent exceeding the model's context window.
 * The initial context (packets + streams + knowledge) already consumes a large portion of
 * the budget. Tool responses accumulate in the conversation, so each must be compact.
 */

// Max characters per tool response (~25K tokens). Keeps room for multiple tool calls.
const MAX_TOOL_RESPONSE_CHARS = 100000;

function truncateResponse(text: string, label: string): string {
    if (text.length <= MAX_TOOL_RESPONSE_CHARS) { return text; }
    const truncated = text.substring(0, MAX_TOOL_RESPONSE_CHARS);
    return truncated + `\n\n... (${label} truncated — ${text.length} chars total, showing first ${MAX_TOOL_RESPONSE_CHARS}. Use more specific filters or smaller ranges to see the rest.)`;
}

export function registerLMTools(
    context: vscode.ExtensionContext,
    tsharkRunner: TsharkRunner,
    capturesTree: CapturesTreeProvider,
    configLoader: ConfigLoader,
    outputChannel: vscode.OutputChannel
): void {

    // ─── Get Stream Detail ────────────────────────────────────────────────
    context.subscriptions.push(
        vscode.lm.registerTool('nettrace-getStreamDetail', {
            async invoke(options: vscode.LanguageModelToolInvocationOptions<{ streamIndex: number; captureFile?: string }>, token) {
                const { streamIndex, captureFile } = options.input;
                const file = captureFile || getDefaultCaptureFile(capturesTree, outputChannel);

                if (!file) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart('Error: No capture file available. The user must open a .pcap/.pcapng/.pcpap file first.')
                    ]);
                }

                outputChannel.appendLine(`[Tool] getStreamDetail: stream=${streamIndex}, file=${file}`);

                try {
                    const detail = await tsharkRunner.getStreamDetail(file, streamIndex);
                    const response = truncateResponse(detail, 'stream detail');
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(`TCP Stream ${streamIndex} packet details:\n\`\`\`\n${response}\n\`\`\``)
                    ]);
                } catch (e) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(`Error retrieving stream ${streamIndex}: ${e}`)
                    ]);
                }
            }
        })
    );

    // ─── Get Packet Range ─────────────────────────────────────────────────
    context.subscriptions.push(
        vscode.lm.registerTool('nettrace-getPacketRange', {
            async invoke(options: vscode.LanguageModelToolInvocationOptions<{ startFrame: number; endFrame: number; filter?: string; captureFile?: string }>, token) {
                const { startFrame, endFrame, filter, captureFile } = options.input;
                const file = captureFile || getDefaultCaptureFile(capturesTree, outputChannel);

                if (!file) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart('Error: No capture file available. The user must open a .pcap/.pcapng/.pcpap file first.')
                    ]);
                }

                // Clamp range to prevent accidentally fetching huge ranges
                const maxRange = 500;
                const clampedEnd = Math.min(endFrame, startFrame + maxRange - 1);
                if (endFrame > clampedEnd) {
                    outputChannel.appendLine(`[Tool] getPacketRange: clamped range from ${startFrame}-${endFrame} to ${startFrame}-${clampedEnd} (max ${maxRange})`);
                }

                outputChannel.appendLine(`[Tool] getPacketRange: frames ${startFrame}-${clampedEnd}${filter ? `, filter="${filter}"` : ''}, file=${file}`);

                try {
                    const packets = await tsharkRunner.getPacketRange(file, startFrame, clampedEnd, filter);
                    const response = truncateResponse(packets, 'packet range');
                    const lineCount = response.trim().split('\n').filter(l => l.trim()).length;
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(
                            `Packets ${startFrame}-${clampedEnd}${filter ? ` (filter: ${filter})` : ''} (${lineCount} lines):\n\`\`\`\n${response}\n\`\`\``
                        )
                    ]);
                } catch (e) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(`Error retrieving packet range ${startFrame}-${clampedEnd}: ${e}`)
                    ]);
                }
            }
        })
    );

    // ─── Get Expert Info ──────────────────────────────────────────────────
    context.subscriptions.push(
        vscode.lm.registerTool('nettrace-getExpertInfo', {
            async invoke(options: vscode.LanguageModelToolInvocationOptions<{ captureFile?: string; severity?: string }>, token) {
                const { captureFile, severity } = options.input;
                const file = captureFile || getDefaultCaptureFile(capturesTree, outputChannel);

                if (!file) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart('Error: No capture file available. The user must open a .pcap/.pcapng/.pcpap file first.')
                    ]);
                }

                outputChannel.appendLine(`[Tool] getExpertInfo: severity=${severity || 'all'}, file=${file}`);

                try {
                    const info = await tsharkRunner.getExpertInfo(file, severity);
                    // Expert info can be massive — cap it hard
                    const response = truncateResponse(info, 'expert info');
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(`Wireshark Expert Info:\n\`\`\`\n${response}\n\`\`\``)
                    ]);
                } catch (e) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(`Error retrieving expert info: ${e}`)
                    ]);
                }
            }
        })
    );

    // ─── Apply Display Filter ─────────────────────────────────────────────
    context.subscriptions.push(
        vscode.lm.registerTool('nettrace-applyFilter', {
            async invoke(options: vscode.LanguageModelToolInvocationOptions<{ filter: string; captureFile?: string; maxPackets?: number; applyToPanel?: boolean }>, token) {
                const { filter, captureFile, maxPackets, applyToPanel } = options.input;
                const file = captureFile || getDefaultCaptureFile(capturesTree, outputChannel);

                if (!file) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart('Error: No capture file available. The user must open a .pcap/.pcapng/.pcpap file first.')
                    ]);
                }

                outputChannel.appendLine(`[Tool] applyFilter: filter="${filter}", max=${maxPackets || 100}, applyToPanel=${applyToPanel !== false}, file=${file}`);

                // ALWAYS push filter to the capture viewer panel FIRST so the user
                // sees the filter change immediately, even if the tshark data query
                // takes time or fails.
                if (applyToPanel !== false) {
                    try {
                        CaptureWebviewPanel.applyFilterToActive(filter);
                        outputChannel.appendLine(`[Tool] applyFilter: pushed filter "${filter}" to capture viewer panel`);
                    } catch (panelErr) {
                        outputChannel.appendLine(`[Tool] applyFilter: panel update failed (non-fatal): ${panelErr}`);
                    }
                }

                try {
                    const result = await tsharkRunner.applyFilter(file, filter, maxPackets || 100);

                    // Handle empty results gracefully — this is NOT an error
                    const trimmed = result.trim();
                    if (!trimmed || trimmed.split('\n').filter(l => l.trim()).length <= 1) {
                        // Only header row or empty — no matching packets
                        return new vscode.LanguageModelToolResult([
                            new vscode.LanguageModelTextPart(
                                `Filter "${filter}" applied successfully${applyToPanel !== false ? ' (viewer panel updated)' : ''}.\n` +
                                `Result: 0 packets matched this filter in the capture. ` +
                                `This means no packets in the capture match the Wireshark display filter "${filter}". ` +
                                `Try a broader filter or check available protocols with nettrace-runTshark using "-q -z io,phs".`
                            )
                        ]);
                    }

                    const lineCount = trimmed.split('\n').filter(l => l.trim()).length - 1; // minus header
                    const response = truncateResponse(result, 'filter results');
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(
                            `Filter "${filter}" applied successfully${applyToPanel !== false ? ' (viewer panel updated)' : ''} — ${lineCount} matching packets:\n\`\`\`\n${response}\n\`\`\``
                        )
                    ]);
                } catch (e) {
                    // Even on tshark error, the panel filter was already updated above
                    const errMsg = String(e);
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(
                            `Filter "${filter}" was applied to the viewer panel${applyToPanel !== false ? '' : ' (panel update skipped)'}.\n` +
                            `However, tshark returned an error when extracting data: ${errMsg}\n` +
                            `This usually means the filter syntax is invalid. Use standard Wireshark display filter syntax ` +
                            `(e.g., "dns", "tcp.port == 443", "http", "ip.addr == 10.0.0.1").`
                        )
                    ]);
                }
            }
        })
    );

    // ─── Get Conversations ────────────────────────────────────────────────
    context.subscriptions.push(
        vscode.lm.registerTool('nettrace-getConversations', {
            async invoke(options: vscode.LanguageModelToolInvocationOptions<{ protocol?: string; captureFile?: string }>, token) {
                const { protocol, captureFile } = options.input;
                const file = captureFile || getDefaultCaptureFile(capturesTree, outputChannel);

                if (!file) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart('Error: No capture file available. The user must open a .pcap/.pcapng/.pcpap file first.')
                    ]);
                }

                const proto = (protocol as any) || 'tcp';
                outputChannel.appendLine(`[Tool] getConversations: protocol=${proto}, file=${file}`);

                try {
                    const convs = await tsharkRunner.getConversations(file, proto);

                    if (!convs || convs.length === 0) {
                        return new vscode.LanguageModelToolResult([
                            new vscode.LanguageModelTextPart(
                                `${proto.toUpperCase()} Conversations: 0 found.\n` +
                                `The capture file contains no ${proto.toUpperCase()} conversations. ` +
                                `Try a different protocol (tcp, udp, ip) or check if the capture has the expected traffic.`
                            )
                        ]);
                    }

                    let text = `${proto.toUpperCase()} Conversations (${convs.length} total):\n\n`;
                    for (const conv of convs) {
                        const anomalyText = conv.anomalies.length > 0
                            ? ` ⚠️ [${conv.anomalies.map((a: any) => a.type).join(', ')}]`
                            : ' ✓';
                        text += `Stream ${conv.index}: ${conv.source} ↔ ${conv.destination} | ${conv.packetCount} pkts | ${conv.totalBytes} bytes | ${conv.durationSeconds.toFixed(2)}s${anomalyText}\n`;
                    }
                    const response = truncateResponse(text, 'conversations');
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(response)
                    ]);
                } catch (e) {
                    const errMsg = String(e);
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(
                            `Error retrieving ${proto.toUpperCase()} conversations: ${errMsg}\n` +
                            `This may happen if tshark cannot parse the capture file or the protocol layer is not present. ` +
                            `Try protocol "ip" for a broader view.`
                        )
                    ]);
                }
            }
        })
    );

    // ─── Follow TCP Stream ────────────────────────────────────────────────
    context.subscriptions.push(
        vscode.lm.registerTool('nettrace-followStream', {
            async invoke(options: vscode.LanguageModelToolInvocationOptions<{ streamIndex: number; format?: string; captureFile?: string }>, token) {
                const { streamIndex, format, captureFile } = options.input;
                const file = captureFile || getDefaultCaptureFile(capturesTree, outputChannel);

                if (!file) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart('Error: No capture file available. The user must open a .pcap/.pcapng/.pcpap file first.')
                    ]);
                }

                outputChannel.appendLine(`[Tool] followStream: stream=${streamIndex}, format=${format || 'ascii'}, file=${file}`);

                try {
                    const data = await tsharkRunner.followStream(file, streamIndex, (format as any) || 'ascii');
                    const response = truncateResponse(data, 'stream data');
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(`Reconstructed data for TCP stream ${streamIndex}:\n\`\`\`\n${response}\n\`\`\``)
                    ]);
                } catch (e) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(`Error following stream ${streamIndex}: ${e}`)
                    ]);
                }
            }
        })
    );

    // ─── Compare Captures ─────────────────────────────────────────────────
    context.subscriptions.push(
        vscode.lm.registerTool('nettrace-compareCaptures', {
            async invoke(options: vscode.LanguageModelToolInvocationOptions<{ clientCapture: string; serverCapture: string; filterExpression?: string }>, token) {
                const { clientCapture, serverCapture, filterExpression } = options.input;

                outputChannel.appendLine(`[Tool] compareCaptures: client=${clientCapture}, server=${serverCapture}`);

                try {
                    // Get conversations from both sides
                    const [clientConvs, serverConvs] = await Promise.all([
                        tsharkRunner.getConversations(clientCapture),
                        tsharkRunner.getConversations(serverCapture),
                    ]);

                    // Get expert info summary counts only (not full detail) from both
                    const [clientSummary, serverSummary] = await Promise.all([
                        tsharkRunner.getCaptureSummary(clientCapture),
                        tsharkRunner.getCaptureSummary(serverCapture),
                    ]);

                    let text = `## Capture Comparison\n\n`;
                    text += `### Client Capture: ${clientConvs.length} streams`;
                    if (clientSummary.expertInfo) {
                        text += ` | Expert: ${clientSummary.expertInfo.errors} errors, ${clientSummary.expertInfo.warnings} warnings`;
                    }
                    text += `\n`;
                    text += `### Server Capture: ${serverConvs.length} streams`;
                    if (serverSummary.expertInfo) {
                        text += ` | Expert: ${serverSummary.expertInfo.errors} errors, ${serverSummary.expertInfo.warnings} warnings`;
                    }
                    text += `\n\n`;

                    // Basic stream count comparison
                    if (clientConvs.length !== serverConvs.length) {
                        text += `⚠️ **Stream count mismatch**: Client has ${clientConvs.length} streams, Server has ${serverConvs.length}. This may indicate dropped connections.\n\n`;
                    }

                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(text)
                    ]);
                } catch (e) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(`Error comparing captures: ${e}`)
                    ]);
                }
            }
        })
    );

    // ─── Set Display Filter in Viewer ─────────────────────────────────────
    context.subscriptions.push(
        vscode.lm.registerTool('nettrace-setDisplayFilter', {
            async invoke(options: vscode.LanguageModelToolInvocationOptions<{ filter: string }>, token) {
                const { filter } = options.input;

                outputChannel.appendLine(`[Tool] setDisplayFilter: filter="${filter}"`);

                try {
                    // Check if any panel exists to receive the filter
                    const hasActivePanel = CaptureWebviewPanel.getActiveCaptureFile() !== undefined;
                    CaptureWebviewPanel.applyFilterToActive(filter);

                    if (!hasActivePanel) {
                        return new vscode.LanguageModelToolResult([
                            new vscode.LanguageModelTextPart(
                                `Note: No Capture Viewer panel is currently open. The filter "${filter}" was set but may not be visible. ` +
                                `Ask the user to open a capture file in the viewer first.`
                            )
                        ]);
                    }

                    const message = filter
                        ? `Display filter "${filter}" has been applied to the capture viewer panel. ` +
                          `The user can now see only packets matching this Wireshark display filter. ` +
                          `The filter bar in the viewer shows "${filter}".`
                        : `Display filter cleared. The capture viewer panel now shows all packets.`;

                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(message)
                    ]);
                } catch (e) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(`Error setting display filter: ${e}`)
                    ]);
                }
            }
        })
    );

    // ─── Run Custom Tshark Command ────────────────────────────────────────
    // Safety: blocks write operations (-w), pipe/shell metacharacters, and enforces timeout.
    const BLOCKED_FLAGS = ['-w', '--write', '-F', '--export-objects', '--export-tls-session-keys'];
    const SHELL_METACHARACTERS = /[|;&`$(){}><\n\r]/;

    context.subscriptions.push(
        vscode.lm.registerTool('nettrace-runTshark', {
            async invoke(options: vscode.LanguageModelToolInvocationOptions<{ args: string; captureFile?: string; applyToPanel?: boolean }>, token) {
                const { args, captureFile, applyToPanel } = options.input;
                const file = captureFile || getDefaultCaptureFile(capturesTree, outputChannel);

                if (!file) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart('Error: No capture file available. The user must open a .pcap/.pcapng/.pcpap file first.')
                    ]);
                }

                // Safety: check for blocked flags and shell metacharacters
                if (SHELL_METACHARACTERS.test(args)) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart('Error: Shell metacharacters (|, ;, &, `, $, etc.) are not allowed in tshark arguments for safety.')
                    ]);
                }

                const argsList = args.split(/\s+/).filter(a => a.length > 0);
                for (const blocked of BLOCKED_FLAGS) {
                    if (argsList.some(a => a.toLowerCase() === blocked.toLowerCase())) {
                        return new vscode.LanguageModelToolResult([
                            new vscode.LanguageModelTextPart(`Error: The "${blocked}" flag is blocked for safety. Only read-only tshark operations are allowed.`)
                        ]);
                    }
                }

                // Don't allow -r in args — we provide it automatically
                const filteredArgs = argsList.filter(a => a !== '-r');

                outputChannel.appendLine(`[Tool] runTshark: args="${filteredArgs.join(' ')}", file=${file}`);

                try {
                    const result = await tsharkRunner.runCustomCommand(file, filteredArgs);

                    // Auto-push -Y display filter to the viewer panel (default: true)
                    // This ensures whatever filter the model uses via runTshark also
                    // updates the user's capture viewer, keeping the UI in sync.
                    let appliedFilter: string | undefined;
                    if (applyToPanel !== false) {
                        const yIndex = filteredArgs.findIndex(a => a === '-Y');
                        if (yIndex !== -1 && yIndex + 1 < filteredArgs.length) {
                            appliedFilter = filteredArgs[yIndex + 1];
                            try {
                                CaptureWebviewPanel.applyFilterToActive(appliedFilter);
                                outputChannel.appendLine(`[Tool] runTshark: pushed -Y filter "${appliedFilter}" to capture viewer panel`);
                            } catch (panelErr) {
                                outputChannel.appendLine(`[Tool] runTshark: panel update failed (non-fatal): ${panelErr}`);
                            }
                        }
                    }

                    const response = truncateResponse(result, 'tshark output');
                    const panelNote = appliedFilter ? ` (viewer panel filter updated to "${appliedFilter}")` : '';
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(`tshark output${panelNote}:\n\`\`\`\n${response}\n\`\`\``)
                    ]);
                } catch (e) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(`Error running tshark command: ${e}`)
                    ]);
                }
            }
        })
    );

    // ─── Create Analysis Agent ────────────────────────────────────────────
    context.subscriptions.push(
        vscode.lm.registerTool('nettrace-createAgent', {
            async invoke(options: vscode.LanguageModelToolInvocationOptions<{
                name: string;
                displayName: string;
                description?: string;
                systemPrompt: string;
                displayFilter?: string;
                tools?: string[];
                followups?: Array<{ label: string; prompt: string }>;
            }>, token) {
                const { name, displayName, description, systemPrompt, displayFilter, tools, followups } = options.input;

                // Validate name format
                if (!/^[a-z0-9-]+$/.test(name)) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart('Error: Agent name must be lowercase letters, numbers, and hyphens only.')
                    ]);
                }

                const toolRootUri = configLoader.getRootUri();

                outputChannel.appendLine(`[Tool] createAgent: name="${name}", displayName="${displayName}"`);

                try {
                    // Ensure .nettrace/agents/ directory exists
                    const agentsDir = vscode.Uri.joinPath(toolRootUri, '.nettrace', 'agents');
                    try { await vscode.workspace.fs.createDirectory(agentsDir); } catch { /* already exists */ }

                    const agentDef: any = {
                        name,
                        displayName,
                        description: description || `Specialized agent for ${displayName} analysis`,
                        icon: 'robot',
                        systemPrompt,
                        tools: tools || [
                            'nettrace-getStreamDetail',
                            'nettrace-getPacketRange',
                            'nettrace-applyFilter',
                            'nettrace-getConversations',
                            'nettrace-followStream',
                            'nettrace-setDisplayFilter',
                            'nettrace-runTshark',
                        ],
                        followups: followups || [],
                    };

                    if (displayFilter) {
                        agentDef.autoFilters = { displayFilter };
                    }

                    const fileUri = vscode.Uri.joinPath(agentsDir, `${name}.json`);
                    const content = Buffer.from(JSON.stringify(agentDef, null, 2));
                    await vscode.workspace.fs.writeFile(fileUri, content);

                    // Config loader will auto-detect via file watcher
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(
                            `✅ Agent "${displayName}" created at .nettrace/agents/${name}.json\n\n` +
                            `The agent is now available in the Analysis Agents sidebar. Click it to activate.\n` +
                            `You can edit the JSON file to fine-tune the prompt, tools, and filters.`
                        )
                    ]);
                } catch (e) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(`Error creating agent: ${e}`)
                    ]);
                }
            }
        })
    );

    // ─── Create Knowledge File ────────────────────────────────────────────
    context.subscriptions.push(
        vscode.lm.registerTool('nettrace-createKnowledge', {
            async invoke(options: vscode.LanguageModelToolInvocationOptions<{
                category: 'wisdom' | 'security' | 'known-issues';
                filename: string;
                content: string;
            }>, token) {
                const { category, filename, content } = options.input;

                // Validate filename format
                if (!/^[a-z0-9-]+$/.test(filename)) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart('Error: Filename must be lowercase letters, numbers, and hyphens only (no extension).')
                    ]);
                }

                const validCategories = ['wisdom', 'security', 'known-issues'];
                if (!validCategories.includes(category)) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(`Error: Category must be one of: ${validCategories.join(', ')}`)
                    ]);
                }

                const toolRootUri = configLoader.getRootUri();

                outputChannel.appendLine(`[Tool] createKnowledge: category="${category}", filename="${filename}"`);

                try {
                    const categoryDir = vscode.Uri.joinPath(toolRootUri, '.nettrace', 'knowledge', category);
                    try { await vscode.workspace.fs.createDirectory(categoryDir); } catch { /* already exists */ }

                    const fileUri = vscode.Uri.joinPath(categoryDir, `${filename}.md`);
                    await vscode.workspace.fs.writeFile(fileUri, Buffer.from(content));

                    const categoryLabels: Record<string, string> = {
                        'wisdom': 'Analysis Guidance (always applied)',
                        'security': 'Security Heuristics (conditional)',
                        'known-issues': 'Known Issues (always applied)',
                    };

                    // Config loader will auto-detect via file watcher
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(
                            `✅ Knowledge file created at .nettrace/knowledge/${category}/${filename}.md\n\n` +
                            `**Category:** ${categoryLabels[category]}\n` +
                            `This knowledge will be injected into the AI's context on the next analysis.\n` +
                            `Edit the file in the Knowledge sidebar to refine it.`
                        )
                    ]);
                } catch (e) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(`Error creating knowledge file: ${e}`)
                    ]);
                }
            }
        })
    );
}

/**
 * Get the capture file to analyze.
 * Priority: 1) Active webview panel (the capture the user is looking at)
 *           2) First capture in the tree (fallback)
 */
function getDefaultCaptureFile(capturesTree: CapturesTreeProvider, outputChannel: vscode.OutputChannel): string | undefined {
    // 1. Always prefer the capture visible in the active viewer panel
    const activeFile = CaptureWebviewPanel.getActiveCaptureFile();
    if (activeFile) {
        outputChannel.appendLine(`[Tool] Using active viewer capture: ${activeFile}`);
        return activeFile;
    }

    const captures = capturesTree.getCaptures();

    // 2. In dual-capture mode with no active panel, default to the client-role capture
    const clientCapture = captures.find(c => c.role === 'client');
    if (clientCapture) {
        outputChannel.appendLine(`[Tool] No active viewer — using client-role capture: ${clientCapture.filePath}`);
        return clientCapture.filePath;
    }

    // 3. Final fallback: first capture in tree
    if (captures.length > 0) {
        outputChannel.appendLine(`[Tool] No active viewer — falling back to first capture: ${captures[0].filePath}`);
        return captures[0].filePath;
    }

    outputChannel.appendLine(`[Tool] No capture file available`);
    return undefined;
}

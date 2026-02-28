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
                        new vscode.LanguageModelTextPart('Error: No capture file available.')
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
                        new vscode.LanguageModelTextPart('Error: No capture file available.')
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
                        new vscode.LanguageModelTextPart('Error: No capture file available.')
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
            async invoke(options: vscode.LanguageModelToolInvocationOptions<{ filter: string; captureFile?: string; maxPackets?: number }>, token) {
                const { filter, captureFile, maxPackets } = options.input;
                const file = captureFile || getDefaultCaptureFile(capturesTree, outputChannel);

                if (!file) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart('Error: No capture file available.')
                    ]);
                }

                outputChannel.appendLine(`[Tool] applyFilter: filter="${filter}", max=${maxPackets || 100}, file=${file}`);

                try {
                    const result = await tsharkRunner.applyFilter(file, filter, maxPackets || 100);
                    const response = truncateResponse(result, 'filter results');
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(`Packets matching "${filter}":\n\`\`\`\n${response}\n\`\`\``)
                    ]);
                } catch (e) {
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(`Error applying filter "${filter}": ${e}`)
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
                        new vscode.LanguageModelTextPart('Error: No capture file available.')
                    ]);
                }

                outputChannel.appendLine(`[Tool] getConversations: protocol=${protocol || 'tcp'}, file=${file}`);

                try {
                    const convs = await tsharkRunner.getConversations(file, (protocol as any) || 'tcp');
                    let text = `${(protocol || 'TCP').toUpperCase()} Conversations (${convs.length} total):\n\n`;
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
                    return new vscode.LanguageModelToolResult([
                        new vscode.LanguageModelTextPart(`Error getting conversations: ${e}`)
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
                        new vscode.LanguageModelTextPart('Error: No capture file available.')
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
}

/**
 * Get the capture file to analyze.
 * Priority: 1) Active webview panel (the capture the user is looking at)
 *           2) First capture in the tree (fallback)
 */
function getDefaultCaptureFile(capturesTree: CapturesTreeProvider, outputChannel: vscode.OutputChannel): string | undefined {
    // Always prefer the capture that's open in the viewer
    const activeFile = CaptureWebviewPanel.getActiveCaptureFile();
    if (activeFile) {
        outputChannel.appendLine(`[Tool] Using active viewer capture: ${activeFile}`);
        return activeFile;
    }
    // Fallback to first capture in tree
    const captures = capturesTree.getCaptures();
    if (captures.length > 0) {
        outputChannel.appendLine(`[Tool] No active viewer — falling back to first capture: ${captures[0].filePath}`);
        return captures[0].filePath;
    }
    outputChannel.appendLine(`[Tool] No capture file available`);
    return undefined;
}

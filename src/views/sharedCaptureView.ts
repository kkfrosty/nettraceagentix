import * as vscode from 'vscode';
import { TsharkRunner } from '../parsing/tsharkRunner';

export interface ParsedPacketRow {
    number: number;
    time: string;
    source: string;
    destination: string;
    protocol: string;
    length: number;
    info: string;
    stream: string;
}

export interface ProtoTreeNode {
    name: string;
    showname: string;
    children: ProtoTreeNode[];
}

interface PacketDetailLoaderOptions {
    tsharkRunner: Pick<TsharkRunner, 'getPacketDetail' | 'getPacketDetailPdml'>;
    captureFile: string;
    frameNumber: number;
    postMessage: (message: object) => void;
    outputChannel?: vscode.OutputChannel;
    logPrefix: string;
    preferredFormat: 'verbose' | 'pdml';
}

interface PacketHexLoaderOptions {
    tsharkRunner: Pick<TsharkRunner, 'getPacketHexDump'>;
    captureFile: string;
    frameNumber: number;
    postMessage: (message: object) => void;
    outputChannel?: vscode.OutputChannel;
    logPrefix: string;
}

export function parsePacketOutput(rawOutput: string): ParsedPacketRow[] {
    const lines = rawOutput.split('\n').filter(line => line.trim().length > 0);
    const packets: ParsedPacketRow[] = [];

    for (const line of lines) {
        const parts = line.split('|');
        if (parts.length < 5) { continue; }

        const frameNumber = Number.parseInt(parts[0], 10);
        if (Number.isNaN(frameNumber) || frameNumber <= 0) { continue; }

        packets.push({
            number: frameNumber,
            time: (parts[1] || '0').trim(),
            source: (parts[2] || '').trim(),
            destination: (parts[3] || '').trim(),
            protocol: (parts[4] || '').trim(),
            length: Number.parseInt(parts[5], 10) || 0,
            info: parts.slice(6, -1).join('|').trim(),
            stream: parts[parts.length - 1]?.trim() || '',
        });
    }

    return packets;
}

export function getMaxPacketNumber(packets: ParsedPacketRow[]): number {
    let maxPacketNumber = 0;
    for (const packet of packets) {
        if (packet.number > maxPacketNumber) {
            maxPacketNumber = packet.number;
        }
    }
    return maxPacketNumber;
}

export function parseVerboseToTree(verbose: string): ProtoTreeNode[] {
    const nodes: ProtoTreeNode[] = [];
    if (!verbose || verbose.trim().length === 0) { return nodes; }

    const rawLines = verbose.split('\n');
    const lines: string[] = [];
    for (const raw of rawLines) {
        if (raw.length === 0) { continue; }
        const indent = raw.search(/\S/);
        if (indent === -1) { continue; }

        if (lines.length > 0 && indent > 0) {
            const prevIndent = lines[lines.length - 1].search(/\S/);
            if (indent % 4 !== 0 || indent > prevIndent + 8) {
                lines[lines.length - 1] = lines[lines.length - 1] + ' ' + raw.trim();
                continue;
            }
        }
        lines.push(raw);
    }

    const stack: Array<{ node: ProtoTreeNode; indent: number }> = [];

    for (const line of lines) {
        const indent = line.search(/\S/);
        if (indent === -1) { continue; }
        const text = line.trim();
        if (text.length === 0) { continue; }

        const node: ProtoTreeNode = {
            name: '',
            showname: text,
            children: [],
        };

        if (indent === 0) {
            nodes.push(node);
            stack.length = 0;
            stack.push({ node, indent: 0 });
        } else {
            while (stack.length > 0 && stack[stack.length - 1].indent >= indent) {
                stack.pop();
            }
            if (stack.length > 0) {
                stack[stack.length - 1].node.children.push(node);
            } else {
                nodes.push(node);
            }
            stack.push({ node, indent });
        }
    }

    return nodes;
}

export function parsePdmlToTree(pdml: string): ProtoTreeNode[] {
    const nodes: ProtoTreeNode[] = [];
    const normalized = pdml.replace(/\n\s*/g, ' ');
    const tagRegex = /<(\/?)([\w:.-]+)(\s[^>]*?)?\s*(\/?)>/g;
    const stack: ProtoTreeNode[] = [];
    let skipDepth = 0;
    let match;

    while ((match = tagRegex.exec(normalized)) !== null) {
        const isClosing = match[1] === '/';
        const tagName = match[2];
        const attrStr = match[3] || '';
        const isSelfClosing = match[4] === '/';

        if (tagName !== 'proto' && tagName !== 'field') { continue; }

        if (isClosing) {
            if (skipDepth > 0) {
                skipDepth--;
                continue;
            }
            stack.pop();
            continue;
        }

        const attrs = parseXmlAttrs(attrStr);

        if (tagName === 'proto' && attrs.name === 'geninfo') {
            if (!isSelfClosing) { skipDepth++; }
            continue;
        }

        if (attrs.hide === 'yes') {
            if (!isSelfClosing) { skipDepth++; }
            continue;
        }

        if (skipDepth > 0) {
            if (!isSelfClosing) { skipDepth++; }
            continue;
        }

        if (tagName === 'field' && !attrs.showname) {
            if (!isSelfClosing) { skipDepth++; }
            continue;
        }

        const node: ProtoTreeNode = {
            name: attrs.name || '',
            showname: attrs.showname || attrs.name || 'Unknown',
            children: [],
        };

        if (stack.length === 0) {
            nodes.push(node);
        } else {
            stack[stack.length - 1].children.push(node);
        }

        if (!isSelfClosing) {
            stack.push(node);
        }
    }

    return nodes;
}

export async function loadPacketDetailIntoWebview(options: PacketDetailLoaderOptions): Promise<void> {
    const {
        tsharkRunner,
        captureFile,
        frameNumber,
        postMessage,
        outputChannel,
        logPrefix,
        preferredFormat,
    } = options;

    outputChannel?.appendLine(`[${logPrefix}] Loading detail for packet #${frameNumber}`);

    try {
        if (preferredFormat === 'verbose') {
            const verbose = await tsharkRunner.getPacketDetail(captureFile, frameNumber);
            outputChannel?.appendLine(
                `[${logPrefix}] Verbose output length: ${verbose.length} chars, lines: ${verbose.split('\n').length}`
            );

            const tree = parseVerboseToTree(verbose);
            outputChannel?.appendLine(`[${logPrefix}] Parsed ${tree.length} protocol layers from verbose detail`);

            if (tree.length > 0) {
                postMessage({ command: 'packetDetail', frameNumber, tree });
            } else {
                postMessage({
                    command: 'packetDetailRaw',
                    frameNumber,
                    text: verbose || 'No detail available for this packet.',
                });
            }
            return;
        }

        const detail = await tsharkRunner.getPacketDetail(captureFile, frameNumber);
        const pdml = await tsharkRunner.getPacketDetailPdml(captureFile, frameNumber).catch(() => '');
        const tree = pdml ? parsePdmlToTree(pdml) : [];

        outputChannel?.appendLine(
            `[${logPrefix}] PDML output length: ${pdml.length} chars, parsed ${tree.length} protocol layers`
        );

        if (tree.length > 0) {
            postMessage({ command: 'packetDetail', frameNumber, tree });
        } else {
            postMessage({
                command: 'packetDetailRaw',
                frameNumber,
                text: detail || 'No detail available for this packet.',
            });
        }
    } catch (error) {
        outputChannel?.appendLine(`[${logPrefix}] Packet detail error: ${error}`);
        postMessage({
            command: 'packetDetailRaw',
            frameNumber,
            text: `Error loading packet detail: ${error}`,
        });
    }
}

export async function loadPacketHexIntoWebview(options: PacketHexLoaderOptions): Promise<void> {
    const { tsharkRunner, captureFile, frameNumber, postMessage, outputChannel, logPrefix } = options;

    try {
        const hex = await tsharkRunner.getPacketHexDump(captureFile, frameNumber);
        postMessage({ command: 'packetHex', frameNumber, hex });
    } catch (error) {
        outputChannel?.appendLine(`[${logPrefix}] Packet hex error: ${error}`);
        postMessage({ command: 'packetHex', frameNumber, hex: `Error: ${error}` });
    }
}

function parseXmlAttrs(attrString: string): Record<string, string> {
    const attrs: Record<string, string> = {};
    const regex = /(\w+)="([^"]*)"/g;
    let match;
    while ((match = regex.exec(attrString)) !== null) {
        attrs[match[1]] = match[2];
    }
    return attrs;
}
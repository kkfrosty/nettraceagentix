import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import { CaptureSummary, TcpStream, StreamAnomaly, ExpertInfoSummary, ExpertInfoEntry, CaptureSignals } from '../types';

/**
 * Manages tshark execution and pcap file parsing.
 * This is the core engine that converts binary pcap data into structured text for LLM analysis.
 */
export class TsharkRunner {
    private tsharkPath: string | undefined;
    private outputChannel: vscode.OutputChannel;

    constructor(outputChannel: vscode.OutputChannel) {
        this.outputChannel = outputChannel;
    }

    /**
     * Detect tshark on the system. Checks:
     * 1. User-configured path in settings
     * 2. PATH environment variable
     * 3. Standard install locations (Windows/macOS/Linux)
     */
    async detectTshark(): Promise<string | undefined> {
        // Check user setting first
        const configPath = vscode.workspace.getConfiguration('nettrace').get<string>('tsharkPath');
        if (configPath && configPath.trim() !== '') {
            if (await this.validateTshark(configPath)) {
                this.tsharkPath = configPath;
                return configPath;
            }
        }

        // Check PATH
        const pathResult = await this.tryRunTshark('tshark');
        if (pathResult) {
            this.tsharkPath = 'tshark';
            return 'tshark';
        }

        // Check standard install locations
        const standardPaths = this.getStandardTsharkPaths();
        for (const p of standardPaths) {
            if (await this.validateTshark(p)) {
                this.tsharkPath = p;
                return p;
            }
        }

        return undefined;
    }

    private getStandardTsharkPaths(): string[] {
        if (process.platform === 'win32') {
            return [
                'C:\\Program Files\\Wireshark\\tshark.exe',
                'C:\\Program Files (x86)\\Wireshark\\tshark.exe',
            ];
        } else if (process.platform === 'darwin') {
            return [
                '/Applications/Wireshark.app/Contents/MacOS/tshark',
                '/usr/local/bin/tshark',
                '/opt/homebrew/bin/tshark',
            ];
        } else {
            return ['/usr/bin/tshark', '/usr/local/bin/tshark'];
        }
    }

    private async validateTshark(tsharkPath: string): Promise<boolean> {
        return this.tryRunTshark(tsharkPath);
    }

    private tryRunTshark(tsharkPath: string): Promise<boolean> {
        return new Promise((resolve) => {
            cp.exec(`"${tsharkPath}" --version`, { timeout: 10000 }, (error) => {
                resolve(!error);
            });
        });
    }

    /**
     * Check whether tshark has been found.
     */
    isAvailable(): boolean {
        return this.tsharkPath !== undefined;
    }

    getTsharkPath(): string | undefined {
        return this.tsharkPath;
    }

    // ─── Core Parsing Commands ────────────────────────────────────────────

    /**
     * Get a high-level summary of a capture file.
     */
    async getCaptureSummary(captureFile: string): Promise<CaptureSummary> {
        this.outputChannel.appendLine(`[TsharkRunner] Parsing summary for: ${captureFile}`);

        // Run multiple tshark commands in parallel for speed
        const [statsOutput, protocolOutput, convOutput, expertOutput] = await Promise.all([
            this.runTshark(['-r', captureFile, '-q', '-z', 'io,stat,0']),
            this.runTshark(['-r', captureFile, '-q', '-z', 'io,phs']),
            this.runTshark(['-r', captureFile, '-q', '-z', 'conv,tcp']),
            this.runTshark(['-r', captureFile, '-q', '-z', 'expert']),
        ]);

        // Parse packet count and duration from capinfos-style data
        const capInfoOutput = await this.runTshark(['-r', captureFile, '-T', 'fields', '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_relative', '-c', '1']);
        const lastPacketOutput = await this.runTshark(['-r', captureFile, '-T', 'fields', '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_relative', '-Y', 'frame.number > 0'], true);

        const summary = this.parseCaptureSummary(statsOutput, protocolOutput, convOutput, expertOutput, capInfoOutput, lastPacketOutput);
        this.outputChannel.appendLine(`[TsharkRunner] Summary: ${summary.packetCount} packets, ${summary.tcpStreamCount} TCP streams, ${summary.durationSeconds.toFixed(2)}s`);

        return summary;
    }

    /**
     * Get all TCP conversations/streams with statistics.
     */
    async getConversations(captureFile: string, protocol: 'tcp' | 'udp' | 'ip' = 'tcp'): Promise<TcpStream[]> {
        const convOutput = await this.runTshark(['-r', captureFile, '-q', '-z', `conv,${protocol}`]);
        const streams = this.parseConversations(convOutput, captureFile);

        // Get anomaly info for each stream
        const anomalyOutput = await this.runTshark([
            '-r', captureFile, '-T', 'fields',
            '-e', 'tcp.stream',
            '-e', 'tcp.analysis.retransmission',
            '-e', 'tcp.analysis.duplicate_ack',
            '-e', 'tcp.analysis.zero_window',
            '-e', 'tcp.analysis.out_of_order',
            '-e', 'tcp.flags.reset',
            '-e', 'tls.alert_message',
            '-e', 'http.response.code',
            '-Y', 'tcp.analysis.retransmission || tcp.analysis.duplicate_ack || tcp.analysis.zero_window || tcp.analysis.out_of_order || tcp.flags.reset == 1 || tls.alert_message || http.response.code >= 400',
        ]);

        this.enrichStreamsWithAnomalies(streams, anomalyOutput);

        // Enhanced: detect security-relevant anomalies (malformed, fragments, bad checksums, suspicious flags)
        await this.enrichStreamsWithSecurityAnomalies(streams, captureFile);

        return streams;
    }

    /**
     * Scan a capture for security-relevant signals.
     * Returns a CaptureSignals object describing what was found.
     * This is used by the context assembler to decide whether to inject security heuristics.
     */
    async getCaptureSignals(captureFile: string): Promise<CaptureSignals> {
        const signals: CaptureSignals = {
            hasMalformedPackets: false,
            hasFragments: false,
            hasChecksumErrors: false,
            hasSuspiciousFlags: false,
            hasIcmpErrors: false,
            securityAnomalyCount: 0,
            anomalyTypes: new Set(),
        };

        // Run all signal-detection queries in parallel
        const [malformedOut, fragmentOut, suspFlagsOut, icmpOut] = await Promise.all([
            this.runTshark(['-r', captureFile, '-T', 'fields', '-e', 'frame.number', '-Y', '_ws.malformed', '-c', '1']),
            this.runTshark(['-r', captureFile, '-T', 'fields', '-e', 'frame.number', '-Y', 'ip.flags.mf == 1 || ip.frag_offset > 0', '-c', '1']),
            this.runTshark(['-r', captureFile, '-T', 'fields', '-e', 'frame.number', '-Y', 'tcp.flags.syn == 1 && tcp.flags.fin == 1', '-c', '1']),
            this.runTshark(['-r', captureFile, '-T', 'fields', '-e', 'frame.number', '-Y', 'icmp.type == 3 || icmp.type == 11', '-c', '1']),
        ]);

        if (malformedOut.trim()) {
            signals.hasMalformedPackets = true;
            signals.securityAnomalyCount++;
            signals.anomalyTypes.add('malformed');
        }
        if (fragmentOut.trim()) {
            signals.hasFragments = true;
            signals.securityAnomalyCount++;
            signals.anomalyTypes.add('fragment');
        }
        if (suspFlagsOut.trim()) {
            signals.hasSuspiciousFlags = true;
            signals.securityAnomalyCount++;
            signals.anomalyTypes.add('suspicious-flags');
        }
        if (icmpOut.trim()) {
            signals.hasIcmpErrors = true;
            signals.anomalyTypes.add('icmp-error');
        }

        this.outputChannel.appendLine(
            `[TsharkRunner] Capture signals for ${path.basename(captureFile)}: ` +
            `malformed=${signals.hasMalformedPackets}, fragments=${signals.hasFragments}, ` +
            `suspiciousFlags=${signals.hasSuspiciousFlags}, icmpErrors=${signals.hasIcmpErrors}, ` +
            `securityScore=${signals.securityAnomalyCount}`
        );

        return signals;
    }

    /**
     * Get detailed packets for a specific TCP stream.
     */
    async getStreamDetail(captureFile: string, streamIndex: number): Promise<string> {
        const output = await this.runTshark([
            '-r', captureFile,
            '-Y', `tcp.stream eq ${streamIndex}`,
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'frame.time_relative',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'tcp.flags',
            '-e', 'tcp.seq',
            '-e', 'tcp.ack',
            '-e', 'tcp.len',
            '-e', 'tcp.analysis.retransmission',
            '-e', 'tcp.analysis.duplicate_ack',
            '-e', '_ws.col.Protocol',
            '-e', '_ws.col.Info',
            '-E', 'header=y',
            '-E', 'separator=|',
        ]);
        return output;
    }

    /**
     * Get packets within a frame number range.
     * Used for on-demand pagination through large captures without loading everything.
     * Returns pipe-separated fields: frame.number|time|src|dst|protocol|length|info
     */
    async getPacketRange(captureFile: string, startFrame: number, endFrame: number, filter?: string): Promise<string> {
        const rangeFilter = `frame.number >= ${startFrame} && frame.number <= ${endFrame}`;
        const combinedFilter = filter
            ? `(${rangeFilter}) && (${filter})`
            : rangeFilter;

        const args = [
            '-r', captureFile,
            '-Y', combinedFilter,
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'frame.time_relative',
            '-e', '_ws.col.Source',
            '-e', '_ws.col.Destination',
            '-e', '_ws.col.Protocol',
            '-e', 'frame.len',
            '-e', '_ws.col.Info',
            '-E', 'header=y',
            '-E', 'separator=|',
        ];

        return this.runTshark(args);
    }

    /**
     * Follow a TCP stream to reconstruct application-layer data.
     */
    async followStream(captureFile: string, streamIndex: number, format: 'ascii' | 'hex' | 'raw' = 'ascii'): Promise<string> {
        const output = await this.runTshark([
            '-r', captureFile,
            '-q',
            '-z', `follow,tcp,${format},${streamIndex}`,
        ]);
        return output;
    }

    /**
     * Get expert info (warnings, errors, etc.)
     */
    async getExpertInfo(captureFile: string, severity?: string): Promise<string> {
        const args = ['-r', captureFile, '-q', '-z', 'expert'];
        if (severity && severity !== 'all') {
            args.push('-z', `expert,${severity}`);
        }
        return this.runTshark(args);
    }

    /**
     * Apply a Wireshark display filter and return matching packets.
     */
    async applyFilter(captureFile: string, filter: string, maxPackets: number = 100): Promise<string> {
        const args = [
            '-r', captureFile,
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'frame.time_relative',
            '-e', '_ws.col.Source',
            '-e', '_ws.col.Destination',
            '-e', '_ws.col.Protocol',
            '-e', 'frame.len',
            '-e', '_ws.col.Info',
            '-E', 'header=y',
            '-E', 'separator=|',
            '-c', maxPackets.toString(),
        ];

        // Only add filter if non-empty
        if (filter && filter.trim()) {
            args.splice(2, 0, '-Y', filter);
        }

        const output = await this.runTshark(args);
        return output;
    }

    /**
     * Get packets as structured data for the webview panel.
     * Returns pipe-separated fields: frame.number|time|src|dst|protocol|length|info|tcp.stream
     */
    async getPacketsForDisplay(captureFile: string, filter: string = ''): Promise<string> {
        const args = [
            '-r', captureFile,
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'frame.time_relative',
            '-e', '_ws.col.Source',
            '-e', '_ws.col.Destination',
            '-e', '_ws.col.Protocol',
            '-e', 'frame.len',
            '-e', '_ws.col.Info',
            '-e', 'tcp.stream',
            '-E', 'header=n',
            '-E', 'separator=|',
        ];

        if (filter && filter.trim()) {
            args.splice(2, 0, '-Y', filter);
        }

        return this.runTshark(args);
    }

    /**
     * Get compact packet data for LLM context.
     * Optimized for token efficiency:
     * - No tcp.stream field (saves ~6 chars/packet)
     * - No header line
     * - Timestamps trimmed to 3 decimal places (millisecond precision, saves ~9 chars/packet)
     */
    async getPacketsCompact(captureFile: string, filter: string = ''): Promise<string> {
        const args = [
            '-r', captureFile,
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'frame.time_relative',
            '-e', '_ws.col.Source',
            '-e', '_ws.col.Destination',
            '-e', '_ws.col.Protocol',
            '-e', 'frame.len',
            '-e', '_ws.col.Info',
            '-E', 'header=n',
            '-E', 'separator=|',
        ];

        if (filter && filter.trim()) {
            args.splice(2, 0, '-Y', filter);
        }

        const raw = await this.runTshark(args);

        // Trim timestamps from nanosecond (0.000000000) to millisecond (0.000) precision
        // Saves ~9 chars per packet = significant for large captures
        return raw.replace(/\|(\d+)\.(\d{3})\d{6}\|/g, '|$1.$2|');
    }

    /**
     * Get verbose packet detail (protocol dissection tree) for a single packet.
     * Returns the full -V output for one frame, which shows the expandable
     * Wireshark-style protocol layers.
     */
    async getPacketDetail(captureFile: string, frameNumber: number): Promise<string> {
        return this.runTshark([
            '-r', captureFile,
            '-Y', `frame.number == ${frameNumber}`,
            '-V',
        ]);
    }

    /**
     * Get packet detail as PDML (XML) for a single packet.
     * Structured protocol tree that can be parsed into an expandable UI.
     */
    async getPacketDetailPdml(captureFile: string, frameNumber: number): Promise<string> {
        return this.runTshark([
            '-r', captureFile,
            '-Y', `frame.number == ${frameNumber}`,
            '-T', 'pdml',
        ]);
    }

    /**
     * Get hex dump for a single packet.
     */
    async getPacketHexDump(captureFile: string, frameNumber: number): Promise<string> {
        return this.runTshark([
            '-r', captureFile,
            '-Y', `frame.number == ${frameNumber}`,
            '-x',
        ]);
    }

    /**
     * Get protocol hierarchy statistics.
     */
    async getProtocolHierarchy(captureFile: string): Promise<string> {
        return this.runTshark(['-r', captureFile, '-q', '-z', 'io,phs']);
    }

    /**
     * Run a custom tshark command with arbitrary arguments.
     * Used by dynamically loaded tool definitions.
     */
    async runCustomCommand(captureFile: string, args: string[]): Promise<string> {
        return this.runTshark(['-r', captureFile, ...args]);
    }

    // ─── Internal Execution ───────────────────────────────────────────────

    private runTshark(args: string[], lastOnly: boolean = false): Promise<string> {
        return new Promise((resolve, reject) => {
            if (!this.tsharkPath) {
                reject(new Error('tshark not found. Install Wireshark or configure nettrace.tsharkPath.'));
                return;
            }

            const tsharkCmd = this.tsharkPath;
            this.outputChannel.appendLine(`[TsharkRunner] Running: ${tsharkCmd} ${args.join(' ')}`);

            const proc = cp.spawn(tsharkCmd, args, {
                stdio: ['ignore', 'pipe', 'pipe'],
                windowsHide: true,
            });

            let stdout = '';
            let stderr = '';

            proc.stdout.on('data', (data: Buffer) => {
                stdout += data.toString();
            });

            proc.stderr.on('data', (data: Buffer) => {
                stderr += data.toString();
            });

            proc.on('close', (code) => {
                if (code !== 0 && code !== null) {
                    this.outputChannel.appendLine(`[TsharkRunner] Error (code ${code}): ${stderr}`);
                    // Still resolve with whatever we got — tshark sometimes returns non-zero with partial output
                    resolve(stdout || stderr);
                } else {
                    if (lastOnly && stdout.trim()) {
                        const lines = stdout.trim().split('\n');
                        resolve(lines[lines.length - 1]);
                    } else {
                        resolve(stdout);
                    }
                }
            });

            proc.on('error', (err) => {
                this.outputChannel.appendLine(`[TsharkRunner] Spawn error: ${err.message}`);
                reject(err);
            });
        });
    }

    // ─── Parse Helpers ────────────────────────────────────────────────────

    private parseCaptureSummary(
        statsOutput: string,
        protocolOutput: string,
        convOutput: string,
        expertOutput: string,
        firstPacket: string,
        lastPacket: string
    ): CaptureSummary {
        // Count TCP streams from conversation output
        const convLines = convOutput.split('\n').filter(l => l.match(/^\s*\d+\.\d+\.\d+\.\d+/));
        const tcpStreamCount = convLines.length;

        // Parse protocol breakdown from protocol hierarchy
        const protocolBreakdown: Record<string, number> = {};
        const phsLines = protocolOutput.split('\n');
        for (const line of phsLines) {
            const match = line.match(/^\s*([\w.]+)\s+frames:(\d+)/);
            if (match) {
                protocolBreakdown[match[1]] = parseInt(match[2]);
            }
        }

        // Parse packet count from stats
        let packetCount = 0;
        const statsMatch = statsOutput.match(/(\d+)\s*$/m);
        if (statsMatch) {
            packetCount = parseInt(statsMatch[1]);
        }
        // Fallback: count from protocol hierarchy
        if (packetCount === 0 && protocolBreakdown['eth'] !== undefined) {
            packetCount = protocolBreakdown['eth'];
        }
        if (packetCount === 0) {
            // Sum top-level protocols
            packetCount = Object.values(protocolBreakdown).reduce((a, b) => Math.max(a, b), 0);
        }

        // Parse timestamps
        const firstFields = firstPacket.trim().split('\t');
        const lastFields = lastPacket.trim().split('\t');
        const startTime = firstFields[1] || '';
        const endTime = lastFields[1] || '';
        const durationSeconds = parseFloat(lastFields[2] || '0') || 0;

        // Parse expert info
        const expertInfo = this.parseExpertInfo(expertOutput);

        return {
            packetCount,
            durationSeconds,
            protocolBreakdown,
            tcpStreamCount,
            udpStreamCount: 0, // Will be populated separately if needed
            startTime,
            endTime,
            expertInfo,
        };
    }

    private parseConversations(convOutput: string, captureFile: string): TcpStream[] {
        const streams: TcpStream[] = [];
        const lines = convOutput.split('\n');

        let index = 0;
        for (const line of lines) {
            // Match lines like: 10.0.0.1:443 <-> 10.0.0.2:54321   12  1234  8  432  20  1666  0.5000  0.0100
            const match = line.match(/^\s*([\d.]+:\d+)\s+<->\s+([\d.]+:\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)/);
            if (match) {
                const packetsAtoB = parseInt(match[3]);
                const bytesAtoB = parseInt(match[4]);
                const packetsBtoA = parseInt(match[5]);
                const bytesBtoA = parseInt(match[6]);

                streams.push({
                    index,
                    source: match[1],
                    destination: match[2],
                    packetCount: packetsAtoB + packetsBtoA,
                    totalBytes: bytesAtoB + bytesBtoA,
                    durationSeconds: parseFloat(match[9]) || 0,
                    anomalies: [],
                    anomalyScore: 0,
                    excluded: false,
                    captureFile,
                });
                index++;
            }
        }

        return streams;
    }

    private enrichStreamsWithAnomalies(streams: TcpStream[], anomalyOutput: string): void {
        const lines = anomalyOutput.trim().split('\n');
        const anomalyMap = new Map<number, Map<string, { count: number; packets: number[] }>>();

        for (const line of lines) {
            const fields = line.split('\t');
            if (fields.length < 2) { continue; }

            const streamIdx = parseInt(fields[0]);
            if (isNaN(streamIdx)) { continue; }

            if (!anomalyMap.has(streamIdx)) {
                anomalyMap.set(streamIdx, new Map());
            }
            const streamAnomalies = anomalyMap.get(streamIdx)!;

            if (fields[1]) { this.incrementAnomaly(streamAnomalies, 'retransmission', 0); }
            if (fields[2]) { this.incrementAnomaly(streamAnomalies, 'duplicate-ack', 0); }
            if (fields[3]) { this.incrementAnomaly(streamAnomalies, 'zero-window', 0); }
            if (fields[4]) { this.incrementAnomaly(streamAnomalies, 'out-of-order', 0); }
            if (fields[5] === '1') { this.incrementAnomaly(streamAnomalies, 'rst', 0); }
            if (fields[6]) { this.incrementAnomaly(streamAnomalies, 'tls-alert', 0); }
            if (fields[7] && parseInt(fields[7]) >= 400) { this.incrementAnomaly(streamAnomalies, 'http-error', 0); }
        }

        this.applyAnomalyMapToStreams(streams, anomalyMap);
    }

    /**
     * Detect security-relevant anomalies: malformed packets, IP fragments,
     * suspicious TCP flag combinations, and ICMP errors.
     * These are scored separately with higher weights because they indicate
     * either attacks, serious misconfigurations, or hardware/driver issues.
     */
    private async enrichStreamsWithSecurityAnomalies(streams: TcpStream[], captureFile: string): Promise<void> {
        // Query for malformed packets per TCP stream
        const [malformedOut, fragmentOut, suspFlagsOut] = await Promise.all([
            this.runTshark([
                '-r', captureFile, '-T', 'fields',
                '-e', 'tcp.stream', '-e', 'frame.number',
                '-Y', '_ws.malformed && tcp.stream',
            ]),
            this.runTshark([
                '-r', captureFile, '-T', 'fields',
                '-e', 'tcp.stream', '-e', 'frame.number',
                '-Y', '(ip.flags.mf == 1 || ip.frag_offset > 0) && tcp.stream',
            ]),
            this.runTshark([
                '-r', captureFile, '-T', 'fields',
                '-e', 'tcp.stream', '-e', 'frame.number',
                '-Y', '(tcp.flags.syn == 1 && tcp.flags.fin == 1) && tcp.stream',
            ]),
        ]);

        const secAnomalyMap = new Map<number, Map<string, { count: number; packets: number[] }>>();

        this.parseSecurityOutput(secAnomalyMap, malformedOut, 'malformed');
        this.parseSecurityOutput(secAnomalyMap, fragmentOut, 'fragment');
        this.parseSecurityOutput(secAnomalyMap, suspFlagsOut, 'suspicious-flags');

        this.applyAnomalyMapToStreams(streams, secAnomalyMap);
    }

    private parseSecurityOutput(
        map: Map<number, Map<string, { count: number; packets: number[] }>>,
        output: string,
        anomalyType: string
    ): void {
        for (const line of output.trim().split('\n')) {
            const fields = line.split('\t');
            if (fields.length < 1) { continue; }
            const streamIdx = parseInt(fields[0]);
            if (isNaN(streamIdx)) { continue; }
            const packetNum = parseInt(fields[1]) || 0;

            if (!map.has(streamIdx)) {
                map.set(streamIdx, new Map());
            }
            this.incrementAnomaly(map.get(streamIdx)!, anomalyType, packetNum);
        }
    }

    private applyAnomalyMapToStreams(
        streams: TcpStream[],
        anomalyMap: Map<number, Map<string, { count: number; packets: number[] }>>
    ): void {
        for (const stream of streams) {
            const anomalies = anomalyMap.get(stream.index);
            if (!anomalies) { continue; }

            for (const [type, data] of anomalies) {
                // Check if this anomaly type already exists on the stream
                const existing = stream.anomalies.find(a => a.type === type);
                if (existing) {
                    existing.count += data.count;
                    existing.packetNumbers.push(...data.packets);
                    existing.description = this.getAnomalyDescription(type, existing.count);
                } else {
                    const anomaly: StreamAnomaly = {
                        type: type as StreamAnomaly['type'],
                        count: data.count,
                        description: this.getAnomalyDescription(type, data.count),
                        packetNumbers: data.packets,
                    };
                    stream.anomalies.push(anomaly);
                }
            }

            // Recalculate anomaly score with all anomaly types
            stream.anomalyScore = this.calculateAnomalyScore(stream.anomalies);
        }
    }

    private calculateAnomalyScore(anomalies: StreamAnomaly[]): number {
        return anomalies.reduce((score: number, a: StreamAnomaly) => {
            const weights: Record<string, number> = {
                'malformed': 15,
                'suspicious-flags': 12,
                'fragment': 12,
                'rst': 10,
                'tls-alert': 10,
                'checksum-error': 10,
                'http-error': 8,
                'zero-window': 7,
                'icmp-error': 6,
                'timeout': 6,
                'retransmission': 5,
                'out-of-order': 4,
                'duplicate-ack': 3,
            };
            return score + (weights[a.type] || 1) * a.count;
        }, 0);
    }

    private incrementAnomaly(map: Map<string, { count: number; packets: number[] }>, type: string, packet: number): void {
        const existing = map.get(type);
        if (existing) {
            existing.count++;
            if (packet) { existing.packets.push(packet); }
        } else {
            map.set(type, { count: 1, packets: packet ? [packet] : [] });
        }
    }

    private getAnomalyDescription(type: string, count: number): string {
        const descriptions: Record<string, string> = {
            'retransmission': `${count} TCP retransmission(s) — possible packet loss or high latency`,
            'duplicate-ack': `${count} duplicate ACK(s) — receiver signaling missing data`,
            'zero-window': `${count} zero window event(s) — receiver buffer full`,
            'out-of-order': `${count} out-of-order packet(s) — possible path issues`,
            'rst': `${count} TCP RST(s) — connection forcibly closed`,
            'tls-alert': `${count} TLS alert(s) — handshake or certificate issue`,
            'http-error': `${count} HTTP error response(s) (4xx/5xx)`,
            'timeout': `${count} timeout event(s)`,
            'malformed': `${count} MALFORMED packet(s) — protocol structure violation (CRITICAL: legitimate software does not produce malformed packets)`,
            'fragment': `${count} IP fragment(s) — unusual in modern networks, may indicate fragmentation attack`,
            'checksum-error': `${count} checksum error(s) — data integrity violation`,
            'suspicious-flags': `${count} suspicious TCP flag combination(s) (e.g., SYN+FIN) — not produced by legitimate TCP stacks`,
            'icmp-error': `${count} ICMP error(s) (unreachable/TTL exceeded) — routing or firewall issue`,
        };
        return descriptions[type] || `${count} ${type} event(s)`;
    }

    private parseExpertInfo(output: string): ExpertInfoSummary {
        const summary: ExpertInfoSummary = {
            errors: 0,
            warnings: 0,
            notes: 0,
            chats: 0,
            details: [],
        };

        const lines = output.split('\n');
        for (const line of lines) {
            // Match summary line like: "Errors (3)"
            const summaryMatch = line.match(/^\s*(Errors?|Warnings?|Notes?|Chats?)\s*\((\d+)\)/i);
            if (summaryMatch) {
                const key = summaryMatch[1].toLowerCase().replace(/s$/, '');
                const count = parseInt(summaryMatch[2]);
                if (key.startsWith('error')) { summary.errors = count; }
                else if (key.startsWith('warning')) { summary.warnings = count; }
                else if (key.startsWith('note')) { summary.notes = count; }
                else if (key.startsWith('chat')) { summary.chats = count; }
            }
        }

        return summary;
    }
}

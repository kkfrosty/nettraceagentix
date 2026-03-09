import * as vscode from 'vscode';
import * as path from 'path';
import { TsharkRunner } from '../parsing/tsharkRunner';
import { CaptureFile } from '../types';
import { ParsedPacketRow, ProtoTreeNode, loadPacketDetailIntoWebview, loadPacketHexIntoWebview, parsePacketOutput } from './sharedCaptureView';

/**
 * Manages the Capture Viewer webview panel — a mini Wireshark inside VS Code.
 * Shows packet list, protocol hierarchy, expert info, and conversations
 * with a Wireshark-compatible display filter bar.
 */
export class CaptureWebviewPanel {
    public static readonly viewType = 'nettrace.captureViewer';
    private static panels = new Map<string, CaptureWebviewPanel>();
    private static readonly DEFAULT_VIRTUALIZATION_THRESHOLD = 20000;

    /**
     * Callback fired when a viewer panel opens or closes.
     * Set once by extension.ts so the captures tree stays in sync.
     */
    public static onPanelChange: ((filePath: string, event: 'opened' | 'closed', panelType: 'viewer') => void) | undefined;

    private readonly panel: vscode.WebviewPanel;
    private readonly extensionUri: vscode.Uri;
    private disposables: vscode.Disposable[] = [];
    private currentFilter: string = '';
    private currentCapture: CaptureFile;
    private loadSequence: number = 0;
    private packetWindowCache = new Map<string, PacketRow[]>();
    private supplementalTabHtml: Partial<Record<'conversations' | 'protocols' | 'expert', string>> = {};
    private supplementalTabLoads = new Map<'conversations' | 'protocols' | 'expert', Promise<void>>();

    /**
     * Open or focus the viewer for a specific capture file.
     */
    public static createOrShow(
        extensionUri: vscode.Uri,
        capture: CaptureFile,
        tsharkRunner: TsharkRunner,
        outputChannel: vscode.OutputChannel
    ): CaptureWebviewPanel {
        const existing = CaptureWebviewPanel.panels.get(capture.filePath);
        if (existing) {
            existing.panel.reveal(vscode.ViewColumn.One);
            return existing;
        }

        const panel = vscode.window.createWebviewPanel(
            CaptureWebviewPanel.viewType,
            `📡 ${capture.name}`,
            vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'media')],
            }
        );

        const viewer = new CaptureWebviewPanel(panel, extensionUri, capture, tsharkRunner, outputChannel);
        CaptureWebviewPanel.panels.set(capture.filePath, viewer);
        CaptureWebviewPanel.onPanelChange?.(capture.filePath, 'opened', 'viewer');
        return viewer;
    }

    private constructor(
        panel: vscode.WebviewPanel,
        extensionUri: vscode.Uri,
        capture: CaptureFile,
        private tsharkRunner: TsharkRunner,
        private outputChannel: vscode.OutputChannel
    ) {
        this.panel = panel;
        this.extensionUri = extensionUri;
        this.currentCapture = capture;

        // Set initial HTML
        this.panel.webview.html = this.getLoadingHtml();

        // Handle messages from the webview
        this.panel.webview.onDidReceiveMessage(
            async (message) => {
                switch (message.command) {
                    case 'applyFilter':
                        await this.applyFilter(message.filter);
                        break;
                    case 'clearFilter':
                        await this.applyFilter('');
                        break;
                    case 'refreshData':
                        await this.loadCaptureData();
                        break;
                    case 'loadTabData':
                        if (message.tab === 'conversations' || message.tab === 'protocols' || message.tab === 'expert') {
                            await this.ensureSupplementalTabLoaded(message.tab, this.currentCapture.filePath, this.loadSequence);
                        }
                        break;
                    case 'requestPacketWindow':
                        await this.loadPacketWindow(message.startFrame, message.endFrame);
                        break;
                    case 'analyzeWithAI':
                        {
                            const prompt = message.prompt || 'Analyze the current open capture context and diagnose any issues.';
                            await vscode.commands.executeCommand('workbench.action.chat.open', {
                                query: `@nettrace ${prompt}`,
                            });
                        }
                        break;
                    case 'analyzePacket':
                        {
                            const marker = `[[nettrace:captureFile=${encodeURIComponent(this.currentCapture.filePath)}]]`;
                            await vscode.commands.executeCommand('workbench.action.chat.open', {
                                query: `@nettrace ${marker} Look at packet #${message.packetNumber} in detail. What's happening and is there an issue?`,
                            });
                        }
                        break;
                    case 'analyzeStream':
                        {
                            const marker = `[[nettrace:captureFile=${encodeURIComponent(this.currentCapture.filePath)}]]`;
                            await vscode.commands.executeCommand('workbench.action.chat.open', {
                                query: `@nettrace ${marker} /stream ${message.streamIndex} Analyze this stream in detail.`,
                            });
                        }
                        break;
                    case 'getStreamData':
                        await this.loadStreamPackets(message.streamIndex);
                        break;
                    case 'getPacketDetail':
                        await this.loadPacketDetail(message.frameNumber);
                        break;
                    case 'getPacketHex':
                        await this.loadPacketHex(message.frameNumber);
                        break;
                    case 'closeCapture':
                        this.panel.dispose();
                        break;
                    case 'toggleSidebar':
                        vscode.commands.executeCommand('workbench.action.toggleSidebarVisibility');
                        break;
                }
            },
            null,
            this.disposables
        );

        // Clean up on close
        this.panel.onDidDispose(
            () => {
                CaptureWebviewPanel.panels.delete(capture.filePath);
                CaptureWebviewPanel.onPanelChange?.(capture.filePath, 'closed', 'viewer');
                this.dispose();
            },
            null,
            this.disposables
        );

        // Load initial data
        this.loadCaptureData();
    }

    private async loadCaptureData(): Promise<void> {
        const filePath = this.currentCapture.filePath;
        const loadSequence = ++this.loadSequence;
        const virtualizationThreshold = this.getVirtualizationThreshold();
        const summaryPacketCount = this.currentCapture.summary?.packetCount ?? 0;
        const usePagedPacketLoading = !this.currentFilter && summaryPacketCount >= virtualizationThreshold;
        this.packetWindowCache.clear();
        this.supplementalTabHtml = {};
        this.supplementalTabLoads.clear();
        this.outputChannel.appendLine(`[WebviewPanel] Loading data for ${this.currentCapture.name} at ${filePath}`);

        try {
            this.panel.webview.html = this.getHtml([], {
                isChunked: true,
                totalPacketCount: summaryPacketCount || undefined,
                loadedPacketCount: 0,
                chunkSize: 0,
                filter: this.currentFilter,
                virtualizationThreshold,
                isPagedPacketView: usePagedPacketLoading,
            });

            if (usePagedPacketLoading) {
                return;
            }

            const packetData = await this.tsharkRunner.getPacketsForDisplay(filePath, this.currentFilter);
            const packets = this.parsePacketOutput(packetData);

            if (loadSequence !== this.loadSequence) {
                return;
            }

            this.panel.webview.postMessage({
                command: 'replacePackets',
                packets,
                filter: this.currentFilter,
                totalCount: this.currentFilter ? packets.length : (this.currentCapture.summary?.packetCount ?? packets.length),
                isChunked: false,
            });

        } catch (e) {
            this.outputChannel.appendLine(`[WebviewPanel] Error loading data: ${e}`);
            this.panel.webview.html = this.getErrorHtml(`Failed to load capture data: ${e}`);
        }
    }

    private async ensureSupplementalTabLoaded(
        tab: 'conversations' | 'protocols' | 'expert',
        filePath: string,
        loadSequence: number
    ): Promise<void> {
        if (this.supplementalTabHtml[tab]) {
            this.postSupplementalTabHtml(tab, this.supplementalTabHtml[tab]!);
            return;
        }

        const existingLoad = this.supplementalTabLoads.get(tab);
        if (existingLoad) {
            await existingLoad;
            return;
        }

        const loadPromise = this.loadSupplementalTab(tab, filePath, loadSequence)
            .finally(() => this.supplementalTabLoads.delete(tab));
        this.supplementalTabLoads.set(tab, loadPromise);
        await loadPromise;
    }

    private async loadSupplementalTab(
        tab: 'conversations' | 'protocols' | 'expert',
        filePath: string,
        loadSequence: number
    ): Promise<void> {
        try {
            let html = '';

            if (tab === 'conversations') {
                const conversations = await this.tsharkRunner.getConversations(filePath).catch((e) => {
                    this.outputChannel.appendLine(`[WebviewPanel] Conversations error: ${e}`);
                    return [];
                });
                html = this.buildConversationsHtml(conversations);
                this.outputChannel.appendLine(`[WebviewPanel] Conversations tab ready: ${conversations.length} conversations`);
            } else if (tab === 'protocols') {
                const protocolHierarchy = await this.tsharkRunner.getProtocolHierarchy(filePath).catch((e) => {
                    this.outputChannel.appendLine(`[WebviewPanel] Protocol hierarchy error: ${e}`);
                    return '';
                });
                html = this.buildProtocolsHtml(protocolHierarchy);
            } else {
                const expertInfo = await this.tsharkRunner.getExpertInfo(filePath).catch((e) => {
                    this.outputChannel.appendLine(`[WebviewPanel] Expert info error: ${e}`);
                    return '';
                });
                html = this.buildExpertInfoHtml(expertInfo);
            }

            if (loadSequence !== this.loadSequence) {
                return;
            }

            this.supplementalTabHtml[tab] = html;
            this.postSupplementalTabHtml(tab, html);
        } catch (e) {
            this.outputChannel.appendLine(`[WebviewPanel] ${tab} tab load failed: ${e}`);
        }
    }

    private postSupplementalTabHtml(tab: 'conversations' | 'protocols' | 'expert', html: string): void {
        const command = tab === 'conversations'
            ? 'updateConversations'
            : tab === 'protocols'
                ? 'updateProtocols'
                : 'updateExpertInfo';
        this.panel.webview.postMessage({ command, html });
    }

    private async applyFilter(filter: string): Promise<void> {
        this.currentFilter = filter;
        this.packetWindowCache.clear();
        this.outputChannel.appendLine(`[WebviewPanel] Applying filter: "${filter || '(none)'}"`);

        if (!filter) {
            await this.loadCaptureData();
            return;
        }

        try {
            const packetData = await this.tsharkRunner.getPacketsForDisplay(
                this.currentCapture.filePath,
                filter
            );
            const packets = this.parsePacketOutput(packetData);

            this.panel.webview.postMessage({
                command: 'replacePackets',
                packets,
                filter,
                totalCount: packets.length,
                isChunked: false,
            });
        } catch (e) {
            this.panel.webview.postMessage({
                command: 'filterError',
                message: `Invalid filter: ${e}`,
            });
        }
    }

    private async loadPacketWindow(startFrame: number, endFrame: number): Promise<void> {
        const loadSequence = this.loadSequence;
        const clampedStart = Math.max(1, Math.floor(startFrame));
        const clampedEnd = Math.max(clampedStart, Math.floor(endFrame));
        const cacheKey = `${this.currentFilter}::${clampedStart}-${clampedEnd}`;

        try {
            const cached = this.packetWindowCache.get(cacheKey);
            if (cached) {
                this.panel.webview.postMessage({
                    command: 'packetWindow',
                    packets: cached,
                    startFrame: clampedStart,
                    endFrame: clampedEnd,
                    totalCount: this.currentFilter
                        ? cached.length
                        : (this.currentCapture.summary?.packetCount ?? cached.length),
                    filter: this.currentFilter,
                });
                return;
            }

            const packetData = await this.tsharkRunner.getPacketRange(
                this.currentCapture.filePath,
                clampedStart,
                clampedEnd,
                this.currentFilter || undefined
            );
            const packets = this.parsePacketOutput(packetData);

            if (loadSequence !== this.loadSequence) {
                return;
            }

            this.packetWindowCache.set(cacheKey, packets);

            this.panel.webview.postMessage({
                command: 'packetWindow',
                packets,
                startFrame: clampedStart,
                endFrame: clampedEnd,
                totalCount: this.currentFilter
                    ? packets.length
                    : (this.currentCapture.summary?.packetCount ?? packets.length),
                filter: this.currentFilter,
            });
        } catch (e) {
            this.panel.webview.postMessage({
                command: 'error',
                message: `Failed to load packet window ${clampedStart}-${clampedEnd}: ${e}`,
            });
        }
    }

    private async applyDisplayFilterToPanel(filter: string): Promise<void> {
        this.panel.webview.postMessage({ command: 'applyFilterExt', filter });
        await this.applyFilter(filter);
    }

    private async loadStreamPackets(streamIndex: number): Promise<void> {
        try {
            const detail = await this.tsharkRunner.getStreamDetail(
                this.currentCapture.filePath,
                streamIndex
            );
            this.panel.webview.postMessage({
                command: 'streamData',
                streamIndex,
                data: detail,
            });
        } catch (e) {
            this.panel.webview.postMessage({
                command: 'error',
                message: `Failed to load stream ${streamIndex}: ${e}`,
            });
        }
    }

    /**
     * Load detailed protocol dissection for a single packet.
     * Uses tshark -V (verbose text) and parses indentation into a tree.
     * This is more reliable than PDML XML parsing.
     */
    private async loadPacketDetail(frameNumber: number): Promise<void> {
        await loadPacketDetailIntoWebview({
            tsharkRunner: this.tsharkRunner,
            captureFile: this.currentCapture.filePath,
            frameNumber,
            postMessage: (message) => this.panel.webview.postMessage(message),
            outputChannel: this.outputChannel,
            logPrefix: 'WebviewPanel',
            preferredFormat: 'verbose',
        });
    }

    /**
     * Load hex dump for a single packet.
     */
    private async loadPacketHex(frameNumber: number): Promise<void> {
        await loadPacketHexIntoWebview({
            tsharkRunner: this.tsharkRunner,
            captureFile: this.currentCapture.filePath,
            frameNumber,
            postMessage: (message) => this.panel.webview.postMessage(message),
            outputChannel: this.outputChannel,
            logPrefix: 'WebviewPanel',
        });
    }

    /**
     * Get the currently active capture file path.
     * Used by the chat participant to focus on the right capture.
     */
    public getActiveCapturePath(): string {
        return this.currentCapture.filePath;
    }

    /**
     * Static method to get the currently focused (visible) capture file path.
     *
     * Returns the path only when a panel is unambiguously determined:
     *  - A panel is currently visible (user is looking at it)
     *  - Exactly ONE panel is open (unambiguous even if user switched to Chat)
     *
     * Returns undefined when multiple panels are open but none is focused.
     * Callers that need to present a picker should call getOpenCapturePanels() separately.
     */
    public static getActiveCaptureFile(): string | undefined {
        // Visible panel — definitive answer
        for (const [filePath, panel] of CaptureWebviewPanel.panels) {
            if (panel.panel.visible) {
                return filePath;
            }
        }
        // Exactly one panel open: unambiguous even when the user switched to Chat
        if (CaptureWebviewPanel.panels.size === 1) {
            const first = CaptureWebviewPanel.panels.values().next();
            return first.done ? undefined : first.value.currentCapture.filePath;
        }
        // Multiple panels open, none focused — caller must disambiguate
        return undefined;
    }

    /**
     * Returns metadata for every currently open capture panel.
     * Used to build a disambiguation QuickPick when multiple panels are open.
     */
    public static getOpenCapturePanels(): { filePath: string; name: string }[] {
        const result: { filePath: string; name: string }[] = [];
        for (const [, viewer] of CaptureWebviewPanel.panels) {
            result.push({ filePath: viewer.currentCapture.filePath, name: viewer.currentCapture.name });
        }
        return result;
    }

    /**
     * Close the currently active capture viewer, or all viewers.
     */
    public static closeActive(): void {
        // Close the visible panel first
        for (const [, viewer] of CaptureWebviewPanel.panels) {
            if (viewer.panel.visible) {
                viewer.panel.dispose();
                return;
            }
        }
        // Fallback: close the first panel
        const first = CaptureWebviewPanel.panels.values().next();
        if (!first.done) {
            first.value.panel.dispose();
        }
    }

    /**
     * Apply a display filter from an external source (chat command, VS Code command).
     * Pushes the filter into the webview UI and triggers a re-query.
     */
    public static applyFilterToActive(filter: string): void {
        for (const [, viewer] of CaptureWebviewPanel.panels) {
            if (viewer.panel.visible) {
                void viewer.applyDisplayFilterToPanel(filter);
                return;
            }
        }
        // Fallback: apply to first panel
        const first = CaptureWebviewPanel.panels.values().next();
        if (!first.done) {
            void first.value.applyDisplayFilterToPanel(filter);
        }
    }

    /**
     * Parse tshark pipe-separated fields output into structured packet rows.
     * Format: frame.number|time_relative|source|destination|protocol|frame.len|info|tcp.stream
     */
    private parsePacketOutput(rawOutput: string): PacketRow[] {
        return parsePacketOutput(rawOutput).map((packet) => ({
            number: packet.number,
            time: packet.time,
            source: packet.source,
            destination: packet.destination,
            protocol: packet.protocol,
            length: packet.length,
            info: packet.info,
            stream: packet.stream,
        }));
    }

    private getVirtualizationThreshold(): number {
        const configured = vscode.workspace
            .getConfiguration('nettrace')
            .get<number>('captureViewerVirtualizationThreshold', CaptureWebviewPanel.DEFAULT_VIRTUALIZATION_THRESHOLD);

        if (!Number.isFinite(configured) || configured <= 0) {
            return CaptureWebviewPanel.DEFAULT_VIRTUALIZATION_THRESHOLD;
        }

        return Math.floor(configured);
    }

    private buildConversationsHtml(conversations: any[]): string {
        if (conversations.length === 0) {
            return '<tr><td colspan="8" class="loading-cell">No conversations available</td></tr>';
        }

        return conversations.slice(0, 50).map((c) => {
            const anomalyClass = c.anomalyScore >= 10 ? 'row-error' : c.anomalyScore > 0 ? 'row-warning' : '';
            const anomalyBadge = c.anomalies.length > 0
                ? `<span class="badge badge-warning" title="${c.anomalies.map((a: any) => a.description).join(', ')}">${c.anomalies.length} issue${c.anomalies.length > 1 ? 's' : ''}</span>`
                : '<span class="badge badge-ok">✓</span>';
            return `<tr class="${anomalyClass}" data-stream="${c.index}">
                <td>${c.index}</td>
                <td>${c.source}</td>
                <td>${c.destination}</td>
                <td>${c.packetCount}</td>
                <td>${formatBytes(c.totalBytes)}</td>
                <td>${c.durationSeconds.toFixed(2)}s</td>
                <td>${anomalyBadge}</td>
                <td>
                    <button class="btn-icon" data-action="analyzeStream" data-stream="${c.index}" title="Analyze with AI">🔍</button>
                    <button class="btn-icon" data-action="filterStream" data-stream="${c.index}" title="Filter to this stream">🎯</button>
                </td>
            </tr>`;
        }).join('');
    }

    private buildExpertInfoHtml(expertInfo: string): string {
        const expertLines = expertInfo.split('\n').filter(l => l.trim());
        if (expertLines.length === 0) {
            return '<p style="color:var(--vscode-descriptionForeground)">No expert information available</p>';
        }

        return expertLines.slice(0, 50).map(line => {
            const severity = line.toLowerCase().includes('error') ? 'error'
                : line.toLowerCase().includes('warn') ? 'warning'
                : line.toLowerCase().includes('note') ? 'note' : 'info';
            return `<div class="expert-entry expert-${severity}">${escapeHtml(line)}</div>`;
        }).join('');
    }

    private buildProtocolsHtml(protocolHierarchy: string): string {
        const protocolBreakdown = this.currentCapture.summary?.protocolBreakdown || {};
        const topProtocols = Object.entries(protocolBreakdown)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 15);

        const protocolsHtml = topProtocols.map(([name, count]) =>
            `<div class="proto-item"><span class="proto-name">${name}</span><span class="proto-count">${count}</span></div>`
        ).join('');

        const hierarchyHtml = protocolHierarchy
            ? `<pre style="margin-top: 16px; font-size: 11px; white-space: pre-wrap; color: var(--vscode-descriptionForeground);">${escapeHtml(protocolHierarchy)}</pre>`
            : '';

        return `${protocolsHtml || '<p style="color:var(--vscode-descriptionForeground)">No protocol data available</p>'}${hierarchyHtml}`;
    }

    private getErrorHtml(message: string): string {
        return `<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); background: var(--vscode-editor-background); display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .error { text-align: center; max-width: 500px; }
        .error h2 { color: var(--vscode-errorForeground, #f44); }
        .error p { margin-top: 12px; }
    </style>
</head>
<body>
    <div class="error">
        <h2>⚠️ Error</h2>
        <p>${escapeHtml(message)}</p>
        <p style="margin-top: 16px; color: var(--vscode-descriptionForeground);">Check the NetTrace output channel for details.</p>
    </div>
</body>
</html>`;
    }

    private getLoadingHtml(): string {
        return `<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); background: var(--vscode-editor-background); display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .loading { text-align: center; }
        .spinner { font-size: 32px; animation: spin 1s linear infinite; display: inline-block; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="loading">
        <div class="spinner">⟳</div>
        <p>Loading capture data...</p>
    </div>
</body>
</html>`;
    }

    private getHtml(
        packets: PacketRow[],
        options: {
            isChunked: boolean;
            totalPacketCount?: number;
            loadedPacketCount: number;
            chunkSize: number;
            filter: string;
            virtualizationThreshold: number;
            isPagedPacketView?: boolean;
        }
    ): string {
        const nonce = getNonce();
        const captureName = this.currentCapture.name;
        const packetCount = this.currentCapture.summary?.packetCount ?? packets.length;
        const initialHeaderStats = options.isChunked
            ? (options.totalPacketCount !== undefined
                ? `Loading 0 of ${options.totalPacketCount} packets...`
                : 'Loading packets...')
            : `${packetCount} packets`;

        // Build packet rows (div-based grid, matches renderPacketRow in webview JS)
        const packetsHtml = packets.length > 0 ? packets.map(p => {
            const protoClass = getProtocolClass(p.protocol);
            return `<div class="packet-row ${protoClass}" data-packet="${p.number}" data-src="${escapeHtml(p.source)}" data-dst="${escapeHtml(p.destination)}" data-proto="${escapeHtml(p.protocol)}" data-stream="${p.stream}">
                <div class="packet-cell col-no">${p.number}</div>
                <div class="packet-cell col-time">${p.time}</div>
                <div class="packet-cell col-src">${p.source}</div>
                <div class="packet-cell col-dst">${p.destination}</div>
                <div class="packet-cell col-proto">${p.protocol}</div>
                <div class="packet-cell col-len">${p.length}</div>
                <div class="packet-cell col-info">${escapeHtml(p.info)}</div>
            </div>`;
        }).join('') : options.isChunked
            ? '<div class="packet-loading">Loading packets...</div>'
            : '<div class="packet-loading">No packets available</div>';

        return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
    <style nonce="${nonce}">
        :root {
            --border-color: var(--vscode-panel-border, #333);
            --header-bg: var(--vscode-sideBar-background, #252526);
            --hover-bg: var(--vscode-list-hoverBackground, #2a2d2e);
            --selected-bg: var(--vscode-list-activeSelectionBackground, #094771);
            --selected-fg: var(--vscode-list-activeSelectionForeground, #fff);
            --input-bg: var(--vscode-input-background, #3c3c3c);
            --input-fg: var(--vscode-input-foreground, #ccc);
            --input-border: var(--vscode-input-border, #555);
            --button-bg: var(--vscode-button-background, #0e639c);
            --button-fg: var(--vscode-button-foreground, #fff);
            --button-hover: var(--vscode-button-hoverBackground, #1177bb);
            --error-bg: rgba(255, 0, 0, 0.08);
            --warning-bg: rgba(255, 165, 0, 0.08);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: var(--vscode-font-family, 'Segoe UI', sans-serif);
            font-size: var(--vscode-font-size, 13px);
            color: var(--vscode-foreground);
            background: var(--vscode-editor-background);
            overflow: hidden;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }

        /* ─── Top Bar ───────────────────────────────────────── */
        .toolbar {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 6px 12px;
            background: var(--header-bg);
            border-bottom: 1px solid var(--border-color);
            flex-shrink: 0;
        }
        .toolbar .title {
            font-weight: 600;
            font-size: 14px;
            white-space: nowrap;
        }
        .toolbar .stats {
            color: var(--vscode-descriptionForeground, #999);
            font-size: 12px;
            white-space: nowrap;
        }
        .toolbar .spacer { flex: 1; }

        /* ─── Filter Bar ────────────────────────────────────── */
        .filter-bar {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            background: var(--header-bg);
            border-bottom: 1px solid var(--border-color);
            flex-shrink: 0;
        }
        .filter-bar label {
            font-weight: 500;
            font-size: 12px;
            white-space: nowrap;
        }
        .filter-bar input {
            flex: 1;
            padding: 4px 8px;
            background: var(--input-bg);
            color: var(--input-fg);
            border: 1px solid var(--input-border);
            border-radius: 3px;
            font-family: var(--vscode-editor-font-family, 'Consolas', monospace);
            font-size: 13px;
            outline: none;
        }
        .filter-bar input:focus {
            border-color: var(--vscode-focusBorder, #007fd4);
        }
        .filter-bar input.filter-error {
            border-color: var(--vscode-inputValidation-errorBorder, #f44);
        }
        .filter-bar .filter-hint {
            font-size: 11px;
            color: var(--vscode-descriptionForeground, #888);
        }
        .filter-bar .filter-error-msg {
            font-size: 11px;
            color: var(--vscode-errorForeground, #f44);
        }

        /* ─── Buttons ───────────────────────────────────────── */
        .btn {
            padding: 4px 12px;
            background: var(--button-bg);
            color: var(--button-fg);
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
            white-space: nowrap;
        }
        .btn:hover { background: var(--button-hover); }
        .btn-secondary {
            background: transparent;
            border: 1px solid var(--input-border);
            color: var(--vscode-foreground);
        }
        .btn-secondary:hover { background: var(--hover-bg); }
        .btn-ai {
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            border: none;
        }
        .btn-ai:hover { background: linear-gradient(135deg, #7c7ff7, #9d6ffa); }
        .btn-icon {
            background: none;
            border: none;
            cursor: pointer;
            font-size: 14px;
            padding: 2px 4px;
            border-radius: 3px;
            color: var(--vscode-foreground);
        }
        .btn-icon:hover { background: var(--hover-bg); }

        /* ─── Tab Bar ───────────────────────────────────────── */
        .tab-bar {
            display: flex;
            background: var(--header-bg);
            border-bottom: 1px solid var(--border-color);
            flex-shrink: 0;
        }
        .tab {
            padding: 6px 16px;
            cursor: pointer;
            font-size: 12px;
            border-bottom: 2px solid transparent;
            color: var(--vscode-descriptionForeground, #999);
            user-select: none;
        }
        .tab:hover { color: var(--vscode-foreground); background: var(--hover-bg); }
        .tab.active {
            color: var(--vscode-foreground);
            border-bottom-color: var(--vscode-focusBorder, #007fd4);
        }

        /* ─── Content Area ──────────────────────────────────── */
        .content { flex: 1; overflow: hidden; display: flex; flex-direction: column; }
        .tab-content { display: none; flex: 1; overflow: hidden; }
        .tab-content.active { display: flex; flex-direction: column; overflow: hidden; }

        /* ─── Wireshark-style 3-pane layout for Packets tab ── */
        .ws-layout { display: flex; flex-direction: column; flex: 1; overflow: hidden; --ws-bottom-height: 220px; }
        .ws-top { flex: 1 1 auto; min-height: 80px; overflow: hidden; display: flex; flex-direction: column; }
        .ws-splitter {
            flex: 0 0 6px;
            cursor: row-resize;
            background: var(--header-bg);
            border-top: 1px solid var(--border-color);
            border-bottom: 1px solid var(--border-color);
            position: relative;
        }
        .ws-splitter::after {
            content: '';
            position: absolute;
            left: 50%;
            top: 50%;
            width: 36px;
            height: 2px;
            transform: translate(-50%, -50%);
            background: var(--vscode-descriptionForeground, #888);
            box-shadow: 0 -4px 0 var(--vscode-descriptionForeground, #888), 0 4px 0 var(--vscode-descriptionForeground, #888);
            opacity: 0.65;
        }
        .ws-splitter:hover,
        .ws-splitter.dragging { background: var(--hover-bg); }
        .ws-bottom { flex: 0 0 var(--ws-bottom-height); min-height: 80px; display: flex; flex-direction: row; overflow: hidden; }
        .ws-detail { flex: 1; overflow: auto; border-right: 2px solid var(--border-color); }
        .ws-hex { flex: 0 0 40%; max-width: 50%; overflow: auto; font-family: var(--vscode-editor-font-family, monospace); font-size: 11px; }
        .ws-pane-header {
            display: flex; align-items: center; gap: 8px;
            padding: 3px 8px;
            background: var(--header-bg);
            border-bottom: 1px solid var(--border-color);
            font-size: 11px;
            font-weight: 600;
            color: var(--vscode-descriptionForeground, #999);
            flex-shrink: 0;
            justify-content: space-between;
        }
        .ws-pane-header .pane-toggle {
            cursor: pointer; border: none; background: none;
            color: var(--vscode-descriptionForeground, #888); font-size: 12px;
            padding: 0 4px;
        }
        .ws-pane-header .pane-toggle:hover { color: var(--vscode-foreground); }
        .ws-hex.collapsed { flex: 0 0 24px !important; max-width: none !important; min-height: auto !important; overflow: hidden; }
        .ws-hex.collapsed .ws-pane-body { display: none; }
        .ws-hex.collapsed .ws-pane-header { justify-content: center; padding: 3px 0; }
        .ws-hex.collapsed .ws-pane-header span { display: none; }
        .ws-bottom.collapsed { flex: 0 0 24px !important; min-height: 0 !important; overflow: hidden; }
        .ws-bottom.collapsed #packetDetailContent { display: none; }
        .ws-bottom.collapsed .ws-hex { display: none; }
        .ws-layout.bottom-collapsed .ws-splitter { display: none; }
        .ws-empty {
            padding: 20px;
            text-align: center;
            color: var(--vscode-descriptionForeground, #888);
            font-size: 13px;
        }

        /* ─── Right-click context menu ───────────────── */
        .ctx-menu {
            position: fixed; z-index: 1000;
            background: var(--header-bg); border: 1px solid var(--border-color);
            border-radius: 4px; padding: 4px 0;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            min-width: 220px;
            font-size: 12px;
        }
        .ctx-menu-item {
            padding: 5px 16px; cursor: pointer;
            white-space: nowrap;
        }
        .ctx-menu-item:hover { background: var(--hover-bg); }
        .ctx-menu-sep { height: 1px; background: var(--border-color); margin: 4px 0; }
        .loading-cell {
            padding: 16px 8px;
            color: var(--vscode-descriptionForeground, #888);
            text-align: center;
            font-style: italic;
        }

        /* ─── Packet Table ──────────────────────────────────── */
        .packet-table-container { overflow: auto; }
        .packet-grid {
            display: flex;
            flex-direction: column;
            flex: 1 1 0;
            min-height: 0;
            overflow: hidden;
            position: relative;
        }
        .packet-header {
            display: grid;
            grid-template-columns: 60px 90px 140px 140px 70px 55px minmax(220px, 1fr);
            flex: 0 0 auto;
            background: var(--header-bg);
            border-bottom: 1px solid var(--border-color);
            font-family: var(--vscode-editor-font-family, 'Consolas', monospace);
            font-size: 12px;
            font-weight: 600;
        }
        .packet-header-cell {
            padding: 4px 8px;
            white-space: nowrap;
        }
        .packet-viewport {
            flex: 1 1 0;
            min-height: 0;
            overflow-y: auto;
            overflow-x: hidden;
            font-family: var(--vscode-editor-font-family, 'Consolas', monospace);
            font-size: 12px;
        }
        .packet-row {
            display: grid;
            grid-template-columns: 60px 90px 140px 140px 70px 55px minmax(220px, 1fr);
            height: 24px;
            cursor: pointer;
            border-bottom: 1px solid var(--border-color);
            align-items: center;
        }
        .packet-row:hover { background: var(--hover-bg); }
        .packet-row.selected { background: var(--selected-bg); color: var(--selected-fg); }
        .packet-cell {
            padding: 2px 8px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .packet-cell.col-no { text-align: right; color: var(--vscode-descriptionForeground, #888); }
        .packet-cell.col-len { text-align: right; }
        .packet-loading {
            padding: 16px 8px;
            color: var(--vscode-descriptionForeground, #888);
            text-align: center;
            font-style: italic;
        }
        .packet-window-busy {
            position: absolute;
            top: 36px;
            right: 12px;
            z-index: 3;
            padding: 4px 8px;
            border: 1px solid var(--border-color);
            border-radius: 3px;
            background: color-mix(in srgb, var(--header-bg) 92%, transparent);
            color: var(--vscode-descriptionForeground, #bbb);
            font-size: 11px;
            pointer-events: none;
            display: none;
        }
        .packet-window-busy.visible {
            display: block;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-family: var(--vscode-editor-font-family, 'Consolas', monospace);
            font-size: 12px;
        }
        thead { position: sticky; top: 0; z-index: 1; }
        thead th {
            background: var(--header-bg);
            padding: 4px 8px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            font-weight: 600;
            white-space: nowrap;
            user-select: none;
        }
        tbody tr { cursor: pointer; }
        tbody tr:hover { background: var(--hover-bg); }
        tbody tr.selected { background: var(--selected-bg); color: var(--selected-fg); }
        tbody td { padding: 2px 8px; white-space: nowrap; border-bottom: 1px solid var(--border-color); }
        .col-no { width: 60px; text-align: right; color: var(--vscode-descriptionForeground, #888); }
        .col-time { width: 90px; }
        .col-src, .col-dst { width: 140px; }
        .col-proto { width: 70px; font-weight: 600; }
        .col-len { width: 55px; text-align: right; }
        .col-info { overflow: hidden; text-overflow: ellipsis; max-width: 0; }

        /* Protocol colors (Wireshark-inspired) */
        tr.proto-tcp { background: rgba(228, 255, 199, 0.05); }
        tr.proto-http { background: rgba(228, 255, 199, 0.08); }
        tr.proto-tls, tr.proto-ssl { background: rgba(200, 230, 255, 0.06); }
        tr.proto-dns { background: rgba(200, 200, 255, 0.06); }
        tr.proto-arp { background: rgba(255, 240, 200, 0.06); }
        tr.proto-icmp { background: rgba(255, 200, 255, 0.06); }
        tr.row-error { background: var(--error-bg) !important; }
        tr.row-warning { background: var(--warning-bg) !important; }

        /* ─── Conversations Tab ─────────────────────────────── */
        .conv-table { width: 100%; }
        .conv-table td { padding: 4px 8px; }

        /* ─── Sidebar Panels ────────────────────────────────── */
        .side-panel { padding: 12px; overflow: auto; }
        .proto-item {
            display: flex;
            justify-content: space-between;
            padding: 3px 8px;
            border-bottom: 1px solid var(--border-color);
        }
        .proto-name { font-weight: 500; }
        .proto-count { color: var(--vscode-descriptionForeground, #888); }

        .expert-entry {
            padding: 4px 8px;
            font-family: var(--vscode-editor-font-family, monospace);
            font-size: 12px;
            border-left: 3px solid transparent;
            margin-bottom: 2px;
        }
        .expert-error { border-left-color: #f44; background: rgba(255,0,0,0.05); }
        .expert-warning { border-left-color: #fa0; background: rgba(255,165,0,0.05); }
        .expert-note { border-left-color: #0af; background: rgba(0,170,255,0.05); }

        .badge {
            display: inline-block;
            padding: 1px 6px;
            border-radius: 10px;
            font-size: 11px;
        }
        .badge-warning { background: rgba(255,165,0,0.2); color: #fa0; }
        .badge-ok { color: #4c4; }

        /* ─── Protocol Detail Tree ──────────────────────────── */
        .proto-tree { font-family: var(--vscode-editor-font-family, monospace); font-size: 12px; padding: 4px 0; }
        .proto-node { padding: 1px 0; line-height: 1.5; white-space: nowrap; }
        .proto-toggle { cursor: pointer; display: inline-block; width: 16px; text-align: center; font-size: 10px; color: var(--vscode-descriptionForeground, #888); user-select: none; vertical-align: middle; }
        .proto-toggle:hover { color: var(--vscode-foreground); }
        .proto-header { font-weight: 600; color: var(--vscode-foreground); }
        .proto-field { color: var(--vscode-foreground); }
        .proto-label { cursor: pointer; }
        .proto-label:hover { background: var(--hover-bg); }

        /* ─── Status bar ────────────────────────────────────── */
        .status-bar {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 3px 12px;
            background: var(--header-bg);
            border-top: 1px solid var(--border-color);
            font-size: 11px;
            color: var(--vscode-descriptionForeground, #888);
            flex-shrink: 0;
        }
    </style>
</head>
<body>
    <!-- Toolbar -->
    <div class="toolbar">
        <span class="title">📡 ${escapeHtml(captureName)}</span>
        <span class="stats" id="headerPacketStats">${initialHeaderStats}</span>
        <span class="spacer"></span>
        <button class="btn btn-secondary" id="btnToggleSidebar" title="Toggle sidebar (Ctrl+B)">☰</button>
        <button class="btn btn-ai" id="btnAnalyze">Analyze with Copilot</button>
        <button class="btn btn-secondary" id="btnRefresh">↻ Refresh</button>
        <button class="btn btn-secondary" id="btnClose">✕ Close</button>
    </div>

    <!-- Filter Bar -->
    <div class="filter-bar">
        <label>Filter:</label>
        <input type="text" id="filterInput" placeholder="Wireshark display filter (e.g., tcp.port == 443, http, dns.qry.name contains google)" value="${escapeHtml(this.currentFilter)}" />
        <button class="btn" id="btnApplyFilter">Apply</button>
        <button class="btn btn-secondary" id="btnClearFilter">✕</button>
        <span id="filterStatus" class="filter-hint"></span>
    </div>

    <!-- Tab Bar -->
    <div class="tab-bar">
        <div class="tab active" data-tab="packets">Packets</div>
        <div class="tab" data-tab="conversations">Conversations</div>
        <div class="tab" data-tab="protocols">Protocols</div>
        <div class="tab" data-tab="expert">Expert Info</div>
    </div>

    <!-- Content -->
    <div class="content">
        <!-- Packets Tab: Wireshark 3-pane layout -->
        <div class="tab-content active" id="tab-packets">
            <div class="ws-layout">
                <!-- TOP: Packet list -->
                <div class="ws-top">
                    <div class="packet-grid">
                        <div class="packet-header">
                            <div class="packet-header-cell col-no">No.</div>
                            <div class="packet-header-cell col-time">Time</div>
                            <div class="packet-header-cell col-src">Source</div>
                            <div class="packet-header-cell col-dst">Destination</div>
                            <div class="packet-header-cell col-proto">Protocol</div>
                            <div class="packet-header-cell col-len">Length</div>
                            <div class="packet-header-cell col-info">Info</div>
                        </div>
                        <div class="packet-window-busy" id="packetWindowBusy">Loading visible packets...</div>
                        <div class="packet-viewport" id="packetViewport">
                            <div class="packet-canvas" id="packetTableBody">
                                ${packetsHtml}
                            </div>
                        </div>
                    </div>
                </div>
                <div class="ws-splitter" id="wsBottomSplitter" role="separator" aria-orientation="horizontal" title="Drag to resize detail pane"></div>
                <!-- BOTTOM: Detail (left) + Hex (right), always visible -->
                <div class="ws-bottom" id="wsBottom">
                    <!-- Left: Protocol detail tree -->
                    <div class="ws-detail" id="detailPane">
                        <div class="ws-pane-header">
                            <span id="detailTitle">Packet Detail</span>
                            <button class="pane-toggle" id="btnToggleDetail" title="Minimize">&#x25bc;</button>
                        </div>
                        <div id="packetDetailContent" style="padding: 4px 8px;">
                            <div class="ws-empty">Click a packet above to see its protocol dissection</div>
                        </div>
                    </div>
                    <!-- Right: Hex dump -->
                    <div class="ws-hex" id="hexPane">
                        <div class="ws-pane-header">
                            <span>Packet Bytes</span>
                            <button class="pane-toggle" id="btnToggleHex" title="Minimize/Maximize">◀</button>
                        </div>
                        <div class="ws-pane-body">
                            <pre id="packetHexContent" style="padding: 4px 8px; margin: 0; color: var(--vscode-descriptionForeground);">Click a packet above to see hex dump</pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Conversations Tab -->
        <div class="tab-content" id="tab-conversations">
            <div class="packet-table-container">
                <table class="conv-table">
                    <thead>
                        <tr>
                            <th>Stream</th>
                            <th>Source</th>
                            <th>Destination</th>
                            <th>Packets</th>
                            <th>Bytes</th>
                            <th>Duration</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td colspan="8" class="loading-cell">Open this tab to load conversations</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Protocols Tab -->
        <div class="tab-content" id="tab-protocols">
            <div class="side-panel" id="protocolsContent">
                <h3 style="margin-bottom: 8px;">Protocol Hierarchy</h3>
                <p style="color:var(--vscode-descriptionForeground)" id="protocolsLoading">Open this tab to load protocol hierarchy</p>
            </div>
        </div>

        <!-- Expert Info Tab -->
        <div class="tab-content" id="tab-expert">
            <div class="side-panel" id="expertContent">
                <h3 style="margin-bottom: 8px;">Expert Information</h3>
                <p style="color:var(--vscode-descriptionForeground)" id="expertLoading">Open this tab to load expert information</p>
            </div>
        </div>
    </div>

    <!-- Status Bar -->
    <div class="status-bar">
        <span id="statusPacketCount">Showing ${packets.length} of ${packetCount} packets</span>
        <span id="statusFilter">${this.currentFilter ? `Filter: ${escapeHtml(this.currentFilter)}` : 'No filter applied'}</span>
        <span id="statusSelected"></span>
    </div>

    <script nonce="${nonce}">
        const vscode = acquireVsCodeApi();
        const filterInput = document.getElementById('filterInput');
        const packetTableBody = document.getElementById('packetTableBody');
        const packetScroller = document.getElementById('packetViewport');
        const packetWindowBusy = document.getElementById('packetWindowBusy');
        const wsLayout = document.querySelector('.ws-layout');
        const wsBottom = document.getElementById('wsBottom');
        const wsBottomSplitter = document.getElementById('wsBottomSplitter');
        const MIN_BOTTOM_HEIGHT = 80;
        const DEFAULT_BOTTOM_HEIGHT = 220;
        const VIRTUALIZATION_THRESHOLD = ${JSON.stringify(options.virtualizationThreshold)};
        const VIRTUAL_ROW_HEIGHT = 24;
        const VIRTUAL_OVERSCAN = 30;
        const requestedTabs = { conversations: false, protocols: false, expert: false };
        const pendingTabs = { conversations: false, protocols: false, expert: false };
        const PAGED_PACKET_WINDOW_SIZE = 1000;
        const PAGED_PACKET_BUFFER = 250;
        let isChunkedPacketView = ${JSON.stringify(options.isChunked)};
        let isPagedPacketView = ${JSON.stringify(!!options.isPagedPacketView)};
        let totalPacketCount = ${JSON.stringify(options.totalPacketCount ?? null)};
        let loadedPacketCount = ${JSON.stringify(options.loadedPacketCount)};
        let packetListLoaded = !isChunkedPacketView;
        let packetRows = [];
        let usingVirtualPacketList = false;
        let virtualRenderQueued = false;
        let packetWindowStart = 1;
        let packetWindowEnd = 0;
        let packetWindowRequestKey = '';
        let packetWindowLoading = false;

        // ══════════════════════════════════════════════════════
        // EVENT DELEGATION — no inline onclick needed (CSP safe)
        // ══════════════════════════════════════════════════════

        function updatePacketStatusText(filterValue) {
            var status = document.getElementById('statusPacketCount');
            if (filterValue) {
                status.textContent = isChunkedPacketView
                    ? 'Loading filtered packets...'
                    : 'Showing ' + loadedPacketCount + ' filtered packets';
                return;
            }
            if (isPagedPacketView && totalPacketCount !== null) {
                status.textContent = 'Showing ' + totalPacketCount + ' packets';
                return;
            }
            if (isChunkedPacketView) {
                status.textContent = 'Loading packet list...';
                return;
            }
            status.textContent = 'Showing ' + loadedPacketCount + ' packets';
        }

        function updateHeaderStatsText(filterValue) {
            var header = document.getElementById('headerPacketStats');
            if (!header) return;

            if (filterValue) {
                header.textContent = isChunkedPacketView
                    ? 'Loading filtered packets...'
                    : loadedPacketCount + ' filtered packets';
                return;
            }

            if (isChunkedPacketView) {
                header.textContent = 'Loading packet list...';
                return;
            }

            if (isPagedPacketView && totalPacketCount !== null) {
                header.textContent = totalPacketCount + ' packets';
                return;
            }

            header.textContent = loadedPacketCount + ' packets';
        }

        function renderPacketRow(p) {
            var protoClass = getProtocolClass(p.protocol);
            var selectedClass = selectedPacket === p.number ? ' selected' : '';
            return '<div class="packet-row ' + protoClass + selectedClass + '" data-packet="' + p.number + '" data-src="' + escapeHtml(p.source) + '" data-dst="' + escapeHtml(p.destination) + '" data-proto="' + escapeHtml(p.protocol) + '" data-stream="' + (p.stream || '') + '">' 
                + '<div class="packet-cell col-no">' + p.number + '</div>'
                + '<div class="packet-cell col-time">' + p.time + '</div>'
                + '<div class="packet-cell col-src">' + p.source + '</div>'
                + '<div class="packet-cell col-dst">' + p.destination + '</div>'
                + '<div class="packet-cell col-proto">' + p.protocol + '</div>'
                + '<div class="packet-cell col-len">' + p.length + '</div>'
                + '<div class="packet-cell col-info">' + escapeHtml(p.info) + '</div>'
                + '</div>';
        }

        function setPacketWindowBusy(isBusy) {
            if (!packetWindowBusy) return;
            packetWindowBusy.classList.toggle('visible', !!isBusy);
            if (isPagedPacketView) {
                document.getElementById('filterStatus').textContent = isBusy ? 'Loading visible packets...' : 'Packet list loaded';
                document.getElementById('filterStatus').className = 'filter-hint';
            }
        }

        function sizeViewport() {
            if (!packetScroller || !packetScroller.parentElement) return;
            var gridRect = packetScroller.parentElement.getBoundingClientRect();
            var headerEl = packetScroller.parentElement.querySelector('.packet-header');
            var headerH = headerEl ? headerEl.getBoundingClientRect().height : 0;
            var h = Math.floor(gridRect.height - headerH);
            if (h > 0) packetScroller.style.height = h + 'px';
        }

        function renderPacketRows() {
            if (!usingVirtualPacketList) {
                packetTableBody.innerHTML = packetRows.length > 0
                    ? packetRows.map(renderPacketRow).join('')
                    : '<div class="packet-loading">No packets available</div>';
                return;
            }

            sizeViewport();
            var totalRows = isPagedPacketView && totalPacketCount !== null ? totalPacketCount : packetRows.length;
            var startIndex = isPagedPacketView ? Math.max(0, packetWindowStart - 1) : 0;
            var endIndex = isPagedPacketView ? Math.min(totalRows, packetWindowEnd) : packetRows.length;
            var topSpacerHeight = startIndex * VIRTUAL_ROW_HEIGHT;
            var bottomSpacerHeight = Math.max(0, (totalRows - endIndex) * VIRTUAL_ROW_HEIGHT);
            var rowsHtml = '<div style="height:' + topSpacerHeight + 'px"></div>';
            for (var i = 0; i < packetRows.length; i++) {
                rowsHtml += renderPacketRow(packetRows[i]);
            }
            rowsHtml += '<div style="height:' + bottomSpacerHeight + 'px"></div>';
            packetTableBody.innerHTML = rowsHtml;
        }

        function requestPacketWindowForScroll(force) {
            if (!isPagedPacketView || !packetScroller || totalPacketCount === null || totalPacketCount <= 0) {
                return;
            }

            sizeViewport();
            var viewportHeight = packetScroller.clientHeight || 600;
            var scrollTop = packetScroller.scrollTop || 0;
            var visibleStart = Math.max(1, Math.floor(scrollTop / VIRTUAL_ROW_HEIGHT) + 1);
            var visibleEnd = Math.min(totalPacketCount, Math.ceil((scrollTop + viewportHeight) / VIRTUAL_ROW_HEIGHT));
            var nearTopEdge = visibleStart < (packetWindowStart + PAGED_PACKET_BUFFER);
            var nearBottomEdge = visibleEnd > (packetWindowEnd - PAGED_PACKET_BUFFER);
            var needWindow = force || packetWindowEnd < packetWindowStart || nearTopEdge || nearBottomEdge;

            if (!needWindow) {
                return;
            }

            var desiredStart = Math.max(1, visibleStart - Math.floor(PAGED_PACKET_WINDOW_SIZE / 2));
            var desiredEnd = Math.min(totalPacketCount, desiredStart + PAGED_PACKET_WINDOW_SIZE - 1);
            desiredStart = Math.max(1, desiredEnd - PAGED_PACKET_WINDOW_SIZE + 1);

            var requestKey = desiredStart + ':' + desiredEnd;
            if ((packetWindowLoading && !force) || requestKey === packetWindowRequestKey) {
                return;
            }

            packetWindowLoading = true;
            packetWindowRequestKey = requestKey;
            setPacketWindowBusy(true);
            vscode.postMessage({ command: 'requestPacketWindow', startFrame: desiredStart, endFrame: desiredEnd });
        }

        function queueVirtualRender() {
            if (!usingVirtualPacketList || virtualRenderQueued) {
                return;
            }
            virtualRenderQueued = true;
            requestAnimationFrame(function() {
                virtualRenderQueued = false;
                renderPacketRows();
            });
        }

        function setPacketRows(nextPackets) {
            packetRows = Array.isArray(nextPackets) ? nextPackets : [];
            usingVirtualPacketList = isPagedPacketView;
            if (packetScroller) {
                packetScroller.scrollTop = 0;
            }
            sizeViewport();
            renderPacketRows();
        }

        function setBottomHeight(heightPx) {
            if (!wsLayout) return;
            var layoutHeight = wsLayout.getBoundingClientRect().height || 0;
            var maxHeight = Math.max(MIN_BOTTOM_HEIGHT, Math.floor(layoutHeight * 0.75));
            var nextHeight = Math.max(MIN_BOTTOM_HEIGHT, Math.min(heightPx, maxHeight));
            wsLayout.style.setProperty('--ws-bottom-height', nextHeight + 'px');
            wsBottom.dataset.lastHeight = String(nextHeight);
        }

        function restoreBottomHeight() {
            var lastHeight = parseInt(wsBottom.dataset.lastHeight || '', 10);
            setBottomHeight(Number.isNaN(lastHeight) ? DEFAULT_BOTTOM_HEIGHT : lastHeight);
        }

        (function initializeBottomResizer() {
            if (!wsBottomSplitter || !wsLayout) return;

            var dragging = false;

            function stopDragging() {
                if (!dragging) return;
                dragging = false;
                wsBottomSplitter.classList.remove('dragging');
                document.body.style.cursor = '';
                document.body.style.userSelect = '';
            }

            wsBottomSplitter.addEventListener('mousedown', function(e) {
                if (wsBottom.classList.contains('collapsed')) return;
                dragging = true;
                wsBottomSplitter.classList.add('dragging');
                document.body.style.cursor = 'row-resize';
                document.body.style.userSelect = 'none';
                e.preventDefault();
            });

            window.addEventListener('mousemove', function(e) {
                if (!dragging || !wsLayout) return;
                var layoutRect = wsLayout.getBoundingClientRect();
                setBottomHeight(layoutRect.bottom - e.clientY);
            });

            window.addEventListener('mouseup', stopDragging);
            window.addEventListener('mouseleave', stopDragging);

            restoreBottomHeight();
        })();

        // Toolbar buttons
        document.getElementById('btnAnalyze').addEventListener('click', function() {
            vscode.postMessage({ command: 'analyzeWithAI', prompt: 'Analyze this capture. Give me an overview and highlight anything suspicious or problematic.' });
        });
        document.getElementById('btnRefresh').addEventListener('click', function() {
            vscode.postMessage({ command: 'refreshData' });
        });
        document.getElementById('btnClose').addEventListener('click', function() {
            vscode.postMessage({ command: 'closeCapture' });
        });
        document.getElementById('btnToggleSidebar').addEventListener('click', function() {
            vscode.postMessage({ command: 'toggleSidebar' });
        });

        // Filter buttons
        document.getElementById('btnApplyFilter').addEventListener('click', applyFilter);
        document.getElementById('btnClearFilter').addEventListener('click', clearFilter);
        filterInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') applyFilter();
            if (e.key === 'Escape') clearFilter();
        });

        // Tab switching — delegate from tab bar
        document.querySelector('.tab-bar').addEventListener('click', function(e) {
            var tab = e.target.closest('.tab');
            if (!tab) return;
            var tabName = tab.getAttribute('data-tab');
            if (!tabName) return;
            document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
            document.querySelectorAll('.tab-content').forEach(function(t) { t.classList.remove('active'); });
            tab.classList.add('active');
            document.getElementById('tab-' + tabName).classList.add('active');

            if (tabName === 'packets') {
                sizeViewport();
                renderPacketRows();
                if (isPagedPacketView) {
                    setPacketWindowBusy(packetWindowLoading);
                    requestPacketWindowForScroll(false);
                }
            }

            if (tabName !== 'packets' && !requestedTabs[tabName]) {
                if (!packetListLoaded) {
                    pendingTabs[tabName] = true;
                    if (tabName === 'conversations') {
                        document.querySelector('#tab-conversations tbody').innerHTML = '<tr><td colspan="8" class="loading-cell">Packet list is still loading. Conversations will load next.</td></tr>';
                    } else if (tabName === 'protocols') {
                        document.getElementById('protocolsContent').innerHTML = '<h3 style="margin-bottom: 8px;">Protocol Hierarchy</h3><p style="color:var(--vscode-descriptionForeground)">Packet list is still loading. Protocol hierarchy will load next.</p>';
                    } else if (tabName === 'expert') {
                        document.getElementById('expertContent').innerHTML = '<h3 style="margin-bottom: 8px;">Expert Information</h3><p style="color:var(--vscode-descriptionForeground)">Packet list is still loading. Expert info will load next.</p>';
                    }
                    return;
                }
                requestedTabs[tabName] = true;
                if (tabName === 'conversations') {
                    document.querySelector('#tab-conversations tbody').innerHTML = '<tr><td colspan="8" class="loading-cell">Loading conversations...</td></tr>';
                } else if (tabName === 'protocols') {
                    document.getElementById('protocolsContent').innerHTML = '<h3 style="margin-bottom: 8px;">Protocol Hierarchy</h3><p style="color:var(--vscode-descriptionForeground)">Loading protocol hierarchy...</p>';
                } else if (tabName === 'expert') {
                    document.getElementById('expertContent').innerHTML = '<h3 style="margin-bottom: 8px;">Expert Information</h3><p style="color:var(--vscode-descriptionForeground)">Loading expert information...</p>';
                }
                vscode.postMessage({ command: 'loadTabData', tab: tabName });
            }
        });

        // Packet table — click on any row to select it
        document.getElementById('packetTableBody').addEventListener('click', function(e) {
            var row = e.target.closest('[data-packet]');
            if (!row) return;
            var num = parseInt(row.getAttribute('data-packet'));
            if (isNaN(num)) return;
            selectPacket(num);
        });

        // Packet table — right-click context menu
        document.getElementById('packetTableBody').addEventListener('contextmenu', function(e) {
            e.preventDefault();
            var row = e.target.closest('[data-packet]');
            if (!row) return;
            // Select the row first
            var num = parseInt(row.getAttribute('data-packet'));
            if (!isNaN(num)) selectPacket(num);
            showContextMenu(e.clientX, e.clientY, row);
        });

        if (packetScroller) {
            packetScroller.addEventListener('scroll', function() {
                if (isPagedPacketView) {
                    requestPacketWindowForScroll(false);
                }
                queueVirtualRender();
            });
        }

        // Resize: recompute viewport height and re-render virtual rows
        var resizeTimer = null;
        window.addEventListener('resize', function() {
            if (resizeTimer) clearTimeout(resizeTimer);
            resizeTimer = setTimeout(function() {
                resizeTimer = null;
                if (usingVirtualPacketList) {
                    sizeViewport();
                    renderPacketRows();
                }
            }, 100);
        });

        // Close context menu on click elsewhere
        document.addEventListener('click', function(e) {
            var menu = document.getElementById('ctxMenu');
            if (menu && !menu.contains(e.target)) {
                menu.remove();
            }
            // Also handle action buttons (conversations tab)
            var btn = e.target.closest('[data-action]');
            if (!btn) return;
            var action = btn.getAttribute('data-action');
            var stream = parseInt(btn.getAttribute('data-stream'));
            if (action === 'analyzeStream') {
                vscode.postMessage({ command: 'analyzeStream', streamIndex: stream });
            } else if (action === 'filterStream') {
                filterInput.value = 'tcp.stream == ' + stream;
                applyFilter();
            }
        });

        // Detail pane toggle — collapses entire bottom section to give packet list more space
        document.getElementById('btnToggleDetail').addEventListener('click', function() {
            var btn = document.getElementById('btnToggleDetail');
            if (wsBottom.classList.contains('collapsed')) {
                wsBottom.classList.remove('collapsed');
                wsLayout.classList.remove('bottom-collapsed');
                restoreBottomHeight();
                btn.textContent = '\u25bc';
                btn.title = 'Minimize';
            } else {
                wsBottom.dataset.lastHeight = String(wsBottom.getBoundingClientRect().height || DEFAULT_BOTTOM_HEIGHT);
                wsBottom.classList.add('collapsed');
                wsLayout.classList.add('bottom-collapsed');
                btn.textContent = '\u25b2';
                btn.title = 'Maximize';
            }
        });

        // Hex pane toggle
        document.getElementById('btnToggleHex').addEventListener('click', function() {
            var hexPane = document.getElementById('hexPane');
            var btn = document.getElementById('btnToggleHex');
            if (hexPane.classList.contains('collapsed')) {
                hexPane.classList.remove('collapsed');
                btn.textContent = '\u25c0';
                btn.title = 'Minimize';
            } else {
                hexPane.classList.add('collapsed');
                btn.textContent = '\u25b6';
                btn.title = 'Maximize';
            }
        });

        // Protocol tree toggle — delegate from detail pane
        document.getElementById('packetDetailContent').addEventListener('click', function(e) {
            var toggle = e.target.closest('.proto-toggle');
            if (!toggle) return;
            var targetId = toggle.getAttribute('data-toggle');
            if (!targetId) return;
            var el = document.getElementById(targetId);
            if (!el) return;
            if (el.style.display === 'none') {
                el.style.display = 'block';
                toggle.textContent = '▼';
            } else {
                el.style.display = 'none';
                toggle.textContent = '▶';
            }
        });

        // ══════════════════════════════════════════════════════
        // FUNCTIONS
        // ══════════════════════════════════════════════════════

        function showContextMenu(x, y, row) {
            // Remove any existing menu
            var old = document.getElementById('ctxMenu');
            if (old) old.remove();

            var src = row.getAttribute('data-src') || '';
            var dst = row.getAttribute('data-dst') || '';
            var proto = row.getAttribute('data-proto') || '';
            var stream = row.getAttribute('data-stream') || '';
            var packetNum = row.getAttribute('data-packet') || '';

            var menu = document.createElement('div');
            menu.id = 'ctxMenu';
            menu.className = 'ctx-menu';
            menu.style.left = x + 'px';
            menu.style.top = y + 'px';

            var items = [];

            if (stream !== '') {
                items.push({ label: 'Filter: TCP Conversation (stream ' + stream + ')', filter: 'tcp.stream == ' + stream });
            }
            if (src) {
                items.push({ label: 'Filter: Source \u2192 ' + src, filter: 'ip.addr == ' + src });
            }
            if (dst) {
                items.push({ label: 'Filter: Destination \u2192 ' + dst, filter: 'ip.addr == ' + dst });
            }
            if (src && dst) {
                items.push({ label: 'Filter: Conversation ' + src + ' \u2194 ' + dst, filter: 'ip.addr == ' + src + ' && ip.addr == ' + dst });
            }
            if (proto) {
                items.push({ label: 'Filter: Protocol ' + proto, filter: proto.toLowerCase() });
            }
            items.push(null); // separator
            items.push({ label: 'Analyze Packet #' + packetNum + ' with AI', action: 'analyzePacket', packet: packetNum });
            if (stream !== '') {
                items.push({ label: 'Analyze TCP Stream ' + stream + ' with AI', action: 'analyzeStream', stream: stream });
            }

            for (var i = 0; i < items.length; i++) {
                if (items[i] === null) {
                    var sep = document.createElement('div');
                    sep.className = 'ctx-menu-sep';
                    menu.appendChild(sep);
                } else {
                    var mi = document.createElement('div');
                    mi.className = 'ctx-menu-item';
                    mi.textContent = items[i].label;
                    (function(item) {
                        mi.addEventListener('click', function() {
                            menu.remove();
                            if (item.filter) {
                                filterInput.value = item.filter;
                                applyFilter();
                            } else if (item.action === 'analyzePacket') {
                                vscode.postMessage({ command: 'analyzePacket', packetNumber: item.packet });
                            } else if (item.action === 'analyzeStream') {
                                vscode.postMessage({ command: 'analyzeStream', streamIndex: parseInt(item.stream) });
                            }
                        });
                    })(items[i]);
                    menu.appendChild(mi);
                }
            }

            document.body.appendChild(menu);

            // Keep menu in viewport
            var rect = menu.getBoundingClientRect();
            if (rect.right > window.innerWidth) menu.style.left = (window.innerWidth - rect.width - 4) + 'px';
            if (rect.bottom > window.innerHeight) menu.style.top = (window.innerHeight - rect.height - 4) + 'px';
        }

        function applyFilter() {
            var filter = filterInput.value.trim();
            document.getElementById('filterStatus').textContent = 'Applying...';
            document.getElementById('filterStatus').className = 'filter-hint';
            filterInput.classList.remove('filter-error');
            vscode.postMessage({ command: 'applyFilter', filter: filter });
        }

        function clearFilter() {
            filterInput.value = '';
            document.getElementById('filterStatus').textContent = '';
            filterInput.classList.remove('filter-error');
            vscode.postMessage({ command: 'clearFilter' });
        }

        function loadPendingTabs() {
            ['conversations', 'protocols', 'expert'].forEach(function(tabName) {
                if (!pendingTabs[tabName] || requestedTabs[tabName]) {
                    return;
                }
                pendingTabs[tabName] = false;
                requestedTabs[tabName] = true;
                if (tabName === 'conversations') {
                    document.querySelector('#tab-conversations tbody').innerHTML = '<tr><td colspan="8" class="loading-cell">Loading conversations...</td></tr>';
                } else if (tabName === 'protocols') {
                    document.getElementById('protocolsContent').innerHTML = '<h3 style="margin-bottom: 8px;">Protocol Hierarchy</h3><p style="color:var(--vscode-descriptionForeground)">Loading protocol hierarchy...</p>';
                } else if (tabName === 'expert') {
                    document.getElementById('expertContent').innerHTML = '<h3 style="margin-bottom: 8px;">Expert Information</h3><p style="color:var(--vscode-descriptionForeground)">Loading expert information...</p>';
                }
                vscode.postMessage({ command: 'loadTabData', tab: tabName });
            });
        }

        var selectedPacket = null;

        function selectPacket(num) {
            if (isChunkedPacketView && !packetListLoaded) {
                document.getElementById('statusSelected').textContent = 'Packet list is still loading';
                return;
            }
            selectedPacket = num;
            if (usingVirtualPacketList) {
                var packetIndex = isPagedPacketView
                    ? (num - 1)
                    : packetRows.findIndex(function(packet) { return packet.number === num; });
                if (packetIndex >= 0 && packetScroller) {
                    var targetTop = Math.max(0, (packetIndex * VIRTUAL_ROW_HEIGHT) - Math.floor((packetScroller.clientHeight || 400) / 2));
                    packetScroller.scrollTop = targetTop;
                    if (isPagedPacketView) {
                        requestPacketWindowForScroll(true);
                    }
                    renderPacketRows();
                }
            } else {
                document.querySelectorAll('#packetTableBody .selected').forEach(function(r) { r.classList.remove('selected'); });
                var row = document.querySelector('#packetTableBody [data-packet="' + num + '"]');
                if (row) {
                    row.classList.add('selected');
                }
            }
            document.getElementById('statusSelected').textContent = 'Packet #' + num + ' selected';
            document.getElementById('detailTitle').textContent = 'Packet #' + num + ' Detail';
            document.getElementById('packetDetailContent').innerHTML = '<div style="color:var(--vscode-descriptionForeground);padding:8px;">Loading packet detail...</div>';
            document.getElementById('packetHexContent').textContent = 'Loading hex dump...';
            vscode.postMessage({ command: 'getPacketDetail', frameNumber: num });
            vscode.postMessage({ command: 'getPacketHex', frameNumber: num });
        }

        function getProtocolClass(proto) {
            var p = (proto || '').toLowerCase();
            if (p === 'tcp') return 'proto-tcp';
            if (p === 'http' || p === 'http/1.1' || p === 'http2') return 'proto-http';
            if (p === 'tls' || p === 'ssl' || p === 'tls1.2' || p === 'tls1.3') return 'proto-tls';
            if (p === 'dns') return 'proto-dns';
            if (p === 'arp') return 'proto-arp';
            if (p === 'icmp' || p === 'icmpv6') return 'proto-icmp';
            return '';
        }

        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        // ═══ Protocol tree rendering ══════════════════════════
        function renderProtoTree(nodes) {
            if (!nodes || nodes.length === 0) return '<div style="padding:8px;color:var(--vscode-descriptionForeground);">No detail available.</div>';
            var html = '<div class="proto-tree">';
            for (var i = 0; i < nodes.length; i++) {
                // Only expand the last protocol node (transport/app layer)
                var isLast = (i === nodes.length - 1);
                html += renderProtoNode(nodes[i], 0, isLast);
            }
            html += '</div>';
            return html;
        }

        function renderProtoNode(node, depth, startExpanded) {
            var hasChildren = node.children && node.children.length > 0;
            var indent = depth * 16;
            var id = 'pn_' + Math.random().toString(36).substr(2, 9);
            var expanded = startExpanded === true;

            var html = '<div class="proto-node" style="padding-left:' + indent + 'px;">';
            if (hasChildren) {
                var arrow = expanded ? '▼' : '▶';
                var displayStyle = expanded ? 'block' : 'none';
                html += '<span class="proto-toggle" data-toggle="' + id + '" id="toggle_' + id + '">' + arrow + '</span> ';
                html += '<span class="proto-label ' + (depth === 0 ? 'proto-header' : 'proto-field') + '">' + escapeHtml(node.showname) + '</span>';
                html += '<div class="proto-children" id="' + id + '" style="display:' + displayStyle + ';">';
                for (var ci = 0; ci < node.children.length; ci++) {
                    html += renderProtoNode(node.children[ci], depth + 1, false);
                }
                html += '</div>';
            } else {
                html += '<span style="display:inline-block;width:16px;"></span> ';
                html += '<span class="proto-field">' + escapeHtml(node.showname) + '</span>';
            }
            html += '</div>';
            return html;
        }

        // ═══ Messages from extension ══════════════════════════
        window.addEventListener('message', function(event) {
            var msg = event.data;
            switch (msg.command) {
                case 'replacePackets': {
                    var wasLoading = isChunkedPacketView;
                    setPacketWindowBusy(false);
                    isPagedPacketView = false;
                    setPacketRows(msg.packets);
                    isChunkedPacketView = !!msg.isChunked;
                    loadedPacketCount = msg.packets.length;
                    totalPacketCount = typeof msg.totalCount === 'number' ? msg.totalCount : null;
                    packetListLoaded = !isChunkedPacketView;
                    updatePacketStatusText(msg.filter);
                    updateHeaderStatsText(msg.filter);
                    document.getElementById('statusFilter').textContent = msg.filter ? 'Filter: ' + msg.filter : 'No filter applied';
                    document.getElementById('filterStatus').textContent = msg.filter
                        ? msg.packets.length + ' packets match'
                        : 'Packet list loaded';
                    document.getElementById('filterStatus').className = 'filter-hint';
                    if (wasLoading && !isChunkedPacketView) {
                        loadPendingTabs();
                    }
                    break;
                }
                case 'packetWindow': {
                    packetWindowLoading = false;
                    setPacketWindowBusy(false);
                    packetWindowStart = Math.max(1, msg.startFrame || 1);
                    packetWindowEnd = Math.max(packetWindowStart, msg.endFrame || packetWindowStart);
                    packetRows = Array.isArray(msg.packets) ? msg.packets : [];
                    usingVirtualPacketList = true;
                    isChunkedPacketView = false;
                    packetListLoaded = true;
                    loadedPacketCount = packetRows.length;
                    totalPacketCount = typeof msg.totalCount === 'number' ? msg.totalCount : totalPacketCount;
                    updatePacketStatusText(msg.filter);
                    updateHeaderStatsText(msg.filter);
                    document.getElementById('statusFilter').textContent = msg.filter ? 'Filter: ' + msg.filter : 'No filter applied';
                    document.getElementById('filterStatus').textContent = 'Packet list loaded';
                    document.getElementById('filterStatus').className = 'filter-hint';
                    renderPacketRows();
                    loadPendingTabs();
                    break;
                }
                case 'packetChunkError': {
                    packetListLoaded = true;
                    isChunkedPacketView = false;
                    packetWindowLoading = false;
                    setPacketWindowBusy(false);
                    document.getElementById('statusSelected').textContent = msg.message;
                    break;
                }
                case 'updateConversations': {
                    document.querySelector('#tab-conversations tbody').innerHTML = msg.html;
                    break;
                }
                case 'updateProtocols': {
                    document.getElementById('protocolsContent').innerHTML = '<h3 style="margin-bottom: 8px;">Protocol Hierarchy</h3>' + msg.html;
                    break;
                }
                case 'updateExpertInfo': {
                    document.getElementById('expertContent').innerHTML = '<h3 style="margin-bottom: 8px;">Expert Information</h3>' + msg.html;
                    break;
                }
                case 'filterError': {
                    packetListLoaded = true;
                    document.getElementById('filterStatus').textContent = msg.message;
                    document.getElementById('filterStatus').className = 'filter-error-msg';
                    document.getElementById('filterInput').classList.add('filter-error');
                    break;
                }
                case 'packetDetail': {
                    document.getElementById('packetDetailContent').innerHTML = renderProtoTree(msg.tree);
                    break;
                }
                case 'packetDetailRaw': {
                    document.getElementById('packetDetailContent').innerHTML = '<pre style="margin:0;padding:8px;font-size:12px;white-space:pre-wrap;word-break:break-all;">' + escapeHtml(msg.text) + '</pre>';
                    break;
                }
                case 'packetHex': {
                    document.getElementById('packetHexContent').textContent = msg.hex;
                    break;
                }
                case 'error': {
                    packetWindowLoading = false;
                    setPacketWindowBusy(false);
                    document.getElementById('statusSelected').textContent = msg.message;
                    break;
                }
                case 'applyFilterExt': {
                    // Applied from chat or external command. Backend owns the re-query.
                    filterInput.value = msg.filter || '';
                    document.getElementById('filterStatus').textContent = '';
                    document.getElementById('filterInput').classList.remove('filter-error');
                    break;
                }
            }
        });

        updatePacketStatusText(${JSON.stringify(options.filter)});
        updateHeaderStatsText(${JSON.stringify(options.filter)});
        if (isChunkedPacketView) {
            document.getElementById('filterStatus').textContent = 'Loading packet list...';
            document.getElementById('filterStatus').className = 'filter-hint';
        }
        if (isPagedPacketView) {
            requestPacketWindowForScroll(true);
        }
    </script>
</body>
</html>`;
    }

    dispose(): void {
        for (const d of this.disposables) {
            d.dispose();
        }
        this.disposables = [];
    }
}

// ─── Helper types and functions ───────────────────────────────────────────

type PacketRow = ParsedPacketRow;

function getNonce(): string {
    let text = '';
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < 32; i++) {
        text += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return text;
}

function escapeHtml(str: string): string {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function formatBytes(bytes: number): string {
    if (bytes < 1024) { return `${bytes} B`; }
    if (bytes < 1024 * 1024) { return `${(bytes / 1024).toFixed(1)} KB`; }
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function getProtocolClass(protocol: string): string {
    const p = (protocol || '').toLowerCase();
    if (p === 'tcp') { return 'proto-tcp'; }
    if (p.includes('http')) { return 'proto-http'; }
    if (p.includes('tls') || p.includes('ssl')) { return 'proto-tls'; }
    if (p === 'dns') { return 'proto-dns'; }
    if (p === 'arp') { return 'proto-arp'; }
    if (p.includes('icmp')) { return 'proto-icmp'; }
    return '';
}

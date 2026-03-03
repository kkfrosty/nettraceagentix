import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as crypto from 'crypto';
import { TsharkRunner } from '../parsing/tsharkRunner';
import { NetworkInterface, LiveCaptureSession } from '../types';

/** Options to pre-fill the panel when opened via AI or command. */
export interface LiveCapturePrefill {
    /** tshark interface name to pre-select */
    suggestedInterface?: string;
    /** BPF capture filter expression to pre-populate */
    captureFilter?: string;
    /** Display filter to pre-populate */
    displayFilter?: string;
    /** Auto-start the capture immediately after the panel opens */
    autoStart?: boolean;
}

/**
 * Live Capture Webview Panel — Wireshark-style capture dialog inside VS Code.
 *
 * States:
 *   configure  → Interface/filter controls. User clicks Start or autoStart fires.
 *   capturing  → Controls locked, packet rows stream in every 1.5 s, status bar updates.
 *   stopped    → Full packet table + stream/expert sidebar + Analyze AI / New Capture buttons.
 */
export class LiveCaptureWebviewPanel {
    public static readonly viewType = 'nettrace.liveCapture';

    /** Only one live capture panel at a time. */
    private static instance: LiveCaptureWebviewPanel | undefined;

    private readonly panel: vscode.WebviewPanel;
    private readonly extensionUri: vscode.Uri;
    private disposables: vscode.Disposable[] = [];

    private session: LiveCaptureSession | undefined;
    private refreshTimer: ReturnType<typeof setInterval> | undefined;
    private startTime: Date | undefined;

    /** Last display filter the user set — preserved across New Capture resets. */
    private lastDisplayFilter: string = '';
    private lastPushedLivePreviewCount: number = 0;
    private lastLoggedLivePreviewCount: number = 0;

    // ─── Static API ───────────────────────────────────────────────────────

    /**
     * Open or reveal the live capture panel, optionally pre-filling controls.
     */
    public static async createOrShow(
        extensionUri: vscode.Uri,
        tsharkRunner: TsharkRunner,
        outputChannel: vscode.OutputChannel,
        prefill?: LiveCapturePrefill
    ): Promise<LiveCaptureWebviewPanel> {
        if (LiveCaptureWebviewPanel.instance) {
            LiveCaptureWebviewPanel.instance.panel.reveal(vscode.ViewColumn.One);
            if (prefill) {
                LiveCaptureWebviewPanel.instance.applyPrefill(prefill);
            }
            return LiveCaptureWebviewPanel.instance;
        }

        // Fetch interfaces BEFORE creating the panel so they can be baked
        // directly into the HTML as a JSON constant.  No postMessage, no
        // webviewReady handshake, no race conditions.
        outputChannel.appendLine('[LiveCapture] Fetching interfaces…');
        let initialInterfaces: NetworkInterface[] = [];
        let initialError: string | undefined;
        try {
            initialInterfaces = await tsharkRunner.listNetworkInterfaces();
            outputChannel.appendLine(`[LiveCapture] Got ${initialInterfaces.length} interface(s): ${initialInterfaces.map(i => i.name).join(', ')}`);
        } catch (e) {
            initialError = `Could not list interfaces: ${e}\n\nMake sure tshark/Wireshark is installed.`;
            outputChannel.appendLine(`[LiveCapture] Interface fetch error: ${e}`);
        }

        const panel = vscode.window.createWebviewPanel(
            LiveCaptureWebviewPanel.viewType,
            '⏺ Live Capture',
            vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'media')],
            }
        );
        const instance = new LiveCaptureWebviewPanel(
            panel, extensionUri, tsharkRunner, outputChannel, prefill,
            initialInterfaces, initialError
        );
        LiveCaptureWebviewPanel.instance = instance;
        return instance;
    }

    public static getActivePanel(): LiveCaptureWebviewPanel | undefined {
        return LiveCaptureWebviewPanel.instance;
    }

    // ─── Constructor ──────────────────────────────────────────────────────

    private constructor(
        panel: vscode.WebviewPanel,
        extensionUri: vscode.Uri,
        private tsharkRunner: TsharkRunner,
        private outputChannel: vscode.OutputChannel,
        private prefill?: LiveCapturePrefill,
        initialInterfaces: NetworkInterface[] = [],
        initialError?: string
    ) {
        this.panel = panel;
        this.extensionUri = extensionUri;

        // Register the message listener BEFORE setting html to avoid any race.
        this.panel.webview.onDidReceiveMessage(
            async (msg) => this.handleMessage(msg),
            null,
            this.disposables
        );

        // Interfaces are baked into the HTML — no postMessage handshake needed.
        this.panel.webview.html = this.getHtml(initialInterfaces, initialError);

        // Force the Output panel open and select this channel so log messages are visible.
        this.outputChannel.show(true);
        this.outputChannel.appendLine('[LiveCapture] Panel created, HTML set, waiting for webview script to start…');

        this.panel.onDidDispose(() => {
            this.teardown();
            LiveCaptureWebviewPanel.instance = undefined;
        }, null, this.disposables);
    }

    private applyPrefill(prefill: LiveCapturePrefill): void {
        this.prefill = prefill;
        this.postMessage({
            command: 'applyPrefill',
            suggestedInterface: prefill.suggestedInterface,
            captureFilter: prefill.captureFilter ?? '',
            displayFilter: prefill.displayFilter ?? '',
        });
        if (prefill.autoStart && prefill.suggestedInterface) {
            setTimeout(() => this.postMessage({ command: 'triggerAutoStart' }), 300);
        }
    }

    // ─── Message Bus ──────────────────────────────────────────────────────

    private async handleMessage(msg: any): Promise<void> {
        try {
            await this.handleMessageInner(msg);
        } catch (e) {
            this.outputChannel.appendLine(`[LiveCapture] Unhandled error in message handler (${msg?.command}): ${e}`);
        }
    }

    private async handleMessageInner(msg: any): Promise<void> {
        switch (msg.command) {
            case 'log':
                this.outputChannel.show(true);
                this.outputChannel.appendLine(`[LiveCapture:webview] ${msg.text}`);
                break;
            case 'showError':
                this.outputChannel.appendLine(`[LiveCapture:ERROR] ${msg.message}`);
                vscode.window.showErrorMessage(`NetTrace Live Capture: ${msg.message}`);
                break;
            case 'startCapture':
                this.outputChannel.show(true);  // force Output panel open so user can see logs
                this.outputChannel.appendLine(`[LiveCapture] Received startCapture message: iface=${msg.interfaceName}`);
                await this.startCapture(msg.interfaceName, msg.interfaceDisplayName, msg.captureFilter, msg.displayFilter, msg.captureName);
                break;
            case 'stopCapture':
                this.stopCapture();
                break;
            case 'newCapture':
                this.newCapture();
                break;
            case 'refreshInterfaces': {
                let ifaces: NetworkInterface[] = [];
                try { ifaces = await this.tsharkRunner.listNetworkInterfaces(); } catch (e) { /* ignore */ }
                this.postMessage({ command: 'setInterfaces', interfaces: ifaces });
                break;
            }
            case 'updateDisplayFilter':
                this.lastDisplayFilter = msg.filter ?? '';
                await this.applyDisplayFilterToPanel();
                break;
            case 'analyzeWithAI':
                await this.analyzeWithAI(msg);
                break;
            case 'analyzePacket':
                await vscode.commands.executeCommand('workbench.action.chat.open', {
                    query: `@nettrace Look at packet #${msg.packetNumber} in detail. What's happening and is there an issue?`,
                });
                break;
            case 'analyzeStream':
                await vscode.commands.executeCommand('workbench.action.chat.open', {
                    query: `@nettrace /stream ${msg.streamIndex} Analyze this stream in detail.`,
                });
                break;
            case 'getPacketDetail':
                if (this.session?.outputFilePath) {
                    try {
                        const detail = await this.tsharkRunner.getPacketDetail(this.session.outputFilePath, msg.frameNumber);
                        const pdml = await this.tsharkRunner.getPacketDetailPdml(this.session.outputFilePath, msg.frameNumber).catch(() => '');
                        if (pdml) {
                            this.postMessage({ command: 'packetDetail', frameNumber: msg.frameNumber, pdml, raw: detail });
                        } else {
                            this.postMessage({ command: 'packetDetailRaw', frameNumber: msg.frameNumber, text: detail });
                        }
                    } catch (e) { /* ignore */ }
                }
                break;
            case 'getPacketHex':
                if (this.session?.outputFilePath) {
                    try {
                        const hex = await this.tsharkRunner.getPacketHexDump(this.session.outputFilePath, msg.frameNumber);
                        this.postMessage({ command: 'packetHex', frameNumber: msg.frameNumber, hex });
                    } catch (e) { /* ignore */ }
                }
                break;
        }
    }

    // ─── Capture Lifecycle ────────────────────────────────────────────────

    /** Called by the webview 'startCapture' message. */
    private async startCapture(
        interfaceName: string,
        interfaceDisplayName: string,
        captureFilter: string,
        displayFilter: string,
        captureName?: string
    ): Promise<void> {
        if (this.session && this.session.status !== 'stopped' && this.session.status !== 'error') {
            this.outputChannel.appendLine(`[LiveCapture] Ignoring startCapture: existing session ${this.session.id} is ${this.session.status}`);
            return;
        }

        const sessionId = crypto.randomUUID();
        const outputFile = this.resolveLiveCaptureOutputPath(interfaceName, captureName);

        // Ensure the output directory exists.
        try {
            fs.mkdirSync(path.dirname(outputFile), { recursive: true });
        } catch (e) {
            this.postMessage({ command: 'captureError', message: `Could not create output directory: ${e}` });
            return;
        }

        this.lastDisplayFilter = displayFilter;
        this.startTime = new Date();

        const session: LiveCaptureSession = {
            id: sessionId,
            interfaceName,
            interfaceDisplayName,
            captureFilter,
            displayFilter,
            outputFilePath: outputFile,
            status: 'starting',
            packetCount: 0,
            startTime: this.startTime,
            livePreviewPackets: [],
        };
        this.session = session;
        this.lastPushedLivePreviewCount = 0;
        this.lastLoggedLivePreviewCount = 0;

        this.outputChannel.appendLine(`[LiveCapture] Starting capture on ${interfaceName} → ${outputFile}`);

        let captureStartedNotified = false;
        this.tsharkRunner.startLiveCapture(session, (s) => {
            if (s.status === 'error') {
                this.clearRefreshTimer();
                this.postMessage({ command: 'captureError', message: s.errorMessage ?? 'Unknown capture error' });
                vscode.commands.executeCommand('setContext', 'nettrace.isCapturing', false);
                return;
            }
            if (s.status === 'capturing') {
                if (!captureStartedNotified) {
                    captureStartedNotified = true;
                    this.postMessage({ command: 'captureStarted', sessionId: s.id, outputFile: s.outputFilePath });
                    vscode.commands.executeCommand('setContext', 'nettrace.isCapturing', true);
                    this.startRefreshTimer();
                }
            }

            if (s.livePreviewPackets && s.livePreviewPackets.length > 0) {
                if (s.livePreviewPackets.length !== this.lastPushedLivePreviewCount) {
                    this.lastPushedLivePreviewCount = s.livePreviewPackets.length;
                    this.postMessage({ command: 'updatePackets', packets: s.livePreviewPackets, isFinal: false });

                    if (
                        s.livePreviewPackets.length <= 5 ||
                        s.livePreviewPackets.length - this.lastLoggedLivePreviewCount >= 50
                    ) {
                        this.lastLoggedLivePreviewCount = s.livePreviewPackets.length;
                        this.outputChannel.appendLine(
                            `[LiveCapture] Sent updatePackets: ${s.livePreviewPackets.length} packet row(s) to webview`
                        );
                    }
                }
            }

            if (s.status === 'stopped') {
                this.onCaptureStopped();
            }
            // Always push the packet count update.
            const elapsed = this.startTime ? Math.floor((Date.now() - this.startTime.getTime()) / 1000) : 0;
            this.postMessage({ command: 'packetCountUpdate', count: s.packetCount, elapsed });
        });
    }

    /**
     * Stop the current capture. Called by the webview message OR the external
     * `nettrace.stopLiveCapture` command.
     */
    public stopCapture(): void {
        if (!this.session || (this.session.status !== 'starting' && this.session.status !== 'capturing' && this.session.status !== 'stopping')) { return; }
        this.outputChannel.appendLine(`[LiveCapture] Stopping capture session ${this.session.id}`);
        this.session.status = 'stopping';
        this.clearRefreshTimer();
        this.tsharkRunner.stopLiveCapture(this.session.id);
        vscode.commands.executeCommand('setContext', 'nettrace.isCapturing', false);
        // The 'close' event on the process will call onCaptureStopped via the onUpdate callback.
    }

    /** Reset the panel back to configure state (New Capture). */
    public newCapture(): void {
        this.clearRefreshTimer();
        if (this.session?.status === 'capturing') {
            this.tsharkRunner.stopLiveCapture(this.session.id);
            vscode.commands.executeCommand('setContext', 'nettrace.isCapturing', false);
        }
        const prev = this.session;
        this.session = undefined;
        this.startTime = undefined;
        this.postMessage({
            command: 'resetPanel',
            prefill: {
                captureFilter: prev?.captureFilter ?? '',
                displayFilter: this.lastDisplayFilter,
                suggestedInterface: prev?.interfaceName,
            },
        });
    }

    // ─── Post-Stop Processing ─────────────────────────────────────────────

    private async onCaptureStopped(): Promise<void> {
        this.clearRefreshTimer();
        vscode.commands.executeCommand('setContext', 'nettrace.isCapturing', false);

        const outputFile = this.session?.outputFilePath;
        const packetCount = this.session?.packetCount ?? 0;
        const elapsed = this.startTime ? Math.floor((Date.now() - this.startTime.getTime()) / 1000) : 0;

        this.outputChannel.appendLine(`[LiveCapture] Capture stopped. File: ${outputFile}, packets: ${packetCount}`);

        // Tell the webview capture is complete so it enables the Analyze button.
        this.postMessage({ command: 'captureComplete', packetCount, elapsed, outputFile });

        if (!outputFile) { return; }

        // Do a final full parse so the packet table is fully populated.
        try {
            const [packetData, conversations, expertInfo] = await Promise.all([
                this.tsharkRunner.getPacketsForDisplay(outputFile, this.lastDisplayFilter),
                this.tsharkRunner.getConversations(outputFile).catch(() => []),
                this.tsharkRunner.getExpertInfo(outputFile).catch(() => ''),
            ]);
            const packets = this.parsePacketOutput(packetData);
            this.postMessage({ command: 'updatePackets', packets, conversations, expertInfo, isFinal: true });
        } catch (e) {
            this.outputChannel.appendLine(`[LiveCapture] Final parse error: ${e}`);
        }
    }

    // ─── Live Refresh Timer ───────────────────────────────────────────────

    private startRefreshTimer(): void {
        this.clearRefreshTimer();
        this.refreshTimer = setInterval(async () => {
            if (!this.session?.outputFilePath) { return; }
            // The file may not exist yet if tshark hasn't written the first packet.
            if (!fs.existsSync(this.session.outputFilePath)) { return; }
            try {
                const packetData = await this.tsharkRunner.getPacketsForDisplay(
                    this.session.outputFilePath,
                    this.lastDisplayFilter,
                    3000  // cap at 3000 packets while live — keeps UI responsive
                );
                const packets = this.parsePacketOutput(packetData);
                if (packets.length > 0) {
                    const elapsed = this.startTime ? Math.floor((Date.now() - this.startTime.getTime()) / 1000) : 0;
                    this.postMessage({ command: 'updatePackets', packets, elapsed, isFinal: false });
                }
            } catch (e) {
                this.outputChannel.appendLine(`[LiveCapture] refresh read error: ${e}`);
            }
        }, 1500);
    }

    private clearRefreshTimer(): void {
        if (this.refreshTimer !== undefined) {
            clearInterval(this.refreshTimer);
            this.refreshTimer = undefined;
        }
    }

    // ─── AI Analysis ─────────────────────────────────────────────────────

    private async analyzeWithAI(msg: any): Promise<void> {
        const captureFilter: string = msg.captureFilter || '';
        const displayFilter: string = msg.displayFilter || this.lastDisplayFilter || '';
        const iface: string = msg.interface || this.session?.interfaceDisplayName || '';
        const packetCount: number = msg.packetCount ?? this.session?.packetCount ?? 0;
        const elapsed: number = msg.durationSec ?? 0;

        const mins = Math.floor(elapsed / 60).toString().padStart(2, '0');
        const secs = (elapsed % 60).toString().padStart(2, '0');

        const contextParts: string[] = [];
        if (iface) { contextParts.push(`interface: ${iface}`); }
        if (captureFilter) { contextParts.push(`capture filter: ${captureFilter}`); }
        if (displayFilter) { contextParts.push(`display filter: ${displayFilter}`); }
        if (packetCount) { contextParts.push(`${packetCount.toLocaleString()} packets`); }
        if (elapsed) { contextParts.push(`duration: ${mins}:${secs}`); }

        const contextStr = contextParts.length > 0 ? ` [Live capture — ${contextParts.join(' | ')}]` : '';
        const query = `@nettrace /diagnose${contextStr}`;

        await vscode.commands.executeCommand('workbench.action.chat.open', { query });
    }

    private async applyDisplayFilterToPanel(): Promise<void> {
        if (!this.session?.outputFilePath) { return; }
        if (!fs.existsSync(this.session.outputFilePath)) { return; }

        try {
            const packetData = await this.tsharkRunner.getPacketsForDisplay(
                this.session.outputFilePath,
                this.lastDisplayFilter,
                this.session.status === 'capturing' ? 3000 : undefined
            );
            const packets = this.parsePacketOutput(packetData);
            const elapsed = this.startTime ? Math.floor((Date.now() - this.startTime.getTime()) / 1000) : 0;
            this.postMessage({ command: 'updatePackets', packets, elapsed, isFinal: this.session.status !== 'capturing' });
        } catch (e) {
            this.outputChannel.appendLine(`[LiveCapture] applyDisplayFilter error: ${e}`);
        }
    }

    // ─── Helpers ──────────────────────────────────────────────────────────

    private resolveLiveCaptureOutputPath(interfaceName: string, captureName?: string): string {
        const customPath = vscode.workspace.getConfiguration('nettrace').get<string>('liveCapturePath', '').trim();
        let baseDir: string;
        if (customPath) {
            baseDir = customPath;
        } else {
            const folders = vscode.workspace.workspaceFolders;
            if (folders && folders.length > 0) {
                baseDir = path.join(folders[0].uri.fsPath, '.nettrace', 'captures', 'live');
            } else {
                baseDir = path.join(vscode.Uri.parse('').fsPath || process.env['USERPROFILE'] || process.env['HOME'] || '.', '.nettrace-live');
            }
        }

        // Sanitize interface name for use in a filename (strip GUID parts, etc.)
        const safeIface = interfaceName
            .replace(/\\Device\\NPF_/i, '')
            .replace(/[{}\-]/g, '')
            .replace(/[^a-zA-Z0-9_]/g, '_')
            .substring(0, 20);

        const safeCaptureName = (captureName || '')
            .trim()
            .replace(/\.pcapng$/i, '')
            .replace(/[^a-zA-Z0-9._-]/g, '_')
            .replace(/_+/g, '_')
            .replace(/^_+|_+$/g, '')
            .substring(0, 80);

        const timestamp = new Date().toISOString().replace(/[:.]/g, '').replace('T', '_').substring(0, 15);
        const filename = safeCaptureName
            ? `${safeCaptureName}.pcapng`
            : `live_${safeIface}_${timestamp}.pcapng`;
        return path.join(baseDir, filename);
    }

    private parsePacketOutput(raw: string): any[] {
        const packets: any[] = [];
        for (const line of raw.split('\n')) {
            const fields = line.split('|');
            if (fields.length < 7) { continue; }
            const num = parseInt(fields[0], 10);
            if (isNaN(num)) { continue; }
            packets.push({
                num,
                time: fields[1],
                src: fields[2],
                dst: fields[3],
                proto: fields[4],
                len: fields[5],
                info: fields[6],
            });
        }
        return packets;
    }

    private postMessage(msg: object): void {
        try {
            this.panel.webview.postMessage(msg);
        } catch { /* panel may be disposed */ }
    }

    private teardown(): void {
        this.clearRefreshTimer();
        if (this.session?.status === 'capturing') {
            this.tsharkRunner.stopLiveCapture(this.session.id);
            vscode.commands.executeCommand('setContext', 'nettrace.isCapturing', false);
        }
        for (const d of this.disposables) { d.dispose(); }
        this.disposables = [];
    }

    // ─── HTML ─────────────────────────────────────────────────────────────

    private getHtml(interfaces: NetworkInterface[], error?: string): string {
        const webview = this.panel.webview;
        return /* html */`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${webview.cspSource} data:; style-src ${webview.cspSource} 'unsafe-inline'; script-src ${webview.cspSource} 'unsafe-inline';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Live Capture</title>
<style>
/* ── Reset ── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

/* ── Root ── */
:root {
    --bg:              var(--vscode-editor-background);
    --fg:              var(--vscode-editor-foreground);
    --border:          var(--vscode-panel-border, #3c3c3c);
    --input-bg:        var(--vscode-input-background);
    --input-fg:        var(--vscode-input-foreground);
    --input-border:    var(--vscode-input-border, #3c3c3c);
    --input-focus:     var(--vscode-focusBorder, #007acc);
    --btn-bg:          var(--vscode-button-background, #0e639c);
    --btn-fg:          var(--vscode-button-foreground, #fff);
    --btn-hover:       var(--vscode-button-hoverBackground, #1177bb);
    --btn-sec:         var(--vscode-button-secondaryBackground, #3a3d41);
    --btn-sec-fg:      var(--vscode-button-secondaryForeground, #ccc);
    --toolbar-bg:      var(--vscode-editorGroupHeader-tabsBackground, #252526);
    --row-hover:       var(--vscode-list-hoverBackground, rgba(255,255,255,.05));
    --row-sel:         var(--vscode-list-activeSelectionBackground, #094771);
    --row-sel-fg:      var(--vscode-list-activeSelectionForeground, #fff);
    --desc:            var(--vscode-descriptionForeground, #888);
    --red:             #e05252;
    --green:           #6dbd6d;
    --mono:            'SFMono-Regular', Consolas, 'Courier New', monospace;
    --toolbar-h:       36px;
    --filter-h:        30px;
    --status-h:        24px;
}

body {
    margin: 0;
    padding: 0;
    font: 12px/1.4 var(--vscode-font-family, 'Segoe UI', sans-serif);
    background: var(--bg);
    color: var(--fg);
    height: 100vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
}

*, *::before, *::after { box-sizing: border-box; }

/* ════════════════════════════════════════
   ROW 1 — ICON TOOLBAR (Wireshark-style compact)
   ════════════════════════════════════════ */
#action-toolbar {
    height: 32px;
    min-height: 32px;
    background: var(--toolbar-bg);
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 2px;
    padding: 0 6px;
    flex-shrink: 0;
}
.icon-btn {
    width: 26px;
    height: 26px;
    padding: 0;
    border: 1px solid transparent;
    border-radius: 3px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 15px;
    flex-shrink: 0;
    background: transparent;
    color: var(--fg);
}
.icon-btn:disabled { opacity: 0.35; cursor: default; }
.icon-btn:hover:not(:disabled) { background: var(--row-hover); border-color: var(--border); }
#btn-start { color: var(--green); }
#btn-start:hover:not(:disabled) { background: rgba(109,189,109,0.15); border-color: var(--green); }
#btn-pause { color: var(--fg); }
#btn-pause:hover:not(:disabled) { background: rgba(200,200,200,0.15); border-color: var(--border); }
#btn-stop  { color: var(--red); }
#btn-stop:hover:not(:disabled)  { background: rgba(224,82,82,0.15);  border-color: var(--red); }
#btn-analyze { display: none; }
.act-sep { width: 1px; height: 20px; background: var(--border); margin: 0 4px; flex-shrink: 0; }

/* ════════════════════════════════════════
   ROW 1 addition — interface combo inside action-toolbar
   ════════════════════════════════════════ */
#iface-wrap { display: flex; align-items: center; gap: 4px; flex-shrink: 0; }
#iface-label { font-size: 11px; color: var(--desc); white-space: nowrap; flex-shrink: 0; }
#iface-select {
    width: 220px;
    height: 24px;
    background: var(--input-bg);
    color: var(--input-fg);
    border: 1px solid var(--input-border);
    border-radius: 2px;
    padding: 0 6px;
    font: inherit;
    font-size: 11px;
}
#iface-select:focus { outline: 1px solid var(--input-focus); }
#iface-select:disabled { opacity: 0.5; }
#btn-refresh {
    height: 24px; width: 26px; padding: 0;
    background: transparent; border: 1px solid var(--border);
    border-radius: 2px; color: var(--fg); font-size: 13px;
    cursor: pointer; display: flex; align-items: center; justify-content: center; flex-shrink: 0;
}
#btn-refresh:hover:not(:disabled) { background: var(--row-hover); }
#btn-refresh:disabled { opacity: 0.4; }

#capture-name-wrap { display: flex; align-items: center; gap: 4px; flex-shrink: 0; }
#capture-name-label,
#capture-filter-label { font-size: 11px; color: var(--desc); white-space: nowrap; flex-shrink: 0; }
#capture-name {
    width: 190px;
    height: 24px;
    background: var(--input-bg);
    color: var(--input-fg);
    border: 1px solid var(--input-border);
    border-radius: 2px;
    padding: 0 8px;
    font: inherit;
    font-size: 11px;
}
#capture-name:focus { outline: 1px solid var(--input-focus); }
#capture-filter {
    flex: 1;
    min-width: 0;
    height: 24px;
    background: var(--input-bg);
    color: var(--input-fg);
    border: 1px solid var(--input-border);
    border-radius: 2px;
    padding: 0 8px;
    font: inherit;
    font-size: 11px;
}
#capture-filter:focus { outline: 1px solid var(--input-focus); }
#capture-filter:disabled,
#capture-name:disabled { opacity: 0.5; }

/* ════════════════════════════════════════
   ROW 2 — CAPTURE FILTER ONLY
   ════════════════════════════════════════ */
#filter-row {
    height: 30px;
    min-height: 30px;
    background: var(--vscode-sideBar-background, rgba(0,0,0,.15));
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 0 8px;
    flex-shrink: 0;
}

/* ════════════════════════════════════════
   DISPLAY FILTER BAR  (only after data)
   ════════════════════════════════════════ */
#filter-bar {
    height: var(--filter-h);
    min-height: var(--filter-h);
    background: var(--toolbar-bg);
    border-bottom: 1px solid var(--border);
    display: none;            /* hidden until capture starts */
    align-items: center;
    gap: 4px;
    padding: 0 6px;
    flex-shrink: 0;
}
#filter-bar.visible { display: flex; }
#filter-label { font-size: 10px; color: var(--desc); white-space: nowrap; flex-shrink: 0; }
#display-filter {
    flex: 1;
    height: 22px;
    background: var(--input-bg);
    color: var(--input-fg);
    border: 1px solid var(--input-border);
    border-radius: 2px;
    padding: 0 8px;
    font: inherit;
    font-size: 11px;
}
#display-filter:focus { outline: 1px solid var(--input-focus); }
#btn-clear-df {
    height: 22px; width: 22px; padding: 0;
    background: transparent; border: 1px solid var(--border);
    border-radius: 2px; color: var(--fg); font-size: 12px;
    cursor: pointer; display: flex; align-items: center; justify-content: center; flex-shrink: 0;
}
#btn-clear-df:hover { background: var(--row-hover); }

/* ════════════════════════════════════════
   STATUS BAR  (bottom-style bar at top of table)
   ════════════════════════════════════════ */
#status-bar {
    height: var(--status-h);
    min-height: var(--status-h);
    background: var(--toolbar-bg);
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 0 8px;
    font-size: 11px;
    flex-shrink: 0;
    overflow: hidden;
}
#status-dot { font-size: 10px; }
#status-text { font-weight: 600; }
#stat-packets, #stat-elapsed, #stat-file { color: var(--desc); }
#status-bar > span { min-width: 0; }
#stat-file {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
#stat-sep { color: var(--border); }

/* ════════════════════════════════════════
   ERROR BANNER
   ════════════════════════════════════════ */
#banner {
    display: none;
    padding: 8px 12px;
    font-size: 11px;
    background: var(--vscode-inputValidation-errorBackground, #5a1d1d);
    border-bottom: 1px solid var(--vscode-inputValidation-errorBorder, #be1100);
    white-space: pre-wrap;
    line-height: 1.5;
    flex-shrink: 0;
}
#banner.visible { display: block; }

#action-toolbar,
#filter-row,
#filter-bar,
#status-bar,
#banner {
    position: relative;
    z-index: 20;
}

/* ════════════════════════════════════════
   MAIN: packet table + detail pane
   ════════════════════════════════════════ */
#main { flex: 1; display: flex; flex-direction: column; overflow: hidden; min-height: 0; position: relative; z-index: 1; }

/* Empty state */
#empty-state {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 10px;
    color: var(--desc);
    padding: 24px;
}
#empty-state .icon { font-size: 40px; }
#empty-state p { font-size: 12px; text-align: center; line-height: 1.6; }

/* Packet table */
#table-wrap { flex: 1; overflow: auto; display: none; position: relative; z-index: 1; }
table {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--mono);
    font-size: 11px;
    table-layout: fixed;
}
thead { position: sticky; top: 0; background: var(--toolbar-bg); z-index: 10; }
th {
    padding: 3px 6px;
    text-align: left;
    border-bottom: 2px solid var(--border);
    font: 700 11px var(--vscode-font-family, 'Segoe UI', sans-serif);
    white-space: nowrap;
    overflow: hidden;
    user-select: none;
    cursor: default;
}
td {
    padding: 2px 6px;
    border-bottom: 1px solid rgba(128,128,128,0.07);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
tr:hover > td { background: var(--row-hover); cursor: pointer; }
tr.selected > td { background: var(--row-sel); color: var(--row-sel-fg); }

/* Column widths */
col.c-no   { width: 52px; }
col.c-time { width: 96px; }
col.c-src  { width: 15%; }
col.c-dst  { width: 15%; }
col.c-prot { width: 68px; }
col.c-len  { width: 52px; }
col.c-info { width: auto; }

/* Protocol colours — same as existing CaptureWebviewPanel */
.p-tls, .p-ssl { color: #4ec9b0; }
.p-http, .p-http2 { color: #dcdcaa; }
.p-tcp  { color: #569cd6; }
.p-udp  { color: #9cdcfe; }
.p-dns  { color: #c586c0; }
.p-icmp, .p-icmpv6 { color: #f44747; }
.p-arp  { color: #ce9178; }

/* Packet detail pane (collapsible bottom split) */
#detail-pane {
    display: none;
    height: 180px;
    min-height: 60px;
    border-top: 2px solid var(--border);
    overflow: auto;
    flex-shrink: 0;
    background: var(--bg);
    resize: vertical;
}
#detail-pane.visible { display: block; }
#detail-pre {
    font-family: var(--mono);
    font-size: 11px;
    padding: 6px 10px;
    white-space: pre;
    color: var(--fg);
}
</style>
</head>
<body>

<!-- ══ ROW 1: ICON TOOLBAR + INTERFACE COMBO ══ -->
<div id="action-toolbar">
    <button class="icon-btn" id="btn-start" title="Start Capture">&#9654;</button>
    <button class="icon-btn" id="btn-pause" title="Pause Live Trace" disabled>&#10074;&#10074;</button>
    <button class="icon-btn" id="btn-stop" disabled title="Stop Capture">&#9632;</button>
    <div class="act-sep"></div>
    <button class="icon-btn" id="btn-new" title="New Capture">&#43;</button>
    <button class="icon-btn" id="btn-clear" title="Clear / Reset">&#10005;</button>
    <button class="icon-btn" id="btn-analyze" title="Analyze with AI">&#129302;</button>
    <div class="act-sep"></div>
    <div id="iface-wrap">
        <span id="iface-label">Interface:</span>
        <select id="iface-select" title="Network interface">
            ${(() => {
                const he = (s: string) => s.replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
                if (error) { return `<option value="">(error loading interfaces)</option>`; }
                if (interfaces.length === 0) { return `<option value="">(no interfaces found)</option>`; }
                return interfaces.map(iface => {
                    const label = iface.isLoopback
                        ? `${iface.id}. [Loopback]`
                        : `${iface.id}. ${iface.displayName}`;
                    const sel   = (this.prefill?.suggestedInterface === iface.name || this.prefill?.suggestedInterface === iface.displayName) ? ' selected' : '';
                    return `<option value="${he(iface.name)}" data-dn="${he(iface.displayName)}"${sel}>${he(label)}</option>`;
                }).join('\n            ');
            })()}
        </select>
        <button id="btn-refresh" title="Refresh interfaces">&#8635;</button>
    </div>
    <div id="capture-name-wrap">
        <span id="capture-name-label">Name:</span>
        <input type="text" id="capture-name" spellcheck="false" placeholder="live_capture">
    </div>
</div>

<!-- ══ ROW 2: CAPTURE FILTER ══ -->
<div id="filter-row">
    <span id="capture-filter-label">Capture Filter:</span>
    <input type="text" id="capture-filter" spellcheck="false"
           placeholder="e.g. tcp port 443 or host 192.168.1.1">
</div>

<!-- ══ DISPLAY FILTER BAR  (shown once data exists) ══ -->
<div id="filter-bar">
    <span id="filter-label">Display Filter:</span>
    <input type="text" id="display-filter" spellcheck="false"
           placeholder="e.g.  tls  or  http  or  ip.addr==1.2.3.4" list="display-filter-suggestions">
    <button id="btn-clear-df" title="Clear display filter">×</button>
</div>
<datalist id="display-filter-suggestions">
    <option value="tcp"></option>
    <option value="udp"></option>
    <option value="dns"></option>
    <option value="http"></option>
    <option value="tls"></option>
    <option value="icmp"></option>
    <option value="arp"></option>
    <option value="ip.addr == "></option>
    <option value="tcp.stream eq "></option>
    <option value="frame.number == "></option>
    <option value="tcp.port == 443"></option>
    <option value="dns.qry.name contains \""></option>
</datalist>

<!-- ══ STATUS BAR ══ -->
<div id="status-bar">
    <span id="status-dot">○</span>
    <span id="status-text">Ready</span>
    <span id="stat-packets"></span>
    <span id="stat-elapsed"></span>
    <span id="stat-file"></span>
</div>

<!-- ══ ERROR BANNER ══ -->
<div id="banner"></div>

<!-- ══ MAIN AREA ══ -->
<div id="main">
    <div id="empty-state">
        <div class="icon">📡</div>
        <p>Select a network interface above, optionally add a Capture Filter expression,<br>then click <strong>&#9654; Start</strong> to begin.</p>
    </div>
    <div id="table-wrap">
        <table>
            <colgroup>
                <col class="c-no"><col class="c-time"><col class="c-src">
                <col class="c-dst"><col class="c-prot"><col class="c-len"><col class="c-info">
            </colgroup>
            <thead>
                <tr>
                    <th>No.</th><th>Time</th><th>Source</th>
                    <th>Destination</th><th>Protocol</th><th>Len</th><th>Info</th>
                </tr>
            </thead>
            <tbody id="pkt-body"></tbody>
        </table>
    </div>

    <!-- Packet detail (appears when a row is clicked) -->
    <div id="detail-pane">
        <pre id="detail-pre">Click a packet row to inspect its fields.</pre>
    </div>
</div>

<script>
const vscode = acquireVsCodeApi();

// ── Error trap ───────────────────────────────────────────────────
window.onerror = function(msg, src, line, col, err) {
    vscode.postMessage({ command: 'showError', message: 'JS error: ' + msg + ' (line ' + line + ')' });
    return false;
};

// ── Prefill values baked in ────────────────────────────────────────────
const INITIAL_CAP_FILTER  = ${JSON.stringify(this.prefill?.captureFilter  ?? '')};
const INITIAL_DISP_FILTER = ${JSON.stringify(this.prefill?.displayFilter  ?? '')};
const INITIAL_AUTO_START  = ${JSON.stringify(this.prefill?.autoStart      ?? false)};

// ── State ────────────────────────────────────────────────────────────
let isCapturing   = false;
let hasData       = false;
let captureFilter = '';
let displayFilter = '';
let ifaceName     = '';
let ifaceDispName = '';
let packetCount   = 0;
let elapsedSec    = 0;
let outputFile    = '';
let autoScroll    = true;
let selectedTr    = null;
let clockTimer    = null;
let nameTouched   = false;

// ── Elements ─────────────────────────────────────────────────────────
const ifaceSelect     = document.getElementById('iface-select');
const ifaceWrap       = document.getElementById('iface-wrap');
const filterRow       = document.getElementById('filter-row');
const captureNameWrap = document.getElementById('capture-name-wrap');
const captureNameInput = document.getElementById('capture-name');
const capFilterInput  = document.getElementById('capture-filter');
const dispFilterInput = document.getElementById('display-filter');
const filterBar       = document.getElementById('filter-bar');
const btnStart        = document.getElementById('btn-start');
const btnPause        = document.getElementById('btn-pause');
const btnStop         = document.getElementById('btn-stop');
const btnNew          = document.getElementById('btn-new');
const btnClear        = document.getElementById('btn-clear');
const btnAnalyze      = document.getElementById('btn-analyze');
const btnRefresh      = document.getElementById('btn-refresh');
const btnClearDf      = document.getElementById('btn-clear-df');
const statusDot       = document.getElementById('status-dot');
const statusText      = document.getElementById('status-text');
let isPausedMain      = false;
const statPackets     = document.getElementById('stat-packets');
const statElapsed     = document.getElementById('stat-elapsed');
const statFile        = document.getElementById('stat-file');
const bannerEl        = document.getElementById('banner');
const emptyState      = document.getElementById('empty-state');
const tableWrap       = document.getElementById('table-wrap');
const pktBody         = document.getElementById('pkt-body');
const detailPane      = document.getElementById('detail-pane');
const detailPre       = document.getElementById('detail-pre');

// ── Logging helper ──────────────────────────────────────────────────
function log(text) { vscode.postMessage({ command: 'log', text: String(text) }); }

function suggestCaptureNameMain() {
    const selected = ifaceSelect && ifaceSelect.selectedOptions && ifaceSelect.selectedOptions[0]
        ? ifaceSelect.selectedOptions[0]
        : null;
    const ifaceText = (selected && selected.dataset && selected.dataset.dn) || (ifaceSelect ? ifaceSelect.value : '') || 'capture';
    const safeIface = String(ifaceText).replace(/[^a-zA-Z0-9._-]/g, '_').replace(/_+/g, '_').replace(/^_+|_+$/g, '').substring(0, 30) || 'capture';
    const d = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    const ts = d.getFullYear().toString() + pad(d.getMonth() + 1) + pad(d.getDate()) + '_' + pad(d.getHours()) + pad(d.getMinutes()) + pad(d.getSeconds());
    return 'live_' + safeIface + '_' + ts;
}

function initializeUiState() {
    if (clockTimer) { clearInterval(clockTimer); clockTimer = null; }
    isCapturing = false;
    hasData = false;
    packetCount = 0;
    elapsedSec = 0;
    autoScroll = true;
    selectedTr = null;
    isPausedMain = false;
    pktBody.innerHTML = '';
    tableWrap.style.display = 'none';
    emptyState.style.display = 'flex';
    detailPane.classList.remove('visible');
    detailPre.textContent = 'Click a packet row to inspect its fields.';
    filterBar.classList.remove('visible');
    if (filterRow) { filterRow.style.display = 'flex'; }
    if (ifaceWrap) { ifaceWrap.style.display = 'flex'; }
    if (captureNameWrap) { captureNameWrap.style.display = 'flex'; }
    setStatus('ready', 'Ready', '○', '');
    statPackets.textContent = '';
    statElapsed.textContent = '';
    statFile.textContent = '';
    hideBanner();
    btnStart.disabled = false;
    if (btnPause) {
        btnPause.disabled = true;
        btnPause.innerHTML = '&#10074;&#10074;';
        btnPause.title = 'Pause Live Trace';
    }
    btnStop.disabled = true;
    btnNew.disabled = true;
    if (btnClear) { btnClear.disabled = false; }
    btnAnalyze.style.display = 'none';
    lockCaptureControls(false);
}
// Signal the script has started executing (fires before any DOM work)
log('Script started — DOM ready, acquireVsCodeApi OK');

try {
if (INITIAL_CAP_FILTER)  { capFilterInput.value  = INITIAL_CAP_FILTER; }
if (INITIAL_DISP_FILTER) { dispFilterInput.value = INITIAL_DISP_FILTER; displayFilter = INITIAL_DISP_FILTER; }
if (captureNameInput && !captureNameInput.value.trim()) { captureNameInput.value = suggestCaptureNameMain(); }
if (captureNameInput) {
    captureNameInput.addEventListener('input', () => { nameTouched = true; });
}
if (ifaceSelect) {
    ifaceSelect.addEventListener('change', () => {
        if (captureNameInput && !nameTouched) {
            captureNameInput.value = suggestCaptureNameMain();
        }
    });
}
initializeUiState();
if (INITIAL_AUTO_START && ifaceSelect.value) {
    setTimeout(() => startCapture(ifaceSelect.value, ifaceSelect.selectedOptions[0]?.dataset?.dn || ifaceSelect.value), 300);
}
log('Panel ready. Interface combo has ' + ifaceSelect.options.length + ' options, selected="' + ifaceSelect.value + '"');
} catch(e) {
    vscode.postMessage({ command: 'showError', message: 'Init error: ' + e });
}

// ── Toolbar actions ───────────────────────────────────────────────────
btnStart.addEventListener('click', () => {
    log('btnStart clicked, ifaceSelect.value="' + ifaceSelect.value + '"');
    const iface = ifaceSelect.value;
    if (!iface) { showBanner('Please select a network interface first.'); return; }
    hideBanner();
    startCapture(iface, ifaceSelect.selectedOptions[0]?.dataset?.dn || iface);
});

let stopSafetyTimer = null;
btnStop.addEventListener('click', () => {
    if (btnStop.disabled) { return; }
    btnStop.disabled = true;
    // Stop rendering incoming packets immediately — don't wait for backend confirmation
    isCapturing = false;
    vscode.postMessage({ command: 'stopCapture' });
    isPausedMain = false;
    if (btnPause) {
        btnPause.disabled = true;
        btnPause.innerHTML = '&#10074;&#10074;';
        btnPause.title = 'Pause Live Trace';
    }
    setStatus('stopping', 'Stopping…', '◉', '#ccc');
    btnNew.disabled = false;
    if (btnClear) { btnClear.disabled = false; }
    // Safety net: if captureComplete never arrives, re-enable control buttons after 5s
    if (stopSafetyTimer) { clearTimeout(stopSafetyTimer); }
    stopSafetyTimer = setTimeout(() => {
        stopSafetyTimer = null;
        if (isCapturing) {
            log('Stop safety-net fired — forcing ready state');
            isCapturing = false;
            btnStart.disabled = false;
            btnStop.disabled = true;
            btnNew.disabled = false;
            if (btnClear) { btnClear.disabled = false; }
            lockCaptureControls(false);
            setStatus('ready', 'Ready', '○', '');
        }
    }, 5000);
});

if (btnPause) {
    btnPause.addEventListener('click', () => {
        isPausedMain = !isPausedMain;
        btnPause.innerHTML = isPausedMain ? '&#9654;' : '&#10074;&#10074;';
        btnPause.title = isPausedMain ? 'Resume Live Trace' : 'Pause Live Trace';
        setStatus('capturing', isPausedMain ? 'Paused' : ('Capturing on ' + ifaceDispName), '⏺', 'var(--red)');
    });
}

btnNew.addEventListener('click', resetToConfigureState);
if (btnClear) { btnClear.addEventListener('click', resetToConfigureState); }

btnAnalyze.addEventListener('click', () => {
    vscode.postMessage({
        command: 'analyzeWithAI',
        captureFilter,
        displayFilter: dispFilterInput.value.trim(),
        interface: ifaceDispName,
        packetCount,
        durationSec: elapsedSec,
    });
});

btnRefresh.addEventListener('click', () => {
    ifaceSelect.innerHTML = '<option value="">⌛ Refreshing…</option>';
    vscode.postMessage({ command: 'refreshInterfaces' });
});

// ── Display filter bar ────────────────────────────────────────────────
let dfTimer = null;
dispFilterInput.addEventListener('input', () => {
    displayFilter = dispFilterInput.value.trim();
    vscode.postMessage({ command: 'updateDisplayFilter', filter: displayFilter });
    clearTimeout(dfTimer);
    dfTimer = setTimeout(() => dfTimer = null, 400);
});
btnClearDf.addEventListener('click', () => {
    dispFilterInput.value = '';
    displayFilter = '';
    vscode.postMessage({ command: 'updateDisplayFilter', filter: '' });
});

// ── Auto-scroll detection ─────────────────────────────────────────────
tableWrap.addEventListener('scroll', () => {
    const atBottom = tableWrap.scrollHeight - tableWrap.scrollTop - tableWrap.clientHeight < 60;
    autoScroll = atBottom;
});

// ── Packet row click → detail pane ────────────────────────────────────
pktBody.addEventListener('click', e => {
    const tr = e.target.closest('tr');
    if (!tr) { return; }
    if (selectedTr) { selectedTr.classList.remove('selected'); }
    tr.classList.add('selected');
    selectedTr = tr;
    const frame = parseInt(tr.dataset.f);
    if (!isNaN(frame)) {
        detailPre.textContent = 'Loading…';
        detailPane.classList.add('visible');
        vscode.postMessage({ command: 'getPacketDetail', frameNumber: frame });
    }
});

pktBody.addEventListener('dblclick', e => {
    const tr = e.target.closest('tr');
    if (!tr) { return; }
    const frame = parseInt(tr.dataset.f);
    if (!isNaN(frame)) { vscode.postMessage({ command: 'analyzePacket', packetNumber: frame }); }
});

// ── Helpers ───────────────────────────────────────────────────────────
function startCapture(iface, dispName) {
    isCapturing   = true;
    ifaceName     = iface;
    ifaceDispName = dispName;
    captureFilter = capFilterInput.value.trim();
    displayFilter = dispFilterInput.value.trim();

    lockCaptureControls(true);
    btnStart.disabled = true;
    if (btnPause) {
        btnPause.disabled = false;
        btnPause.innerHTML = '&#10074;&#10074;';
        btnPause.title = 'Pause Live Trace';
    }
    btnStop.disabled  = false;
    btnNew.disabled = true;
    if (filterRow) { filterRow.style.display = 'flex'; }
    if (captureNameWrap) { captureNameWrap.style.display = 'flex'; }
    if (ifaceWrap) { ifaceWrap.style.display = 'flex'; }
    filterBar.classList.remove('visible');

    setStatus('capturing', 'Capturing on ' + ifaceDispName, '⏺', 'var(--red)');
    vscode.postMessage({ command: 'startCapture', interfaceName: iface, interfaceDisplayName: dispName, captureFilter, displayFilter, captureName: captureNameInput ? captureNameInput.value.trim() : '' });
}

function resetToConfigureState() {
    if (clockTimer) { clearInterval(clockTimer); clockTimer = null; }
    isCapturing = false;
    hasData     = false;
    pktBody.innerHTML = '';
    tableWrap.style.display    = 'none';
    emptyState.style.display   = 'flex';
    detailPane.classList.remove('visible');
    filterBar.classList.remove('visible');
    if (filterRow) { filterRow.style.display = 'flex'; }
    if (ifaceWrap) { ifaceWrap.style.display = 'flex'; }
    if (captureNameWrap) { captureNameWrap.style.display = 'flex'; }
    setStatus('ready', 'Ready', '○', '');
    statPackets.textContent = '';
    statElapsed.textContent = '';
    statFile.textContent    = '';
    if (captureNameInput) { captureNameInput.value = suggestCaptureNameMain(); }
    nameTouched = false;
    hideBanner();
    btnNew.disabled = false;
    if (btnClear) { btnClear.disabled = false; }
    btnAnalyze.style.display = 'none';
    btnStart.disabled = false;
    isPausedMain = false;
    if (btnPause) {
        btnPause.disabled = true;
        btnPause.innerHTML = '&#10074;&#10074;';
        btnPause.title = 'Pause Live Trace';
    }
    btnStop.disabled  = true;
    lockCaptureControls(false);
    vscode.postMessage({ command: 'newCapture' });
}

function lockCaptureControls(locked) {
    ifaceSelect.disabled    = locked;
    capFilterInput.disabled = locked;
    btnRefresh.disabled     = locked;
}

function setStatus(state, text, dot, dotColor) {
    statusDot.textContent  = dot;
    statusDot.style.color  = dotColor || '';
    statusText.textContent = text;
}

function showBanner(msg) { bannerEl.textContent = msg; bannerEl.classList.add('visible'); }
function hideBanner()    { bannerEl.classList.remove('visible'); }

function protoClass(p) {
    const s = (p || '').toLowerCase();
    if (s.includes('tls') || s.includes('ssl'))  { return 'p-tls'; }
    if (s.startsWith('http'))                     { return 'p-' + s.split('.')[0].replace(/[^a-z0-9_-]/g,''); }
    if (s === 'tcp')  { return 'p-tcp'; }
    if (s === 'udp')  { return 'p-udp'; }
    if (s === 'dns')  { return 'p-dns'; }
    if (s.startsWith('icmp')) { return 'p-icmp'; }
    if (s === 'arp')  { return 'p-arp'; }
    return '';
}

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function pad2(n) { return String(n).padStart(2,'0'); }
function fmtElapsed(s) {
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return h > 0 ? pad2(h)+':'+pad2(m)+':'+pad2(sec) : pad2(m)+':'+pad2(sec);
}

function shortFileLabel(value) {
    const raw = String(value || '');
    if (!raw) { return ''; }
    const fileName = raw.replace(/.*[\\/]/, '');
    const max = 48;
    if (fileName.length <= max) {
        return fileName;
    }
    return fileName.slice(0, 24) + '…' + fileName.slice(-(max - 25));
}

function renderPackets(packets) {
    if (!Array.isArray(packets) || packets.length === 0) { return; }
    const wasBottom = autoScroll;
    const frag = document.createDocumentFragment();
    for (const p of packets) {
        const tr = document.createElement('tr');
        tr.dataset.f = p.num;
        const pc = protoClass(p.proto);
        tr.innerHTML =
            '<td>' + p.num + '</td>' +
            '<td>' + esc(p.time || '') + '</td>' +
            '<td>' + esc(p.src  || '') + '</td>' +
            '<td>' + esc(p.dst  || '') + '</td>' +
            '<td class="' + pc + '">' + esc(p.proto || '') + '</td>' +
            '<td>' + esc(p.len  || '') + '</td>' +
            '<td>' + esc(p.info || '') + '</td>';
        frag.appendChild(tr);
    }
    // Replace entire body on each refresh (tshark returns all packets from file start)
    pktBody.innerHTML = '';
    pktBody.appendChild(frag);
    emptyState.style.display  = 'none';
    tableWrap.style.display   = 'block';
    hasData = true;
    if (wasBottom) { tableWrap.scrollTop = tableWrap.scrollHeight; }
}

function populateInterfaces(ifaces, suggested) {
    ifaceSelect.innerHTML = '';
    if (!ifaces || ifaces.length === 0) {
        const o = document.createElement('option');
        o.value = ''; o.textContent = '(no interfaces found)';
        ifaceSelect.appendChild(o);
        return;
    }
    for (const iface of ifaces) {
        const o  = document.createElement('option');
        o.value  = iface.name;
        o.textContent = iface.isLoopback
            ? '[Loopback]  ' + iface.displayName
            : iface.displayName;
        o.dataset.dn = iface.displayName;
        ifaceSelect.appendChild(o);
    }
    if (suggested) {
        const found = [...ifaceSelect.options].find(o =>
            o.value === suggested || o.dataset.dn === suggested
        );
        if (found) { found.selected = true; }
    }
}

// ── Message bus ───────────────────────────────────────────────────────
window.addEventListener('message', e => {
    const msg = e.data;
    switch (msg.command) {

        case 'setInterfaces':
            log('setInterfaces received: ' + (msg.loadError ? 'error' : (msg.interfaces?.length || 0) + ' iface(s)'));
            if (msg.loadError) {
                showBanner(msg.loadError);
                ifaceSelect.innerHTML = '<option value="">(unable to load interfaces)</option>';
            } else {
                populateInterfaces(msg.interfaces, msg.suggestedInterface);
                log('populateInterfaces done — select.options.length=' + ifaceSelect.options.length);
                if (msg.captureFilter)  { capFilterInput.value  = msg.captureFilter; }
                if (msg.displayFilter)  { dispFilterInput.value = msg.displayFilter; displayFilter = msg.displayFilter; }
            }
            break;

        case 'applyPrefill':
            if (msg.suggestedInterface) {
                const o = [...ifaceSelect.options].find(x => x.value === msg.suggestedInterface);
                if (o) { o.selected = true; }
            }
            if (msg.captureFilter !== undefined) { capFilterInput.value  = msg.captureFilter; }
            if (msg.displayFilter !== undefined) { dispFilterInput.value = msg.displayFilter; displayFilter = msg.displayFilter; }
            break;

        case 'triggerAutoStart':
            if (!isCapturing && ifaceSelect.value) {
                startCapture(ifaceSelect.value, ifaceSelect.selectedOptions[0]?.dataset?.dn || ifaceSelect.value);
            }
            break;

        case 'captureStarted':
            isCapturing = true;
            outputFile = msg.outputFile || '';
            elapsedSec = 0;
            if (clockTimer) { clearInterval(clockTimer); }
            clockTimer = setInterval(() => {
                elapsedSec++;
                statElapsed.textContent = fmtElapsed(elapsedSec);
            }, 1000);
            statFile.textContent = outputFile ? ' → ' + shortFileLabel(outputFile) : '';
            btnStart.disabled = true;
            if (btnPause) { btnPause.disabled = false; }
            btnStop.disabled = false;
            break;

        case 'packetCountUpdate':
            packetCount = msg.count || 0;
            statPackets.textContent = packetCount.toLocaleString() + ' packets';
            if (packetCount > 0) {
                emptyState.style.display = 'none';
                tableWrap.style.display = 'block';
            }
            if (msg.elapsed !== undefined) { elapsedSec = msg.elapsed; }
            break;

        case 'updatePackets':
            // Always allow isFinal through (post-stop full parse); drop live updates when not capturing or paused
            if (!msg.isFinal && (isPausedMain || !isCapturing)) { break; }
            renderPackets(Array.isArray(msg.packets) ? msg.packets : []);
            if (msg.elapsed !== undefined) { elapsedSec = msg.elapsed; }
            if (msg.isFinal && clockTimer) { clearInterval(clockTimer); clockTimer = null; }
            break;

        case 'captureComplete':
            if (stopSafetyTimer) { clearTimeout(stopSafetyTimer); stopSafetyTimer = null; }
            if (clockTimer) { clearInterval(clockTimer); clockTimer = null; }
            isCapturing = false;
            packetCount = msg.packetCount || 0;
            elapsedSec  = msg.elapsed || elapsedSec;
            statPackets.textContent = packetCount.toLocaleString() + ' packets';
            statElapsed.textContent = fmtElapsed(elapsedSec);
            setStatus('stopped', '✔ Capture complete', '●', 'var(--green)');
            btnStart.disabled = false;
            isPausedMain = false;
            if (btnPause) {
                btnPause.disabled = true;
                btnPause.innerHTML = '&#10074;&#10074;';
                btnPause.title = 'Pause Live Trace';
            }
            btnStop.disabled  = true;
            btnNew.disabled = false;
            if (btnClear) { btnClear.disabled = false; }
            btnAnalyze.style.display = '';
            if (filterRow) { filterRow.style.display = 'flex'; }
            if (captureNameWrap) { captureNameWrap.style.display = 'flex'; }
            if (ifaceWrap) { ifaceWrap.style.display = 'flex'; }
            filterBar.classList.add('visible');
            break;

        case 'captureError':
            if (stopSafetyTimer) { clearTimeout(stopSafetyTimer); stopSafetyTimer = null; }
            isCapturing = false;
            if (clockTimer) { clearInterval(clockTimer); clockTimer = null; }
            setStatus('error', '✖ Capture error', '●', 'var(--red)');
            showBanner(msg.message || 'Unknown capture error');
            lockCaptureControls(false);
            btnStart.disabled = false;
            isPausedMain = false;
            if (btnPause) {
                btnPause.disabled = true;
                btnPause.innerHTML = '&#10074;&#10074;';
                btnPause.title = 'Pause Live Trace';
            }
            btnStop.disabled  = true;
            btnNew.disabled = false;
            if (btnClear) { btnClear.disabled = false; }
            if (filterRow) { filterRow.style.display = 'flex'; }
            if (ifaceWrap) { ifaceWrap.style.display = 'flex'; }
            if (captureNameWrap) { captureNameWrap.style.display = 'flex'; }
            filterBar.classList.remove('visible');
            break;

        case 'resetPanel':
            if (msg.prefill) {
                if (msg.prefill.suggestedInterface) {
                    const o = [...ifaceSelect.options].find(x => x.value === msg.prefill.suggestedInterface);
                    if (o) { o.selected = true; }
                }
                capFilterInput.value  = msg.prefill.captureFilter  || '';
                dispFilterInput.value = msg.prefill.displayFilter   || '';
                displayFilter         = msg.prefill.displayFilter   || '';
            }
            break;

        case 'packetDetail':
            if (msg.raw) { detailPre.textContent = msg.raw; }
            break;

        case 'packetDetailRaw':
            detailPre.textContent = msg.text || '';
            break;

        case 'packetHex':
            detailPre.textContent = msg.hex || '';
            break;
    }
});
</script>
</body>
</html>`;
    }
}

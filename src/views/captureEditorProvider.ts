import * as vscode from 'vscode';
import * as path from 'path';
import { TsharkRunner } from '../parsing/tsharkRunner';
import { CapturesTreeProvider } from './capturesTreeProvider';
import { StreamsTreeProvider } from './streamsTreeProvider';
import { CaptureWebviewPanel } from './captureWebviewPanel';
import { CaptureFile } from '../types';

/**
 * Custom readonly editor provider for pcap/pcapng/cap files.
 * When a user double-clicks a capture file in the VS Code file explorer,
 * this provider intercepts the open and launches the capture viewer webview
 * instead of VS Code's default text editor (which fails on binary files).
 */
export class CaptureEditorProvider implements vscode.CustomReadonlyEditorProvider<CaptureDocument> {

    public static readonly viewType = 'nettrace.captureEditor';

    constructor(
        private readonly extensionUri: vscode.Uri,
        private readonly tsharkRunner: TsharkRunner,
        private readonly capturesTree: CapturesTreeProvider,
        private readonly streamsTree: StreamsTreeProvider,
        private readonly outputChannel: vscode.OutputChannel
    ) {}

    /**
     * Register this provider with VS Code.
     */
    public static register(
        context: vscode.ExtensionContext,
        tsharkRunner: TsharkRunner,
        capturesTree: CapturesTreeProvider,
        streamsTree: StreamsTreeProvider,
        outputChannel: vscode.OutputChannel
    ): vscode.Disposable {
        const provider = new CaptureEditorProvider(
            context.extensionUri,
            tsharkRunner,
            capturesTree,
            streamsTree,
            outputChannel
        );
        return vscode.window.registerCustomEditorProvider(
            CaptureEditorProvider.viewType,
            provider,
            {
                webviewOptions: {
                    retainContextWhenHidden: true,
                },
                supportsMultipleEditorsPerDocument: false,
            }
        );
    }

    /**
     * Called when VS Code opens a pcap file.
     */
    async openCustomDocument(
        uri: vscode.Uri,
        _openContext: vscode.CustomDocumentOpenContext,
        _token: vscode.CancellationToken
    ): Promise<CaptureDocument> {
        return new CaptureDocument(uri);
    }

    /**
     * Called when VS Code needs to show the editor for an opened pcap file.
     * We ensure the file is tracked in the captures tree, then delegate
     * to CaptureWebviewPanel which manages the full Wireshark-like UI.
     */
    async resolveCustomEditor(
        document: CaptureDocument,
        webviewPanel: vscode.WebviewPanel,
        _token: vscode.CancellationToken
    ): Promise<void> {
        const filePath = document.uri.fsPath;
        const fileName = path.basename(filePath);

        this.outputChannel.appendLine(`[CaptureEditor] Opening ${fileName} via custom editor`);

        // Ensure this capture is tracked in the captures tree
        let capture = this.capturesTree.getCaptures().find(c => c.filePath === filePath);
        if (!capture) {
            let sizeBytes = 0;
            try {
                const stat = await vscode.workspace.fs.stat(document.uri);
                sizeBytes = stat.size;
            } catch {
                // If stat fails, continue with 0 size
            }

            capture = {
                filePath,
                name: fileName,
                sizeBytes,
                parsed: false,
            };

            // Detect role from folder name
            const parentDir = path.basename(path.dirname(filePath)).toLowerCase();
            if (parentDir === 'client') { capture.role = 'client'; }
            else if (parentDir === 'server') { capture.role = 'server'; }

            this.capturesTree.addCapture(capture);
        }

        // Close the webview panel that VS Code created for the custom editor —
        // we'll open our own CaptureWebviewPanel instead, which has the full
        // Wireshark-like functionality and is reused across the extension.
        //
        // We use a small delay to let VS Code finish setting up the custom editor
        // before we dispose of its panel and open ours.
        webviewPanel.webview.html = this.getRedirectHtml(fileName);

        // Parse if needed, then open the real viewer
        setTimeout(async () => {
            // Dispose the custom editor panel — we're replacing it
            webviewPanel.dispose();

            // Parse if not already parsed and tshark is available
            if (!capture!.parsed && this.tsharkRunner.isAvailable()) {
                await vscode.window.withProgress({
                    location: vscode.ProgressLocation.Notification,
                    title: `Parsing ${capture!.name}...`,
                    cancellable: false,
                }, async (progress) => {
                    try {
                        progress.report({ message: 'Reading capture summary...' });
                        capture!.summary = await this.tsharkRunner.getCaptureSummary(filePath);
                        capture!.parsed = true;
                        this.capturesTree.refresh();

                        progress.report({ message: 'Extracting conversations...' });
                        const streams = await this.tsharkRunner.getConversations(filePath);
                        const existingStreams = this.streamsTree.getStreams().filter(s => s.captureFile !== filePath);
                        this.streamsTree.setStreams([...existingStreams, ...streams]);
                    } catch (e) {
                        this.outputChannel.appendLine(`[CaptureEditor] Parse error: ${e}`);
                    }
                });
            }

            // Open the full capture viewer
            CaptureWebviewPanel.createOrShow(this.extensionUri, capture!, this.tsharkRunner, this.outputChannel);
        }, 100);
    }

    /**
     * Brief loading HTML shown while we redirect to the real capture viewer.
     */
    private getRedirectHtml(fileName: string): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <style>
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            font-family: var(--vscode-font-family);
            color: var(--vscode-foreground);
            background: var(--vscode-editor-background);
        }
        .loading {
            text-align: center;
        }
        .spinner {
            width: 40px;
            height: 40px;
            border: 3px solid var(--vscode-editorWidget-border);
            border-top-color: var(--vscode-progressBar-background);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin: 0 auto 16px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="loading">
        <div class="spinner"></div>
        <div>Opening ${fileName} in NetTrace Capture Viewer...</div>
    </div>
</body>
</html>`;
    }
}

/**
 * Minimal custom document for pcap files.
 * Since pcap files are binary and read-only (we use tshark to parse them),
 * this is just a thin wrapper around the URI.
 */
class CaptureDocument implements vscode.CustomDocument {
    constructor(public readonly uri: vscode.Uri) {}

    dispose(): void {
        // No resources to clean up — tshark parsing is stateless
    }
}

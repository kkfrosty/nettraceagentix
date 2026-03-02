import * as vscode from 'vscode';
import * as path from 'path';
import { CaptureFile } from '../types';

/**
 * Minimal shape stored in globalState for each imported capture.
 * We only persist the file path and role — everything else is re-derived on load.
 */
interface PersistedCapture {
    filePath: string;
    role?: 'client' | 'server';
}

const PERSISTED_CAPTURES_KEY = 'nettrace.captures';

/**
 * TreeView provider for the Captures section in the NetTrace sidebar.
 * Shows all pcap/pcapng/pcpap files in the workspace, organized by folder.
 *
 * Persists imported capture file paths to globalState so they survive
 * across VS Code sessions, project switches, and window reloads.
 */
export class CapturesTreeProvider implements vscode.TreeDataProvider<CaptureTreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<CaptureTreeItem | undefined | void>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private captures: CaptureFile[] = [];
    private globalState: vscode.Memento;

    constructor(globalState: vscode.Memento) {
        this.globalState = globalState;
    }

    /**
     * Restore previously imported captures from globalState.
     * Called once during activation, before discoverCaptures.
     * Verifies each file still exists; prunes stale entries.
     */
    async restorePersistedCaptures(): Promise<number> {
        const persisted = this.globalState.get<PersistedCapture[]>(PERSISTED_CAPTURES_KEY, []);
        let restoredCount = 0;
        const stillValid: PersistedCapture[] = [];

        for (const entry of persisted) {
            try {
                const stat = await vscode.workspace.fs.stat(vscode.Uri.file(entry.filePath));
                const capture: CaptureFile = {
                    filePath: entry.filePath,
                    name: path.basename(entry.filePath),
                    sizeBytes: stat.size,
                    parsed: false,
                    role: entry.role,
                };
                this.captures.push(capture);
                stillValid.push(entry);
                restoredCount++;
            } catch {
                // File no longer exists — skip it
            }
        }

        // Prune stale entries
        if (stillValid.length !== persisted.length) {
            await this.globalState.update(PERSISTED_CAPTURES_KEY, stillValid);
        }

        if (restoredCount > 0) {
            this.refresh();
        }
        return restoredCount;
    }

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    setCaptures(captures: CaptureFile[]): void {
        this.captures = captures;
        this.refresh();
    }

    addCapture(capture: CaptureFile): void {
        // Deduplicate by filePath
        if (this.captures.some(c => c.filePath === capture.filePath)) {
            return;
        }
        this.captures.push(capture);
        this._persistCaptures();
        this.refresh();
    }

    removeCapture(filePath: string): void {
        this.captures = this.captures.filter(c => c.filePath !== filePath);
        this._persistCaptures();
        this.refresh();
    }

    getCaptures(): CaptureFile[] {
        return this.captures;
    }

    getTreeItem(element: CaptureTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: CaptureTreeItem): CaptureTreeItem[] {
        if (!element) {
            // Root level: group by parent folder
            const folders = new Map<string, CaptureFile[]>();
            for (const capture of this.captures) {
                const dir = path.dirname(capture.filePath);
                const folderName = path.basename(dir);
                if (!folders.has(folderName)) {
                    folders.set(folderName, []);
                }
                folders.get(folderName)!.push(capture);
            }

            if (folders.size === 1) {
                // Single folder — show files directly
                const files = Array.from(folders.values())[0];
                return files.map(f => this.createFileItem(f));
            }

            // Multiple folders — show folder tree
            return Array.from(folders.entries()).map(([name, files]) =>
                this.createFolderItem(name, files)
            );
        }

        if (element.contextValue === 'captureFolder') {
            return (element.children || []).map(f => this.createFileItem(f));
        }

        // File items that are parsed — show summary as children
        if (element.contextValue === 'captureFile' && element.capture?.summary) {
            const summary = element.capture.summary;
            return [
                new CaptureTreeItem(
                    `${summary.packetCount} packets, ${summary.durationSeconds.toFixed(1)}s`,
                    vscode.TreeItemCollapsibleState.None,
                    'captureInfo'
                ),
                new CaptureTreeItem(
                    `${summary.tcpStreamCount} TCP streams`,
                    vscode.TreeItemCollapsibleState.None,
                    'captureInfo'
                ),
                ...(summary.expertInfo && summary.expertInfo.errors > 0
                    ? [new CaptureTreeItem(
                        `${summary.expertInfo.errors} errors, ${summary.expertInfo.warnings} warnings`,
                        vscode.TreeItemCollapsibleState.None,
                        'captureInfo'
                    )]
                    : []),
            ];
        }

        return [];
    }

    private createFolderItem(name: string, files: CaptureFile[]): CaptureTreeItem {
        const item = new CaptureTreeItem(
            name,
            vscode.TreeItemCollapsibleState.Expanded,
            'captureFolder'
        );
        item.children = files;
        item.iconPath = new vscode.ThemeIcon('folder');
        return item;
    }

    private createFileItem(capture: CaptureFile): CaptureTreeItem {
        const state = capture.parsed
            ? vscode.TreeItemCollapsibleState.Collapsed
            : vscode.TreeItemCollapsibleState.None;

        const item = new CaptureTreeItem(capture.name, state, 'captureFile');
        item.capture = capture;
        // Note: Do NOT set item.resourceUri — it causes VS Code to try opening
        // the binary .pcap file as text on double-click instead of using our command.

        // Description shows size and role
        const sizeMB = (capture.sizeBytes / (1024 * 1024)).toFixed(1);
        const roleLabel = capture.role ? ` [${capture.role}]` : '';
        item.description = `${sizeMB} MB${roleLabel}`;

        // Icon based on parse state and role
        if (capture.role === 'client') {
            item.iconPath = new vscode.ThemeIcon('vm');
        } else if (capture.role === 'server') {
            item.iconPath = new vscode.ThemeIcon('server');
        } else if (capture.parsed) {
            item.iconPath = new vscode.ThemeIcon('file-binary');
        } else {
            item.iconPath = new vscode.ThemeIcon('file');
        }

        // Tooltip — always show the full source path so users know where the file lives
        const locationLine = `📂 ${capture.filePath}`;
        if (capture.summary) {
            item.tooltip = `${capture.name}\n${capture.summary.packetCount} packets | ${capture.summary.tcpStreamCount} TCP streams | ${capture.summary.durationSeconds.toFixed(2)}s\n\n${locationLine}\n\nClick to open capture viewer`;
        } else {
            item.tooltip = `${capture.name}\n${locationLine}\n\nClick to open capture viewer`;
        }

        // Click to open webview
        item.command = {
            command: 'nettrace.openCapture',
            title: 'Open Capture',
            arguments: [item],
        };

        return item;
    }

    /**
     * Persist current capture paths to globalState for cross-session survival.
     */
    private _persistCaptures(): void {
        const toSave: PersistedCapture[] = this.captures.map(c => ({
            filePath: c.filePath,
            ...(c.role ? { role: c.role } : {}),
        }));
        this.globalState.update(PERSISTED_CAPTURES_KEY, toSave);
    }
}

export class CaptureTreeItem extends vscode.TreeItem {
    capture?: CaptureFile;
    children?: CaptureFile[];

    constructor(
        label: string,
        collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly contextValue: string
    ) {
        super(label, collapsibleState);
    }
}

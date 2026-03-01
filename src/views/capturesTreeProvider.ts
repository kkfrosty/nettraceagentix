import * as vscode from 'vscode';
import * as path from 'path';
import { CaptureFile } from '../types';

/**
 * TreeView provider for the Captures section in the NetTrace sidebar.
 * Shows all pcap/pcapng files in the workspace, organized by folder.
 */
export class CapturesTreeProvider implements vscode.TreeDataProvider<CaptureTreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<CaptureTreeItem | undefined | void>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private captures: CaptureFile[] = [];

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    setCaptures(captures: CaptureFile[]): void {
        this.captures = captures;
        this.refresh();
    }

    addCapture(capture: CaptureFile): void {
        this.captures.push(capture);
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

        // Tooltip
        if (capture.summary) {
            item.tooltip = `${capture.name}\n${capture.summary.packetCount} packets | ${capture.summary.tcpStreamCount} TCP streams | ${capture.summary.durationSeconds.toFixed(2)}s\n\nClick to open capture viewer`;
        } else {
            item.tooltip = `${capture.name}\nClick to open capture viewer`;
        }

        // Click to open webview
        item.command = {
            command: 'nettrace.openCapture',
            title: 'Open Capture',
            arguments: [item],
        };

        return item;
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

import * as vscode from 'vscode';
import { TcpStream } from '../types';

/**
 * TreeView provider for the Streams section in the NetTrace sidebar.
 * Shows TCP/UDP streams sorted by anomaly score (most suspicious first).
 */
export class StreamsTreeProvider implements vscode.TreeDataProvider<StreamTreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<StreamTreeItem | undefined | void>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private streams: TcpStream[] = [];

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    setStreams(streams: TcpStream[]): void {
        // Sort by anomaly score descending (most suspicious first)
        this.streams = [...streams].sort((a, b) => b.anomalyScore - a.anomalyScore);
        this.refresh();
    }

    getStreams(): TcpStream[] {
        return this.streams;
    }

    getTreeItem(element: StreamTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: StreamTreeItem): StreamTreeItem[] {
        if (!element) {
            // Root level: show all streams
            return this.streams.map(s => this.createStreamItem(s));
        }

        // Stream children: show anomaly details
        if (element.contextValue === 'stream' && element.stream) {
            const items: StreamTreeItem[] = [];

            // Connection info
            items.push(new StreamTreeItem(
                `${element.stream.source} → ${element.stream.destination}`,
                vscode.TreeItemCollapsibleState.None,
                'streamInfo'
            ));

            items.push(new StreamTreeItem(
                `${element.stream.packetCount} packets, ${this.formatBytes(element.stream.totalBytes)}, ${element.stream.durationSeconds.toFixed(2)}s`,
                vscode.TreeItemCollapsibleState.None,
                'streamInfo'
            ));

            if (element.stream.appProtocol) {
                items.push(new StreamTreeItem(
                    `Protocol: ${element.stream.appProtocol}`,
                    vscode.TreeItemCollapsibleState.None,
                    'streamInfo'
                ));
            }

            // Anomalies
            for (const anomaly of element.stream.anomalies) {
                const item = new StreamTreeItem(
                    anomaly.description,
                    vscode.TreeItemCollapsibleState.None,
                    'streamAnomaly'
                );
                item.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
                items.push(item);
            }

            return items;
        }

        return [];
    }

    private createStreamItem(stream: TcpStream): StreamTreeItem {
        const hasAnomalies = stream.anomalies.length > 0;
        const state = hasAnomalies
            ? vscode.TreeItemCollapsibleState.Collapsed
            : vscode.TreeItemCollapsibleState.None;

        // Build label
        const label = `Stream ${stream.index}`;
        const item = new StreamTreeItem(label, state, 'stream');
        item.stream = stream;

        // Description
        const proto = stream.appProtocol ? `${stream.appProtocol} ` : '';
        const endpoints = `${stream.source} ↔ ${stream.destination}`;
        item.description = `${proto}${endpoints}`;

        // Icon based on status
        if (stream.excluded) {
            item.iconPath = new vscode.ThemeIcon('circle-slash', new vscode.ThemeColor('disabledForeground'));
        } else if (stream.anomalyScore >= 10) {
            item.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
        } else if (stream.anomalyScore > 0) {
            item.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
        } else {
            item.iconPath = new vscode.ThemeIcon('pass', new vscode.ThemeColor('testing.iconPassed'));
        }

        // Tooltip
        const anomalyText = stream.anomalies.map(a => `  • ${a.description}`).join('\n');
        item.tooltip = `Stream ${stream.index}: ${stream.source} ↔ ${stream.destination}\n${stream.packetCount} packets, ${this.formatBytes(stream.totalBytes)}, ${stream.durationSeconds.toFixed(2)}s\nAnomaly Score: ${stream.anomalyScore}${anomalyText ? '\n\nAnomalies:\n' + anomalyText : ''}`;

        return item;
    }

    private formatBytes(bytes: number): string {
        if (bytes < 1024) { return `${bytes} B`; }
        if (bytes < 1024 * 1024) { return `${(bytes / 1024).toFixed(1)} KB`; }
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    }
}

export class StreamTreeItem extends vscode.TreeItem {
    stream?: TcpStream;

    constructor(
        label: string,
        collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly contextValue: string
    ) {
        super(label, collapsibleState);
    }
}

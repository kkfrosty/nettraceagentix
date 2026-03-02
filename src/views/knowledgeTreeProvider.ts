import * as vscode from 'vscode';
import * as path from 'path';

/**
 * TreeView provider for the Knowledge section in the NetTrace sidebar.
 * Shows knowledge files from .nettrace/knowledge/ organized by category:
 *   - wisdom/       (always loaded — false positive avoidance)
 *   - security/     (conditional — activated by capture signals)
 *   - known-issues/ (always loaded — vendor/OS-specific knowledge)
 *
 * Users edit these .md files to adjust how the AI analyzes captures.
 */
export class KnowledgeTreeProvider implements vscode.TreeDataProvider<KnowledgeTreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<KnowledgeTreeItem | undefined | void>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private categories: Array<{ dir: string; label: string; description: string; icon: string; tooltip: string }> = [
        { dir: 'security', label: 'Security Heuristics', description: 'Activated when suspicious packets detected', icon: 'shield',
          tooltip: 'Injected into AI context ONLY when suspicious patterns are detected (malformed packets, fragments, checksum errors, suspicious flags).\n\nUse for: attack signatures, IDS-like pattern descriptions, threshold-based detection guidance.' },
        { dir: 'wisdom', label: 'Analysis Guidance', description: 'Always applied — expert tips & false positive avoidance', icon: 'lightbulb',
          tooltip: 'ALWAYS injected into AI context for every analysis.\n\nUse for: environment-specific tips, false positive notes, common patterns in your infrastructure, protocol quirks.' },
        { dir: 'known-issues', label: 'Known Issues', description: 'Always applied — vendor/OS-specific behaviors', icon: 'warning',
          tooltip: 'ALWAYS injected into AI context for every analysis.\n\nUse for: OS-specific TCP quirks, firewall behaviors, known vendor bugs, application-specific patterns.' },
    ];

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: KnowledgeTreeItem): vscode.TreeItem {
        return element;
    }

    async getChildren(element?: KnowledgeTreeItem): Promise<KnowledgeTreeItem[]> {
        const folders = vscode.workspace.workspaceFolders;
        if (!folders) { return []; }

        const knowledgeBase = vscode.Uri.joinPath(folders[0].uri, '.nettrace', 'knowledge');

        if (!element) {
            // Root: show categories
            return this.categories.map(cat => {
                const item = new KnowledgeTreeItem(
                    cat.label,
                    vscode.TreeItemCollapsibleState.Expanded,
                    'knowledgeCategory'
                );
                item.description = cat.description;
                item.iconPath = new vscode.ThemeIcon(cat.icon);
                item.categoryDir = cat.dir;
                item.tooltip = new vscode.MarkdownString(cat.tooltip);
                return item;
            });
        }

        if (element.contextValue === 'knowledgeCategory' && element.categoryDir) {
            // Category level: show .md files in the category folder
            const categoryUri = vscode.Uri.joinPath(knowledgeBase, element.categoryDir);
            try {
                const entries = await vscode.workspace.fs.readDirectory(categoryUri);
                const mdFiles = entries
                    .filter(([name, type]) => type === vscode.FileType.File && name.endsWith('.md'))
                    .map(([name]) => {
                        const item = new KnowledgeTreeItem(
                            name.replace('.md', ''),
                            vscode.TreeItemCollapsibleState.None,
                            'knowledgeFile'
                        );
                        item.description = name;
                        item.iconPath = new vscode.ThemeIcon('file-text');
                        item.tooltip = `Click to edit. Changes take effect immediately.\n\nFile: .nettrace/knowledge/${element.categoryDir}/${name}`;
                        item.filePath = vscode.Uri.joinPath(categoryUri, name).fsPath;

                        // Click to open the markdown file
                        item.command = {
                            command: 'nettrace.editKnowledge',
                            title: 'Edit Knowledge File',
                            arguments: [item],
                        };

                        return item;
                    });

                if (mdFiles.length === 0) {
                    const emptyItem = new KnowledgeTreeItem(
                        'No files yet — click + to add',
                        vscode.TreeItemCollapsibleState.None,
                        'knowledgeEmpty'
                    );
                    emptyItem.iconPath = new vscode.ThemeIcon('info');
                    return [emptyItem];
                }

                return mdFiles;
            } catch {
                // Directory doesn't exist yet
                const emptyItem = new KnowledgeTreeItem(
                    'No files yet — click + to add',
                    vscode.TreeItemCollapsibleState.None,
                    'knowledgeEmpty'
                );
                emptyItem.iconPath = new vscode.ThemeIcon('info');
                return [emptyItem];
            }
        }

        return [];
    }
}

export class KnowledgeTreeItem extends vscode.TreeItem {
    categoryDir?: string;
    filePath?: string;

    constructor(
        label: string,
        collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly contextValue: string
    ) {
        super(label, collapsibleState);
    }
}

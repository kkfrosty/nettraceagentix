import * as vscode from 'vscode';
import { AgentDefinition } from '../types';
import { ConfigLoader } from '../configLoader';

/**
 * TreeView provider for the Agents section in the NetTrace sidebar.
 * Shows available analysis agents with their active/inactive state.
 */
export class AgentsTreeProvider implements vscode.TreeDataProvider<AgentTreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<AgentTreeItem | undefined | void>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private activeAgentName: string = 'general';

    constructor(private configLoader: ConfigLoader) {
        configLoader.onAgentsChanged(() => this.refresh());
    }

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    setActiveAgent(name: string): void {
        this.activeAgentName = name;
        this.refresh();
    }

    getActiveAgent(): AgentDefinition {
        return this.configLoader.getAgent(this.activeAgentName) || this.configLoader.getDefaultAgent();
    }

    getTreeItem(element: AgentTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: AgentTreeItem): AgentTreeItem[] {
        if (element) { return []; }

        const agents = this.configLoader.getAllAgents();
        return agents.map(agent => {
            const isActive = agent.name === this.activeAgentName;
            const isBuiltIn = agent.name === 'general';
            const item = new AgentTreeItem(
                agent.displayName,
                vscode.TreeItemCollapsibleState.None,
                isBuiltIn ? 'agent' : 'userAgent' // userAgent enables delete in context menu
            );
            item.agent = agent;
            item.description = isActive ? '(active)' : agent.description;

            // Rich tooltip showing agent capabilities
            const toolList = agent.tools && agent.tools.length > 0
                ? agent.tools.map(t => t.replace('nettrace-', '')).join(', ')
                : 'default tools';
            const filterInfo = agent.autoFilters?.displayFilter
                ? `\nDisplay Filter: ${agent.autoFilters.displayFilter}`
                : '';
            const priorityInfo = agent.contextPriority?.prioritySignals?.length
                ? `\nPriority Signals: ${agent.contextPriority.prioritySignals.join(', ')}`
                : '';
            item.tooltip = new vscode.MarkdownString(
                `**${agent.displayName}**\n\n` +
                `${agent.description || 'No description'}\n\n` +
                `**Tools:** ${toolList}${filterInfo}${priorityInfo}\n\n` +
                `_Click to activate this agent for analysis._`
            );

            // Icon
            const iconName = agent.icon || 'robot';
            item.iconPath = isActive
                ? new vscode.ThemeIcon(iconName, new vscode.ThemeColor('testing.iconPassed'))
                : new vscode.ThemeIcon(iconName);

            // Click to activate
            item.command = {
                command: 'nettrace.selectAgent',
                title: 'Select Agent',
                arguments: [agent.name],
            };

            return item;
        });
    }
}

export class AgentTreeItem extends vscode.TreeItem {
    agent?: AgentDefinition;

    constructor(
        label: string,
        collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly contextValue: string
    ) {
        super(label, collapsibleState);
    }
}

import * as vscode from 'vscode';
import { ScenarioDetails } from '../types';
import { ConfigLoader } from '../configLoader';

/**
 * TreeView provider for the Scenario Details section in the NetTrace sidebar.
 * Shows the current scenario context that gets injected into every LLM prompt.
 */
export class ScenarioDetailsTreeProvider implements vscode.TreeDataProvider<ScenarioDetailItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<ScenarioDetailItem | undefined | void>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    constructor(private configLoader: ConfigLoader) {
        configLoader.onConfigChanged(() => this.refresh());
    }

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: ScenarioDetailItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: ScenarioDetailItem): ScenarioDetailItem[] {
        if (element) { return []; }

        const scenarioDetails = this.configLoader.getScenarioDetails();
        const items: ScenarioDetailItem[] = [];

        items.push(this.createFieldItem('Scenario ID', scenarioDetails.scenarioId || '(not set)', 'scenarioId'));
        items.push(this.createFieldItem('Summary', scenarioDetails.summary || '(not set)', 'summary'));
        items.push(this.createFieldItem('Symptom', scenarioDetails.symptom || '(not set)', 'symptom'));

        if (scenarioDetails.topology) {
            if (scenarioDetails.topology.clientIP) {
                items.push(this.createFieldItem('Client IP', scenarioDetails.topology.clientIP, 'clientIP'));
            }
            if (scenarioDetails.topology.serverIP) {
                items.push(this.createFieldItem('Server IP', scenarioDetails.topology.serverIP, 'serverIP'));
            }
            if (scenarioDetails.topology.description) {
                items.push(this.createFieldItem('Topology', scenarioDetails.topology.description, 'topology'));
            }
        }

        if (scenarioDetails.notes) {
            items.push(this.createFieldItem('Notes', scenarioDetails.notes, 'notes'));
        }

        return items;
    }

    private createFieldItem(label: string, value: string, fieldKey: string): ScenarioDetailItem {
        const item = new ScenarioDetailItem(
            label,
            vscode.TreeItemCollapsibleState.None,
            'scenarioField'
        );
        item.description = value;
        item.fieldKey = fieldKey;
        item.iconPath = new vscode.ThemeIcon(this.getIconForField(fieldKey));
        item.command = {
            command: 'nettrace.editScenarioDetails',
            title: 'Edit',
            arguments: [fieldKey],
        };
        return item;
    }

    private getIconForField(fieldKey: string): string {
        const icons: Record<string, string> = {
            scenarioId: 'tag',
            summary: 'note',
            symptom: 'bug',
            clientIP: 'vm',
            serverIP: 'server',
            topology: 'type-hierarchy',
            notes: 'comment',
        };
        return icons[fieldKey] || 'info';
    }
}

export class ScenarioDetailItem extends vscode.TreeItem {
    fieldKey?: string;

    constructor(
        label: string,
        collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly contextValue: string
    ) {
        super(label, collapsibleState);
    }
}

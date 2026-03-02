import * as vscode from 'vscode';
import * as path from 'path';
import { NetTraceConfig, ScenarioDetails, AgentDefinition, ToolDefinition, FilterConfig, KnowledgeEntry } from './types';

/**
 * Loads and watches configuration files from the .nettrace/ folder.
 * Supports hot-reload: when JSON files change, the config is re-read without restarting.
 */
export class ConfigLoader {
    private config: NetTraceConfig = {};
    private scenarioDetails: ScenarioDetails = {};
    private agents: Map<string, AgentDefinition> = new Map();
    private tools: Map<string, ToolDefinition> = new Map();
    private filters: Map<string, FilterConfig> = new Map();
    private knowledge: KnowledgeEntry[] = [];
    private watchers: vscode.FileSystemWatcher[] = [];
    private outputChannel: vscode.OutputChannel;

    private readonly _onConfigChanged = new vscode.EventEmitter<void>();
    readonly onConfigChanged = this._onConfigChanged.event;

    private readonly _onAgentsChanged = new vscode.EventEmitter<void>();
    readonly onAgentsChanged = this._onAgentsChanged.event;

    private readonly _onKnowledgeChanged = new vscode.EventEmitter<void>();
    readonly onKnowledgeChanged = this._onKnowledgeChanged.event;

    constructor(outputChannel: vscode.OutputChannel) {
        this.outputChannel = outputChannel;
    }

    /**
     * Load all configuration from the workspace's .nettrace/ folder.
     */
    async loadAll(): Promise<void> {
        const folders = vscode.workspace.workspaceFolders;
        if (!folders || folders.length === 0) {
            this.outputChannel.appendLine('[ConfigLoader] No workspace folder open.');
            return;
        }

        const rootUri = folders[0].uri;
        const nettraceUri = vscode.Uri.joinPath(rootUri, '.nettrace');

        await Promise.all([
            this.loadConfig(nettraceUri),
            this.loadScenarioDetails(nettraceUri),
            this.loadAgents(nettraceUri),
            this.loadTools(nettraceUri),
            this.loadFilters(nettraceUri),
            this.loadKnowledge(nettraceUri),
        ]);

        this.setupWatchers(rootUri);
    }

    /**
     * Set up file watchers for hot-reload.
     */
    private setupWatchers(rootUri: vscode.Uri): void {
        // Dispose existing watchers
        this.watchers.forEach(w => w.dispose());
        this.watchers = [];

        const configWatcher = vscode.workspace.createFileSystemWatcher(
            new vscode.RelativePattern(rootUri, '.nettrace/config.json')
        );
        configWatcher.onDidChange(() => this.loadConfig(vscode.Uri.joinPath(rootUri, '.nettrace')));
        configWatcher.onDidCreate(() => this.loadConfig(vscode.Uri.joinPath(rootUri, '.nettrace')));
        this.watchers.push(configWatcher);

        const scenarioWatcher = vscode.workspace.createFileSystemWatcher(
            new vscode.RelativePattern(rootUri, '.nettrace/scenario.json')
        );
        scenarioWatcher.onDidChange(() => this.loadScenarioDetails(vscode.Uri.joinPath(rootUri, '.nettrace')));
        scenarioWatcher.onDidCreate(() => this.loadScenarioDetails(vscode.Uri.joinPath(rootUri, '.nettrace')));
        this.watchers.push(scenarioWatcher);

        const agentWatcher = vscode.workspace.createFileSystemWatcher(
            new vscode.RelativePattern(rootUri, '.nettrace/agents/*.json')
        );
        agentWatcher.onDidChange(() => this.loadAgents(vscode.Uri.joinPath(rootUri, '.nettrace')));
        agentWatcher.onDidCreate(() => this.loadAgents(vscode.Uri.joinPath(rootUri, '.nettrace')));
        agentWatcher.onDidDelete(() => this.loadAgents(vscode.Uri.joinPath(rootUri, '.nettrace')));
        this.watchers.push(agentWatcher);

        const toolWatcher = vscode.workspace.createFileSystemWatcher(
            new vscode.RelativePattern(rootUri, '.nettrace/tools/*.json')
        );
        toolWatcher.onDidChange(() => this.loadTools(vscode.Uri.joinPath(rootUri, '.nettrace')));
        toolWatcher.onDidCreate(() => this.loadTools(vscode.Uri.joinPath(rootUri, '.nettrace')));
        toolWatcher.onDidDelete(() => this.loadTools(vscode.Uri.joinPath(rootUri, '.nettrace')));
        this.watchers.push(toolWatcher);

        const filterWatcher = vscode.workspace.createFileSystemWatcher(
            new vscode.RelativePattern(rootUri, '.nettrace/filters/*.json')
        );
        filterWatcher.onDidChange(() => this.loadFilters(vscode.Uri.joinPath(rootUri, '.nettrace')));
        filterWatcher.onDidCreate(() => this.loadFilters(vscode.Uri.joinPath(rootUri, '.nettrace')));
        filterWatcher.onDidDelete(() => this.loadFilters(vscode.Uri.joinPath(rootUri, '.nettrace')));
        this.watchers.push(filterWatcher);

        // Watch knowledge files (markdown in knowledge/**)
        const knowledgeWatcher = vscode.workspace.createFileSystemWatcher(
            new vscode.RelativePattern(rootUri, '.nettrace/knowledge/**/*.md')
        );
        knowledgeWatcher.onDidChange(() => this.loadKnowledge(vscode.Uri.joinPath(rootUri, '.nettrace')));
        knowledgeWatcher.onDidCreate(() => this.loadKnowledge(vscode.Uri.joinPath(rootUri, '.nettrace')));
        knowledgeWatcher.onDidDelete(() => this.loadKnowledge(vscode.Uri.joinPath(rootUri, '.nettrace')));
        this.watchers.push(knowledgeWatcher);
    }

    // ─── Individual Loaders ───────────────────────────────────────────────

    private async loadConfig(nettraceUri: vscode.Uri): Promise<void> {
        try {
            const configUri = vscode.Uri.joinPath(nettraceUri, 'config.json');
            const data = await vscode.workspace.fs.readFile(configUri);
            this.config = JSON.parse(Buffer.from(data).toString());
            this.outputChannel.appendLine('[ConfigLoader] Config loaded.');
            this._onConfigChanged.fire();
        } catch {
            this.config = {};
            this.outputChannel.appendLine('[ConfigLoader] No config.json found, using defaults.');
        }
    }

    private async loadScenarioDetails(nettraceUri: vscode.Uri): Promise<void> {
        try {
            const scenarioUri = vscode.Uri.joinPath(nettraceUri, 'scenario.json');
            const data = await vscode.workspace.fs.readFile(scenarioUri);
            this.scenarioDetails = JSON.parse(Buffer.from(data).toString());
            this.outputChannel.appendLine('[ConfigLoader] Scenario details loaded.');
            this._onConfigChanged.fire();
        } catch {
            this.scenarioDetails = {};
        }
    }

    private async loadAgents(nettraceUri: vscode.Uri): Promise<void> {
        this.agents.clear();

        // Always load built-in agents first
        this.loadBuiltInAgents();

        try {
            const agentsUri = vscode.Uri.joinPath(nettraceUri, 'agents');
            const entries = await vscode.workspace.fs.readDirectory(agentsUri);
            for (const [name, type] of entries) {
                if (type === vscode.FileType.File && name.endsWith('.json')) {
                    try {
                        const fileUri = vscode.Uri.joinPath(agentsUri, name);
                        const data = await vscode.workspace.fs.readFile(fileUri);
                        const agent: AgentDefinition = JSON.parse(Buffer.from(data).toString());

                        // Validate required fields
                        if (!agent.name || typeof agent.name !== 'string') {
                            this.outputChannel.appendLine(`[ConfigLoader] Skipping agent ${name}: missing or invalid 'name' field`);
                            continue;
                        }
                        if (!agent.systemPrompt || typeof agent.systemPrompt !== 'string') {
                            this.outputChannel.appendLine(`[ConfigLoader] Warning: agent ${name} has no systemPrompt — using default`);
                            agent.systemPrompt = `You are a network analyst specializing in ${agent.displayName || agent.name} analysis.`;
                        }
                        if (!agent.displayName) {
                            agent.displayName = agent.name;
                        }
                        if (!agent.description) {
                            agent.description = '';
                        }

                        this.agents.set(agent.name, agent);
                        this.outputChannel.appendLine(`[ConfigLoader] Agent loaded: ${agent.displayName}`);
                    } catch (e) {
                        this.outputChannel.appendLine(`[ConfigLoader] Failed to load agent ${name}: ${e}`);
                    }
                }
            }
        } catch {
            // agents/ directory doesn't exist yet — that's fine
        }

        this._onAgentsChanged.fire();
    }

    private loadBuiltInAgents(): void {
        this.agents.set('general', {
            name: 'general',
            displayName: 'General Analyzer',
            description: 'General-purpose network trace analysis for any protocol',
            icon: 'search',
            systemPrompt: `You are an expert network analyst helping a support engineer diagnose issues from packet captures.

Your approach:
1. Start with the capture summary to understand the overall picture
2. Identify anomalies: retransmissions, RSTs, TLS alerts, HTTP errors, timeouts
3. Focus on streams with the highest anomaly scores
4. Correlate timing — look for patterns in when problems occur
5. Consider the topology — is the issue client-side, server-side, or in between?

Always reference specific packet numbers, timestamps, and stream indices.
When you find a root cause, explain it clearly and suggest remediation steps.
If you need more data about a specific stream, use the available tools to retrieve it.`,
            tools: [
                'nettrace-getStreamDetail',
                'nettrace-getPacketRange',
                'nettrace-applyFilter',
                'nettrace-getConversations',
                'nettrace-followStream',
                'nettrace-setDisplayFilter',
                'nettrace-runTshark',
                'nettrace-createAgent',
                'nettrace-createKnowledge',
            ],
            followups: [
                { label: 'Show retransmissions', prompt: 'What streams have the most retransmissions and what might be causing them?' },
                { label: 'Check for errors', prompt: 'What errors and warnings does the expert info show?' },
                { label: 'Top talkers', prompt: 'Who are the top talkers in this capture and is the traffic distribution normal?' },
            ],
        });
    }

    private async loadTools(nettraceUri: vscode.Uri): Promise<void> {
        this.tools.clear();
        try {
            const toolsUri = vscode.Uri.joinPath(nettraceUri, 'tools');
            const entries = await vscode.workspace.fs.readDirectory(toolsUri);
            for (const [name, type] of entries) {
                if (type === vscode.FileType.File && name.endsWith('.json')) {
                    try {
                        const fileUri = vscode.Uri.joinPath(toolsUri, name);
                        const data = await vscode.workspace.fs.readFile(fileUri);
                        const tool: ToolDefinition = JSON.parse(Buffer.from(data).toString());
                        this.tools.set(tool.name, tool);
                        this.outputChannel.appendLine(`[ConfigLoader] Tool loaded: ${tool.displayName}`);
                    } catch (e) {
                        this.outputChannel.appendLine(`[ConfigLoader] Failed to load tool ${name}: ${e}`);
                    }
                }
            }
        } catch {
            // tools/ directory doesn't exist yet
        }
    }

    private async loadFilters(nettraceUri: vscode.Uri): Promise<void> {
        this.filters.clear();
        try {
            const filtersUri = vscode.Uri.joinPath(nettraceUri, 'filters');
            const entries = await vscode.workspace.fs.readDirectory(filtersUri);
            for (const [name, type] of entries) {
                if (type === vscode.FileType.File && name.endsWith('.json')) {
                    try {
                        const fileUri = vscode.Uri.joinPath(filtersUri, name);
                        const data = await vscode.workspace.fs.readFile(fileUri);
                        const filter = JSON.parse(Buffer.from(data).toString());
                        this.filters.set(filter.name || name.replace('.json', ''), filter);
                    } catch (e) {
                        this.outputChannel.appendLine(`[ConfigLoader] Failed to load filter ${name}: ${e}`);
                    }
                }
            }
        } catch {
            // filters/ directory doesn't exist yet
        }
    }

    /**
     * Load knowledge base files from .nettrace/knowledge/.
     * Organized by category:
     *   wisdom/   — Always injected (false positives, known quirks, expert guidance)
     *   security/ — Injected only when security-relevant anomalies are detected
     *   known-issues/ — Always injected (vendor bugs, OS behaviors, firewall quirks)
     *
     * Users add/edit .md files to teach the agent about situations it gets wrong.
     */
    private async loadKnowledge(nettraceUri: vscode.Uri): Promise<void> {
        this.knowledge = [];

        const categories: Array<{ dir: string; category: KnowledgeEntry['category'] }> = [
            { dir: 'wisdom', category: 'wisdom' },
            { dir: 'security', category: 'security' },
            { dir: 'known-issues', category: 'known-issues' },
        ];

        for (const { dir, category } of categories) {
            try {
                const dirUri = vscode.Uri.joinPath(nettraceUri, 'knowledge', dir);
                const entries = await vscode.workspace.fs.readDirectory(dirUri);
                for (const [name, type] of entries) {
                    if (type === vscode.FileType.File && name.endsWith('.md')) {
                        try {
                            const fileUri = vscode.Uri.joinPath(dirUri, name);
                            const data = await vscode.workspace.fs.readFile(fileUri);
                            const content = Buffer.from(data).toString();
                            this.knowledge.push({
                                source: `knowledge/${dir}/${name}`,
                                category,
                                content,
                            });
                            this.outputChannel.appendLine(`[ConfigLoader] Knowledge loaded: ${dir}/${name} (${category})`);
                        } catch (e) {
                            this.outputChannel.appendLine(`[ConfigLoader] Failed to load knowledge ${dir}/${name}: ${e}`);
                        }
                    }
                }
            } catch {
                // Directory doesn't exist yet — that's fine
            }
        }

        this.outputChannel.appendLine(
            `[ConfigLoader] Knowledge base: ${this.knowledge.length} entries ` +
            `(${this.knowledge.filter(k => k.category === 'wisdom').length} wisdom, ` +
            `${this.knowledge.filter(k => k.category === 'security').length} security, ` +
            `${this.knowledge.filter(k => k.category === 'known-issues').length} known-issues)`
        );

        this._onKnowledgeChanged.fire();
    }

    // ─── Accessors ────────────────────────────────────────────────────────

    getConfig(): NetTraceConfig {
        return this.config;
    }

    getScenarioDetails(): ScenarioDetails {
        return this.scenarioDetails;
    }

    getAgent(name: string): AgentDefinition | undefined {
        return this.agents.get(name);
    }

    getDefaultAgent(): AgentDefinition {
        const defaultName = this.config.defaultAgent || vscode.workspace.getConfiguration('nettrace').get<string>('defaultAgent') || 'general';
        return this.agents.get(defaultName) || this.agents.get('general')!;
    }

    getAllAgents(): AgentDefinition[] {
        return Array.from(this.agents.values());
    }

    getTool(name: string): ToolDefinition | undefined {
        return this.tools.get(name);
    }

    getAllTools(): ToolDefinition[] {
        return Array.from(this.tools.values());
    }

    getEffectiveFilters(agent?: AgentDefinition): FilterConfig {
        // Merge: built-in defaults → config defaults → agent autoFilters
        const builtIn: FilterConfig = {
            excludeProtocols: vscode.workspace.getConfiguration('nettrace').get<string[]>('excludeProtocols') || [],
            maxPacketsPerStream: vscode.workspace.getConfiguration('nettrace').get<number>('maxPacketsPerStream') || 1000,
        };

        const configFilters = this.config.defaultFilters || {};

        // Merge agent's excludeProtocols if the agent defines autoFilters
        const agentExclude = agent?.autoFilters?.excludeProtocols || [];

        return {
            excludeProtocols: [...new Set([...(builtIn.excludeProtocols || []), ...(configFilters.excludeProtocols || []), ...agentExclude])],
            excludeIPs: configFilters.excludeIPs || [],
            includeFilter: agent?.autoFilters?.displayFilter || configFilters.includeFilter,
            excludeFilter: configFilters.excludeFilter,
            maxPacketsPerStream: configFilters.maxPacketsPerStream || builtIn.maxPacketsPerStream,
        };
    }

    // ─── Knowledge Base Accessors ─────────────────────────────────────────

    /**
     * Get knowledge entries that should always be injected (wisdom + known-issues).
     */
    getAlwaysOnKnowledge(): KnowledgeEntry[] {
        return this.knowledge.filter(k => k.category === 'wisdom' || k.category === 'known-issues');
    }

    /**
     * Get knowledge entries that are only injected when security signals are detected.
     */
    getSecurityKnowledge(): KnowledgeEntry[] {
        return this.knowledge.filter(k => k.category === 'security');
    }

    /**
     * Get all knowledge entries.
     */
    getAllKnowledge(): KnowledgeEntry[] {
        return [...this.knowledge];
    }

    async updateScenarioDetails(updates: Partial<ScenarioDetails>): Promise<void> {
        this.scenarioDetails = { ...this.scenarioDetails, ...updates };

        const folders = vscode.workspace.workspaceFolders;
        if (!folders) { return; }

        const scenarioUri = vscode.Uri.joinPath(folders[0].uri, '.nettrace', 'scenario.json');
        const content = Buffer.from(JSON.stringify(this.scenarioDetails, null, 2));
        await vscode.workspace.fs.writeFile(scenarioUri, content);
    }

    dispose(): void {
        this.watchers.forEach(w => w.dispose());
        this._onConfigChanged.dispose();
        this._onAgentsChanged.dispose();
        this._onKnowledgeChanged.dispose();
    }
}

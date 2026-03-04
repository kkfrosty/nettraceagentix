import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import * as cp from 'child_process';
import { TsharkRunner } from './parsing/tsharkRunner';
import { ConfigLoader } from './configLoader';
import { ContextAssembler } from './contextAssembler';
import { WorkspaceInitializer } from './workspaceInitializer';
import { CapturesTreeProvider } from './views/capturesTreeProvider';
import { StreamsTreeProvider } from './views/streamsTreeProvider';
import { ScenarioDetailsTreeProvider } from './views/scenarioDetailsTreeProvider';
import { AgentsTreeProvider } from './views/agentsTreeProvider';
import { KnowledgeTreeProvider } from './views/knowledgeTreeProvider';
import { NetTraceParticipant } from './participant/nettraceParticipant';
import { registerLMTools } from './tools/lmTools';
import { CaptureWebviewPanel } from './views/captureWebviewPanel';
import { CaptureEditorProvider } from './views/captureEditorProvider';
import { LiveCaptureWebviewPanel } from './views/liveCaptureWebviewPanel';
import { CaptureFile } from './types';
import { Logger } from './logger';
import { getNetTraceRootUri, ensureDefaultFiles, validateCustomStoragePath, cleanupGlobalStorage } from './storage';

let outputChannel: vscode.OutputChannel;
let logger: Logger;
let extensionContext: vscode.ExtensionContext | undefined;
/** Module-level reference so deactivate() can stop live captures. */
let activeTsharkRunner: TsharkRunner | undefined;

export async function activate(context: vscode.ExtensionContext) {
    // Top-level try/catch — ensures we ALWAYS log failures to Debug Console,
    // even if something goes wrong before our logger is set up.
    try {
        return await activateInternal(context);
    } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        const stack = e instanceof Error ? e.stack : '';
        console.error(`[NetTrace] FATAL: Extension activation failed with unhandled error: ${msg}`);
        console.error(`[NetTrace] Stack: ${stack}`);
        if (logger) {
            logger.error('Activation', 'FATAL: Unhandled error during activation', e);
        }
        if (outputChannel) {
            outputChannel.show(true);
        }
        vscode.window.showErrorMessage(
            `NetTrace failed to activate: ${msg}. Check Output > NetTrace for details.`,
            'Show Log'
        ).then(action => {
            if (action === 'Show Log') {
                outputChannel?.show();
            }
        });
    }
}

async function activateInternal(context: vscode.ExtensionContext) {
    const activationStart = Date.now();
    extensionContext = context; // stored for use in deactivate()
    console.log('[NetTrace] ════════════════════════════════════════════════');
    console.log('[NetTrace] Extension activate() called');
    console.log('[NetTrace] All NetTrace log lines are prefixed with [NetTrace].');
    console.log('[NetTrace] Errors WITHOUT this prefix are from OTHER extensions.');
    console.log('[NetTrace] ════════════════════════════════════════════════');
    outputChannel = vscode.window.createOutputChannel('NetTrace', { log: true });
    logger = Logger.init(outputChannel);

    logger.divider('NetTrace Agentix Activation');
    logger.info('Activation', 'Extension activation starting...');

    // ─── Environment Diagnostics ──────────────────────────────────────────

    logger.logEnvironment();
    const deps = await logger.logDependencies();
    logger.logExtensionEnvironment();
    logger.divider('Initialization Steps');

    // ─── Storage Resolution & First-Run Provisioning ──────────────────────

    logger.startStep('Storage Resolution');
    let rootUri: vscode.Uri;
    try {
        // Validate custom path if set
        const customPath = vscode.workspace.getConfiguration('nettrace').get<string>('storagePath', '').trim();
        if (customPath) {
            const valid = await validateCustomStoragePath(customPath, outputChannel);
            if (!valid) {
                logger.warn('Storage', `Custom storage path invalid: ${customPath} — falling back to globalStorageUri`);
            }
        }

        rootUri = getNetTraceRootUri(context);
        logger.info('Storage', `Root URI: ${rootUri.fsPath}`);

        // Ensure globalStorageUri directory exists (VS Code may not create it until first use)
        await vscode.workspace.fs.createDirectory(rootUri);

        // First-run provisioning: copy bundled defaults for any missing files
        const createdCount = await ensureDefaultFiles(rootUri, context.extensionUri, outputChannel);
        if (createdCount > 0) {
            const isFirstRun = !context.globalState.get<boolean>('nettrace.initialized');
            if (isFirstRun) {
                logger.info('Storage', `First-run: provisioned ${createdCount} default files`);
                await context.globalState.update('nettrace.initialized', true);
            } else {
                logger.info('Storage', `Integrity check: restored ${createdCount} missing file(s)`);
            }
        }
        logger.endStep('Storage Resolution', true, rootUri.fsPath);
    } catch (e) {
        logger.endStep('Storage Resolution', false, String(e));
        logger.error('Storage', 'Failed to resolve/provision storage — using globalStorageUri fallback', e);
        rootUri = context.globalStorageUri;
        try { await vscode.workspace.fs.createDirectory(rootUri); } catch { /* best effort */ }
        try { await ensureDefaultFiles(rootUri, context.extensionUri, outputChannel); } catch { /* best effort */ }
    }

    // ─── Core Services ────────────────────────────────────────────────────

    logger.startStep('Core Services');
    let tsharkRunner: TsharkRunner;
    let configLoader: ConfigLoader;
    let workspaceInitializer: WorkspaceInitializer;
    try {
        tsharkRunner = new TsharkRunner(outputChannel);
        activeTsharkRunner = tsharkRunner; // stored for use in deactivate()
        configLoader = new ConfigLoader(rootUri, outputChannel);
        workspaceInitializer = new WorkspaceInitializer(rootUri, outputChannel);
        logger.endStep('Core Services', true);
    } catch (e) {
        logger.endStep('Core Services', false, String(e));
        logger.error('Activation', 'Fatal: Could not create core services', e);
        vscode.window.showErrorMessage('NetTrace failed to initialize core services. Check Output > NetTrace for details.');
        return;
    }

    // Detect tshark (non-blocking — don't await the user prompt)
    logger.startStep('tshark Detection');
    try {
        const tsharkPath = await tsharkRunner.detectTshark();
        if (tsharkPath) {
            logger.endStep('tshark Detection', true, `found at: ${tsharkPath}`);
        } else {
            logger.endStep('tshark Detection', false, 'not found — capture parsing disabled');
            // Fire-and-forget: show warning without blocking activation
            vscode.window.showWarningMessage(
                'NetTrace: tshark (Wireshark CLI) is required but was not found. Install Wireshark to enable capture analysis.',
                'Download Wireshark',
                'Configure Path'
            ).then(action => {
                if (action === 'Download Wireshark') {
                    vscode.env.openExternal(vscode.Uri.parse('https://www.wireshark.org/download.html'));
                } else if (action === 'Configure Path') {
                    vscode.commands.executeCommand('workbench.action.openSettings', 'nettrace.tsharkPath');
                }
            });
        }
    } catch (e) {
        logger.endStep('tshark Detection', false, 'exception during detection');
        logger.error('TsharkRunner', 'tshark detection threw an exception', e);
    }

    // ─── TreeView Providers ───────────────────────────────────────────────

    logger.startStep('TreeView Providers');
    let capturesTree: CapturesTreeProvider;
    let streamsTree: StreamsTreeProvider;
    let scenarioDetailsTree: ScenarioDetailsTreeProvider;
    let agentsTree: AgentsTreeProvider;
    let knowledgeTree: KnowledgeTreeProvider;
    try {
        capturesTree = new CapturesTreeProvider(context.globalState);
        streamsTree = new StreamsTreeProvider();
        scenarioDetailsTree = new ScenarioDetailsTreeProvider(configLoader);
        agentsTree = new AgentsTreeProvider(configLoader);
        knowledgeTree = new KnowledgeTreeProvider(rootUri, configLoader);

        context.subscriptions.push(
            vscode.window.registerTreeDataProvider('nettrace.captures', capturesTree),
            vscode.window.registerTreeDataProvider('nettrace.agents', agentsTree),
            vscode.window.registerTreeDataProvider('nettrace.knowledge', knowledgeTree),
            vscode.window.registerTreeDataProvider('nettrace.scenarioDetails', scenarioDetailsTree),
        );

        // Refresh knowledge tree when knowledge files change
        configLoader.onKnowledgeChanged(() => knowledgeTree.refresh());
        logger.endStep('TreeView Providers', true, '5 tree providers registered');
    } catch (e) {
        logger.endStep('TreeView Providers', false, String(e));
        logger.error('Activation', 'Fatal: Could not register tree views', e);
        vscode.window.showErrorMessage('NetTrace failed to register sidebar views. Check Output > NetTrace for details.');
        return;
    }

    // ─── Context Assembler ────────────────────────────────────────────────

    logger.startStep('Context Assembler');
    let contextAssembler: ContextAssembler;
    try {
        contextAssembler = new ContextAssembler(tsharkRunner, configLoader, outputChannel);
        logger.endStep('Context Assembler', true);
    } catch (e) {
        logger.endStep('Context Assembler', false, String(e));
        logger.error('Activation', 'Fatal: Could not create context assembler', e);
        vscode.window.showErrorMessage('NetTrace failed to create context assembler. Check Output > NetTrace for details.');
        return;
    }

    // ─── Chat Participant ─────────────────────────────────────────────────

    logger.startStep('Chat Participant');
    if (deps.chatApi) {
        try {
            const participant = new NetTraceParticipant(
                context, tsharkRunner, configLoader, contextAssembler,
                capturesTree, agentsTree, streamsTree, outputChannel
            );
            logger.endStep('Chat Participant', true, '@nettrace participant registered');
        } catch (e) {
            logger.endStep('Chat Participant', false, String(e));
            logger.error('Activation', 'Could not register @nettrace chat participant. Copilot Chat features will be unavailable.', e);
        }
    } else {
        logger.endStep('Chat Participant', false, 'vscode.chat API not available — skipped');
        logger.warn('Activation', 'Skipping chat participant registration (vscode.chat API unavailable). Install/enable GitHub Copilot Chat extension.');
    }

    // ─── Custom Editor for pcap/pcapng/cap/pcpap files ────────────────────

    logger.startStep('Custom Editor Provider');
    try {
        context.subscriptions.push(
            CaptureEditorProvider.register(context, tsharkRunner, capturesTree, streamsTree, outputChannel)
        );
        logger.endStep('Custom Editor Provider', true, 'pcap/pcapng/cap/pcpap editor registered');
    } catch (e) {
        logger.endStep('Custom Editor Provider', false, String(e));
        logger.error('Activation', 'Could not register custom editor for capture files. Double-clicking .pcap/.pcpap files may not work.', e);
    }

    // ─── Language Model Tools ─────────────────────────────────────────────

    logger.startStep('Language Model Tools');
    if (deps.lmApi) {
        try {
            registerLMTools(context, tsharkRunner, capturesTree, configLoader, outputChannel);
            logger.endStep('Language Model Tools', true, 'LM tools registered');
        } catch (e) {
            logger.endStep('Language Model Tools', false, String(e));
            logger.error('Activation', 'Could not register LM tools. AI tool-calling will be unavailable.', e);
        }
    } else {
        logger.endStep('Language Model Tools', false, 'vscode.lm API not available — skipped');
        logger.warn('Activation', 'Skipping LM tool registration (vscode.lm API unavailable). Install/enable GitHub Copilot Chat extension.');
    }

    // ─── Commands ─────────────────────────────────────────────────────────

    logger.startStep('Command Registration');
    let commandCount = 0;
    try {

    // Initialize Workspace
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.initWorkspace', async () => {
            await workspaceInitializer.initializeWorkspace();
            await configLoader.loadAll();
            scenarioDetailsTree.refresh();
            agentsTree.refresh();
        })
    );

    // Import Capture File
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.importCapture', async () => {
            const files = await vscode.window.showOpenDialog({
                canSelectFiles: true,
                canSelectMany: true,
                filters: {
                    'Capture Files': ['pcap', 'pcapng', 'cap', 'pcpap'],
                    'All Files': ['*'],
                },
                title: 'Import Capture File',
            });

            if (!files || files.length === 0) { return; }

            for (const fileUri of files) {
                outputChannel.appendLine(`Imported: ${path.basename(fileUri.fsPath)} (tracked at ${fileUri.fsPath})`);
                await addAndParseCapture(fileUri.fsPath, tsharkRunner, capturesTree, streamsTree);
            }
        })
    );

    // Parse Capture
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.parseCapture', async (item: any) => {
            const filePath = item?.capture?.filePath || item?.resourceUri?.fsPath;
            if (!filePath) { return; }
            await addAndParseCapture(filePath, tsharkRunner, capturesTree, streamsTree);
        })
    );

    // Delete Capture (from list and optionally from disk)
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.deleteCapture', async (item: any, allSelected?: any[]) => {
            // Multi-select: allSelected contains all highlighted items; single: just use item
            const targets: string[] = [];
            const rawItems = (allSelected && allSelected.length > 0) ? allSelected : [item];
            for (const raw of rawItems) {
                const fp = raw?.capture?.filePath || raw?.resourceUri?.fsPath || (typeof raw === 'string' ? raw : undefined);
                if (fp) { targets.push(fp); }
            }
            if (targets.length === 0) { return; }

            const multi = targets.length > 1;
            const label = multi ? `${targets.length} captures` : `"${path.basename(targets[0])}"`;

            // Check which targets still exist on disk
            const onDisk = targets.filter(fp => fs.existsSync(fp));
            const warningItems = onDisk.length > 0
                ? ['Delete Files + Remove from List', 'Remove from List Only', 'Cancel']
                : ['Remove from List', 'Cancel'];

            const choice = await vscode.window.showWarningMessage(
                `Delete ${label}?`,
                { modal: true },
                ...warningItems
            );

            if (!choice || choice === 'Cancel') { return; }

            if (choice === 'Delete Files + Remove from List' || choice === 'Delete File + Remove from List') {
                for (const fp of onDisk) {
                    try {
                        await vscode.workspace.fs.delete(vscode.Uri.file(fp));
                        outputChannel.appendLine(`[Capture] Deleted file: ${fp}`);
                    } catch (e) {
                        vscode.window.showErrorMessage(`Failed to delete file: ${e}`);
                    }
                }
            }

            capturesTree.removeCaptures(targets);
            const removedSet = new Set(targets);
            streamsTree.setStreams(streamsTree.getStreams().filter(s => !removedSet.has(s.captureFile)));
            outputChannel.appendLine(`[Capture] Removed from list: ${targets.join(', ')}`);
        })
    );

    // Edit Scenario Details
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.editScenarioDetails', async (fieldKey?: string) => {
            const currentScenario = configLoader.getScenarioDetails();

            if (fieldKey) {
                // Edit a specific field
                const currentValue = getNestedValue(currentScenario, fieldKey) || '';
                const newValue = await vscode.window.showInputBox({
                    prompt: `Edit ${fieldKey}`,
                    value: String(currentValue),
                    title: `NetTrace: Edit ${fieldKey}`,
                });
                if (newValue !== undefined) {
                    const updates: any = {};
                    setNestedValue(updates, fieldKey, newValue);
                    await configLoader.updateScenarioDetails(updates);
                    scenarioDetailsTree.refresh();
                }
            } else {
                // Edit all fields via quick input sequence
                const scenarioId = await vscode.window.showInputBox({
                    prompt: 'Scenario/Ticket ID',
                    value: currentScenario.scenarioId || '',
                });
                const symptom = await vscode.window.showInputBox({
                    prompt: 'Reported Symptom',
                    value: currentScenario.symptom || '',
                });
                const summary = await vscode.window.showInputBox({
                    prompt: 'Summary',
                    value: currentScenario.summary || '',
                });
                const notes = await vscode.window.showInputBox({
                    prompt: 'Notes',
                    value: currentScenario.notes || '',
                });

                await configLoader.updateScenarioDetails({
                    scenarioId: scenarioId ?? currentScenario.scenarioId,
                    symptom: symptom ?? currentScenario.symptom,
                    summary: summary ?? currentScenario.summary,
                    notes: notes ?? currentScenario.notes,
                });
                scenarioDetailsTree.refresh();
            }
        })
    );

    // Select Agent
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.selectAgent', async (agentName?: string) => {
            if (agentName) {
                agentsTree.setActiveAgent(agentName);
                return;
            }

            const agents = configLoader.getAllAgents();
            const pick = await vscode.window.showQuickPick(
                agents.map(a => ({
                    label: a.displayName,
                    description: a.description,
                    agentName: a.name,
                })),
                { placeHolder: 'Select an analysis agent', title: 'NetTrace: Select Agent' }
            );

            if (pick) {
                agentsTree.setActiveAgent((pick as any).agentName);
            }
        })
    );

    // Create Agent — wizard to create a new analysis agent
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.createAgent', async () => {

            const name = await vscode.window.showInputBox({
                prompt: 'Agent ID (lowercase, no spaces)',
                placeHolder: 'e.g., tls-specialist, dns-analyzer, custom-firewall',
                title: 'NetTrace: Create Agent',
                validateInput: (v) => /^[a-z0-9-]+$/.test(v) ? null : 'Use lowercase letters, numbers, and hyphens only',
            });
            if (!name) { return; }

            const displayName = await vscode.window.showInputBox({
                prompt: 'Display name',
                placeHolder: 'e.g., TLS/SSL Specialist',
                title: 'NetTrace: Create Agent',
                value: name.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' '),
            });
            if (!displayName) { return; }

            const description = await vscode.window.showInputBox({
                prompt: 'Short description',
                placeHolder: 'e.g., Expert at diagnosing TLS handshake failures and certificate issues',
                title: 'NetTrace: Create Agent',
            });

            const template = await vscode.window.showQuickPick([
                { label: 'Blank', description: 'Start with a minimal prompt' },
                { label: 'General Analyzer', description: 'Copy from the built-in general analyzer' },
                { label: 'Protocol Specialist', description: 'Template for protocol-focused analysis' },
            ], { placeHolder: 'Start from a template?', title: 'NetTrace: Create Agent' });
            if (!template) { return; }

            let systemPrompt = '';
            if (template.label === 'Blank') {
                systemPrompt = `You are a network analyst specializing in ${displayName} analysis.\n\nProvide your analysis instructions here.`;
            } else if (template.label === 'General Analyzer') {
                const general = configLoader.getAgent('general');
                systemPrompt = general?.systemPrompt || 'You are an expert network analyst.';
            } else {
                systemPrompt = `You are an expert network analyst specializing in ${displayName?.toLowerCase()} traffic analysis.\n\nYour approach:\n1. Identify relevant traffic using the display filter\n2. Analyze protocol-specific patterns and anomalies\n3. Check for misconfigurations, failures, and security issues\n4. Correlate timing and sequence of events\n5. Provide specific remediation steps\n\nAlways reference specific packet numbers, timestamps, and stream indices.`;
            }

            const displayFilter = await vscode.window.showInputBox({
                prompt: 'Wireshark display filter (optional — focuses the agent on specific traffic)',
                placeHolder: 'e.g., tls || ssl || tcp.port == 443',
                title: 'NetTrace: Create Agent',
            });

            const agentDef = {
                name,
                displayName,
                description: description || '',
                icon: 'robot',
                systemPrompt,
                autoFilters: displayFilter ? { displayFilter } : undefined,
                tools: [
                    'nettrace-getStreamDetail',
                    'nettrace-getPacketRange',
                    'nettrace-applyFilter',
                    'nettrace-getConversations',
                    'nettrace-followStream',
                ],
                followups: [],
            };

            // Save to .nettrace/agents/
            const agentsDir = vscode.Uri.joinPath(rootUri, '.nettrace', 'agents');
            try {
                await vscode.workspace.fs.createDirectory(agentsDir);
            } catch { /* exists */ }

            const agentUri = vscode.Uri.joinPath(agentsDir, `${name}.json`);
            await vscode.workspace.fs.writeFile(agentUri, Buffer.from(JSON.stringify(agentDef, null, 2)));

            // Open the file so the user can edit the prompt
            const doc = await vscode.workspace.openTextDocument(agentUri);
            await vscode.window.showTextDocument(doc);

            vscode.window.showInformationMessage(`Agent "${displayName}" created. Edit the systemPrompt in the JSON to customize its behavior.`);
        })
    );

    // Edit Agent — open the agent's JSON file for editing
    // For built-in agents, materialize to a file first so users can edit the prompt directly.
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.editAgent', async (item: any) => {
            const agent = item?.agent;
            if (!agent) { return; }

            const agentsDir = vscode.Uri.joinPath(rootUri, '.nettrace', 'agents');
            const agentUri = vscode.Uri.joinPath(agentsDir, `${agent.name}.json`);

            // Check if agent file exists on disk
            let fileExists = false;
            try {
                await vscode.workspace.fs.stat(agentUri);
                fileExists = true;
            } catch { /* doesn't exist yet */ }

            // If no file on disk (built-in agent), write it out so the user can edit it
            if (!fileExists) {
                try {
                    await vscode.workspace.fs.createDirectory(agentsDir);
                } catch { /* exists */ }

                const agentJson = {
                    name: agent.name,
                    displayName: agent.displayName,
                    description: agent.description,
                    icon: agent.icon || 'search',
                    systemPrompt: agent.systemPrompt,
                    tools: agent.tools || [],
                    followups: agent.followups || [],
                };

                await vscode.workspace.fs.writeFile(agentUri, Buffer.from(JSON.stringify(agentJson, null, 2)));
                outputChannel.appendLine(`[Extension] Materialized built-in agent "${agent.name}" to ${agentUri.fsPath} for editing`);
            }

            const doc = await vscode.workspace.openTextDocument(agentUri);
            await vscode.window.showTextDocument(doc);
        })
    );

    // Duplicate Agent — create a copy of an existing agent
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.duplicateAgent', async (item: any) => {
            const agent = item?.agent;
            if (!agent) { return; }

            const newName = await vscode.window.showInputBox({
                prompt: 'Name for the copy (lowercase, no spaces)',
                placeHolder: `${agent.name}-copy`,
                value: `${agent.name}-custom`,
                title: 'NetTrace: Duplicate Agent',
                validateInput: (v) => /^[a-z0-9-]+$/.test(v) ? null : 'Use lowercase letters, numbers, and hyphens only',
            });
            if (!newName) { return; }

            const copy = {
                ...agent,
                name: newName,
                displayName: `${agent.displayName} (Custom)`,
            };

            const agentsDir = vscode.Uri.joinPath(rootUri, '.nettrace', 'agents');
            try { await vscode.workspace.fs.createDirectory(agentsDir); } catch { /* exists */ }

            const agentUri = vscode.Uri.joinPath(agentsDir, `${newName}.json`);
            await vscode.workspace.fs.writeFile(agentUri, Buffer.from(JSON.stringify(copy, null, 2)));

            const doc = await vscode.workspace.openTextDocument(agentUri);
            await vscode.window.showTextDocument(doc);
            vscode.window.showInformationMessage(`Agent duplicated as "${newName}". Edit the systemPrompt to customize.`);
        })
    );

    // Delete Agent — remove a user-created agent
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.deleteAgent', async (item: any) => {
            const agent = item?.agent;
            if (!agent) { return; }

            if (agent.name === 'general') {
                vscode.window.showWarningMessage('Cannot delete the built-in General Analyzer.');
                return;
            }

            const confirm = await vscode.window.showWarningMessage(
                `Delete agent "${agent.displayName}"? This cannot be undone.`,
                { modal: true },
                'Delete'
            );
            if (confirm !== 'Delete') { return; }

            const agentUri = vscode.Uri.joinPath(rootUri, '.nettrace', 'agents', `${agent.name}.json`);
            try {
                await vscode.workspace.fs.delete(agentUri);
                vscode.window.showInformationMessage(`Agent "${agent.displayName}" deleted.`);
            } catch (e) {
                vscode.window.showErrorMessage(`Could not delete agent: ${e}`);
            }
        })
    );

    // Edit Knowledge — open a knowledge .md file for editing
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.editKnowledge', async (item: any) => {
            const filePath = item?.filePath;
            if (!filePath) { return; }

            const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
            await vscode.window.showTextDocument(doc);
        })
    );

    // Toggle Knowledge — enable or disable a knowledge file with a marker comment
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.toggleKnowledge', async (item: any) => {
            const filePath = item?.filePath;
            if (!filePath) { return; }

            try {
                const fileUri = vscode.Uri.file(filePath);
                const data = await vscode.workspace.fs.readFile(fileUri);
                const content = Buffer.from(data).toString();
                const DISABLED_MARKER = '<!-- nettrace-disabled -->';

                let newContent: string;
                if (content.startsWith(DISABLED_MARKER)) {
                    // Currently disabled — remove marker to re-enable
                    newContent = content.slice(DISABLED_MARKER.length).replace(/^\n/, '');
                    vscode.window.showInformationMessage(`Knowledge enabled: ${filePath.split(/[\\/]/).pop()}`);
                } else {
                    // Currently enabled — prepend marker to disable
                    newContent = `${DISABLED_MARKER}\n${content}`;
                    vscode.window.showInformationMessage(`Knowledge disabled: ${filePath.split(/[\\/]/).pop()} — it will no longer be injected into AI context.`);
                }

                await vscode.workspace.fs.writeFile(fileUri, Buffer.from(newContent));
                // File watcher in configLoader detects the change → triggers reload → tree refreshes automatically
            } catch (e) {
                vscode.window.showErrorMessage(`Could not toggle knowledge file: ${e instanceof Error ? e.message : String(e)}`);
            }
        })
    );

    // Create Knowledge — create a new .md file in a knowledge category
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.createKnowledge', async () => {

            const category = await vscode.window.showQuickPick([
                { label: 'Security Heuristics', value: 'security', description: 'Rules for detecting attacks, malformed packets, suspicious patterns' },
                { label: 'Analysis Guidance', value: 'wisdom', description: 'Expert tips, false positive avoidance, environment-specific notes' },
                { label: 'Known Issues', value: 'known-issues', description: 'Vendor-specific bugs, OS behaviors, firewall quirks' },
            ], { placeHolder: 'What type of knowledge?', title: 'NetTrace: Add Knowledge' });
            if (!category) { return; }

            const fileName = await vscode.window.showInputBox({
                prompt: 'File name (without .md extension)',
                placeHolder: 'e.g., checkpoint-firewall-quirks, aks-packet-duplication',
                title: 'NetTrace: Add Knowledge',
                validateInput: (v) => /^[a-z0-9-]+$/.test(v) ? null : 'Use lowercase letters, numbers, and hyphens',
            });
            if (!fileName) { return; }

            const categoryDir = vscode.Uri.joinPath(rootUri, '.nettrace', 'knowledge', (category as any).value);
            try {
                await vscode.workspace.fs.createDirectory(categoryDir);
            } catch { /* exists */ }

            const fileUri = vscode.Uri.joinPath(categoryDir, `${fileName}.md`);

            const template = `# ${fileName.split('-').map((w: string) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}\n\nAdd your analysis guidance here. This content is injected into the AI's context\nwhen analyzing captures. Use markdown formatting.\n\n## Example\n- Describe patterns the AI should look for\n- Note known false positives specific to your environment\n- Document vendor-specific behaviors\n`;

            await vscode.workspace.fs.writeFile(fileUri, Buffer.from(template));

            const doc = await vscode.workspace.openTextDocument(fileUri);
            await vscode.window.showTextDocument(doc);
            knowledgeTree.refresh();
        })
    );

    // Set Client/Server Capture
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.setClientCapture', async (item: any) => {
            const filePath = item?.capture?.filePath;
            if (!filePath) { return; }
            setCaptureRole(filePath, 'client', capturesTree);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.setServerCapture', async (item: any) => {
            const filePath = item?.capture?.filePath;
            if (!filePath) { return; }
            setCaptureRole(filePath, 'server', capturesTree);
        })
    );

    // Exclude / Focus Stream
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.excludeStream', async (item: any) => {
            const stream = item?.stream;
            if (!stream) { return; }
            const streams = streamsTree.getStreams();
            const target = streams.find(s => s.index === stream.index);
            if (target) {
                target.excluded = true;
                streamsTree.setStreams(streams);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.focusStream', async (item: any) => {
            const stream = item?.stream;
            if (!stream) { return; }
            // Exclude all other streams, keep only this one
            const streams = streamsTree.getStreams();
            for (const s of streams) {
                s.excluded = s.index !== stream.index;
            }
            streamsTree.setStreams(streams);
            vscode.window.showInformationMessage(`Focused on stream ${stream.index}. All other streams excluded from analysis.`);
        })
    );

    // Analyze Stream (opens chat with stream context)
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.analyzeStream', async (item: any) => {
            const stream = item?.stream;
            if (!stream) { return; }
            await vscode.commands.executeCommand('workbench.action.chat.open', {
                query: `@nettrace /stream ${stream.index} Analyze this stream in detail. What's happening and is there anything wrong?`,
            });
        })
    );

    // Analyze Capture with AI — opens Copilot Chat with @nettrace for a specific capture
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.analyzeCapture', async (item: any) => {
            const capture = item?.capture;
            const name = capture?.name || 'this capture';
            await vscode.commands.executeCommand('workbench.action.chat.open', {
                query: `@nettrace /summarize Analyze ${name}. Give me an overview of what's in this capture and highlight anything suspicious or problematic.`,
            });
        })
    );

    // Analyze All — opens Copilot Chat to analyze all loaded captures
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.analyzeAll', async () => {
            const count = capturesTree.getCaptures().length;
            if (count === 0) {
                vscode.window.showInformationMessage('No captures loaded. Import a capture file first.');
                return;
            }
            await vscode.commands.executeCommand('workbench.action.chat.open', {
                query: `@nettrace /diagnose Analyze all ${count} loaded capture(s). What issues do you see? What's the root cause?`,
            });
        })
    );

    // Open Capture Viewer — opens the webview panel for a capture
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.openCapture', async (item: any) => {
            const capture = item?.capture || item;
            if (!capture?.filePath) {
                // If no item, offer to pick from loaded captures
                const captures = capturesTree.getCaptures();
                if (captures.length === 0) {
                    vscode.window.showInformationMessage('No captures loaded. Import a capture file first.');
                    return;
                }
                if (captures.length === 1) {
                    CaptureWebviewPanel.createOrShow(context.extensionUri, captures[0], tsharkRunner, outputChannel);
                    return;
                }
                const pick = await vscode.window.showQuickPick(
                    captures.map(c => ({ label: c.name, description: c.role ? `[${c.role}]` : '', capture: c })),
                    { placeHolder: 'Select a capture to open' }
                );
                if (pick) {
                    CaptureWebviewPanel.createOrShow(context.extensionUri, (pick as any).capture, tsharkRunner, outputChannel);
                }
                return;
            }
            // Verify the file still exists before trying to open it
            try {
                await vscode.workspace.fs.stat(vscode.Uri.file(capture.filePath));
            } catch {
                const action = await vscode.window.showWarningMessage(
                    `Capture file not found — it may have been moved or deleted:\n${capture.filePath}`,
                    'Remove from List',
                    'Re-import'
                );
                if (action === 'Remove from List') {
                    capturesTree.removeCapture(capture.filePath);
                } else if (action === 'Re-import') {
                    vscode.commands.executeCommand('nettrace.importCapture');
                }
                return;
            }
            CaptureWebviewPanel.createOrShow(context.extensionUri, capture, tsharkRunner, outputChannel);
        })
    );

    // Close Capture — closes the active webview panel so user can start fresh
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.closeCapture', async () => {
            CaptureWebviewPanel.closeActive();
        })
    );

    // Apply Filter — can be called from chat to push a filter into the active viewer
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.applyFilter', async (filter?: string) => {
            if (!filter) {
                filter = await vscode.window.showInputBox({
                    prompt: 'Enter a Wireshark display filter',
                    placeHolder: 'tcp.stream == 5',
                    title: 'NetTrace: Apply Filter',
                });
            }
            if (filter !== undefined) {
                CaptureWebviewPanel.applyFilterToActive(filter);
            }
        })
    );

    // Ask AI — generic entry point to start a conversation
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.askAI', async () => {
            const captures = capturesTree.getCaptures();
            if (captures.length === 0) {
                await vscode.commands.executeCommand('workbench.action.chat.open', {
                    query: `@nettrace I want to analyze a network capture. Help me get started.`,
                });
            } else {
                await vscode.commands.executeCommand('workbench.action.chat.open', {
                    query: `@nettrace `,
                });
            }
        })
    );

    // ── Live Capture commands ──────────────────────────────────────────

    // Open Live Capture panel
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.openLiveCapture', async (prefill?: any) => {
            if (!tsharkRunner.isAvailable()) {
                vscode.window.showWarningMessage(
                    'tshark not found. Install Wireshark and restart VS Code, or set nettrace.tsharkPath in settings.',
                    'Open Settings'
                ).then(a => {
                    if (a === 'Open Settings') { vscode.commands.executeCommand('workbench.action.openSettings', 'nettrace.tsharkPath'); }
                });
                return;
            }
            await LiveCaptureWebviewPanel.createOrShow(context.extensionUri, tsharkRunner, outputChannel, prefill);
        })
    );

    // Stop active live capture
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.stopLiveCapture', () => {
            const panel = LiveCaptureWebviewPanel.getActivePanel();
            if (panel) {
                panel.stopCapture();
            } else {
                vscode.window.showInformationMessage('No live capture is currently running.');
            }
        })
    );

    // New Capture — reset the active live capture panel to configure state
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.newLiveCapture', () => {
            const panel = LiveCaptureWebviewPanel.getActivePanel();
            if (panel) {
                panel.newCapture();
            } else {
                vscode.commands.executeCommand('nettrace.openLiveCapture');
            }
        })
    );

    // ── End Live Capture commands ──────────────────────────────────────

    // Open in Wireshark
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.openInWireshark', async (item: any) => {
            const filePath = item?.capture?.filePath || item?.resourceUri?.fsPath || (typeof item === 'string' ? item : undefined);
            if (!filePath) { return; }

            if (!fs.existsSync(filePath)) {
                vscode.window.showErrorMessage(`Capture file not found: ${filePath}`);
                return;
            }

            const configured = vscode.workspace.getConfiguration('nettrace').get<string>('wiresharkPath', '').trim();
            const candidates = configured
                ? [configured]
                : [
                    'wireshark',
                    'C:\\Program Files\\Wireshark\\Wireshark.exe',
                    'C:\\Program Files (x86)\\Wireshark\\Wireshark.exe',
                ];

            let launched = false;
            let lastErr: string | undefined;
            for (const candidate of candidates) {
                try {
                    const child = cp.spawn(candidate, [filePath], {
                        detached: true,
                        stdio: 'ignore',
                        windowsHide: true,
                    });
                    child.unref();
                    launched = true;
                    outputChannel.appendLine(`[Wireshark] Opened ${filePath} using ${candidate}`);
                    break;
                } catch (e) {
                    lastErr = String(e);
                }
            }

            if (!launched) {
                vscode.window.showErrorMessage(`Could not launch Wireshark. Set nettrace.wiresharkPath in settings. ${lastErr ? `(${lastErr})` : ''}`);
            }
        })
    );

    // Reload Configuration
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.reloadConfig', async () => {
            await configLoader.loadAll();
            scenarioDetailsTree.refresh();
            agentsTree.refresh();
            vscode.window.showInformationMessage('NetTrace configuration reloaded.');
        })
    );

    // Show Log command — for easy access to the output panel
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.showLog', () => {
            outputChannel.show();
        })
    );

    // Show Storage Location — reveals where NetTrace data files are stored
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.showStoragePath', () => {
            const customPath = vscode.workspace.getConfiguration('nettrace').get<string>('storagePath', '').trim();
            const storagePath = customPath || context.globalStorageUri.fsPath;
            const storageUri = vscode.Uri.file(storagePath);

            const isCustom = !!customPath;
            const label = isCustom ? 'custom path (nettrace.storagePath setting)' : 'default global storage';
            outputChannel.appendLine(`[Storage] NetTrace data location (${label}): ${storagePath}`);

            vscode.window.showInformationMessage(
                `NetTrace data is stored at:\n${storagePath}`,
                'Reveal in Explorer',
                'Copy Path'
            ).then(action => {
                if (action === 'Reveal in Explorer') {
                    vscode.commands.executeCommand('revealFileInOS', storageUri);
                } else if (action === 'Copy Path') {
                    vscode.env.clipboard.writeText(storagePath);
                    vscode.window.showInformationMessage('Path copied to clipboard.');
                }
            });
        })
    );

    commandCount = 21; // approximate count from all the registrations above
    logger.endStep('Command Registration', true, `${commandCount} commands registered`);
    } catch (e) {
        logger.endStep('Command Registration', false, String(e));
        logger.error('Activation', 'Failed during command registration', e);
    }

    // ─── Auto-Discover Captures in Workspace ──────────────────────────────

    logger.startStep('Load Configuration');
    try {
        await configLoader.loadAll();
        logger.endStep('Load Configuration', true);
    } catch (e) {
        logger.endStep('Load Configuration', false, String(e));
        logger.error('ConfigLoader', 'Config load failed (non-fatal) — using defaults', e);
    }

    logger.startStep('Restore Persisted Captures');
    try {
        const restoredCount = await capturesTree.restorePersistedCaptures();
        logger.endStep('Restore Persisted Captures', true, `${restoredCount} capture(s) restored from previous session`);
    } catch (e) {
        logger.endStep('Restore Persisted Captures', false, String(e));
        logger.error('Activation', 'Failed to restore persisted captures (non-fatal)', e);
    }

    logger.startStep('Discover Captures');
    try {
        await discoverCaptures(tsharkRunner, capturesTree, streamsTree);
        const count = capturesTree.getCaptures().length;
        logger.endStep('Discover Captures', true, `${count} capture file(s) total (persisted + workspace)`);
        logger.logCaptureSummary(count, tsharkRunner.isAvailable());
    } catch (e) {
        logger.endStep('Discover Captures', false, String(e));
        logger.error('Activation', 'Capture discovery failed (non-fatal)', e);
    }

    // Watch for new pcap files
    logger.startStep('File Watchers');
    try {
        const pcapWatcher = vscode.workspace.createFileSystemWatcher('**/*.{pcap,pcapng,cap,pcpap}');
        pcapWatcher.onDidCreate(async (uri) => {
            logger.info('FileWatcher', `New capture file detected: ${uri.fsPath}`);

            // Ignore live capture output files while they are still being written.
            // They are parsed by the Live Capture panel itself after capture completes.
            const normalized = uri.fsPath.replace(/\\/g, '/').toLowerCase();
            if (normalized.includes('/.nettrace/captures/live/')) {
                logger.debug('FileWatcher', `Skipping auto-parse for live capture output: ${uri.fsPath}`);
                return;
            }

            const autoParse = vscode.workspace.getConfiguration('nettrace').get<boolean>('autoParseOnAdd', true);
            if (autoParse) {
                await addAndParseCapture(uri.fsPath, tsharkRunner, capturesTree, streamsTree);
            }
        });
        context.subscriptions.push(pcapWatcher);
        logger.endStep('File Watchers', true);
    } catch (e) {
        logger.endStep('File Watchers', false, String(e));
        logger.error('Activation', 'Could not set up file watchers (non-fatal)', e);
    }

    // ─── React to nettrace.storagePath setting changes ────────────────────

    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration(async (e) => {
            if (!e.affectsConfiguration('nettrace.storagePath')) { return; }
            logger.info('Config', 'nettrace.storagePath changed — re-resolving storage');
            try {
                const customPath = vscode.workspace.getConfiguration('nettrace').get<string>('storagePath', '');
                const ok = await validateCustomStoragePath(customPath, outputChannel);
                if (!ok) { return; } // user cancelled or reset
                const newRoot = getNetTraceRootUri(context);
                await vscode.workspace.fs.createDirectory(newRoot);
                await ensureDefaultFiles(newRoot, context.extensionUri, outputChannel);
                rootUri = newRoot;
                configLoader.setRootUri(rootUri);
                knowledgeTree.setRootUri(rootUri);
                await configLoader.loadAll();
                knowledgeTree.refresh();
                agentsTree.refresh();
                scenarioDetailsTree.refresh();
                logger.info('Config', `Storage path updated to: ${rootUri.fsPath}`);
                vscode.window.showInformationMessage(`NetTrace storage moved to: ${rootUri.fsPath}`);
            } catch (err) {
                logger.error('Config', 'Failed to apply new storagePath', err);
                vscode.window.showErrorMessage('Failed to apply new storage path. Check Output > NetTrace for details.');
            }
        })
    );

    // ─── Activation Complete ──────────────────────────────────────────────

    const activationTime = Date.now() - activationStart;
    logger.divider('Activation Complete');
    logger.info('Activation', `Extension activated in ${activationTime}ms`);
    logger.info('Activation', `Summary: tshark=${tsharkRunner.isAvailable() ? 'yes' : 'NO'}, chatAPI=${deps.chatApi ? 'yes' : 'NO'}, lmAPI=${deps.lmApi ? 'yes' : 'NO'}, captures=${capturesTree.getCaptures().length}`);

    if (!deps.copilotChat) {
        // This shouldn't normally happen since github.copilot-chat is a hard extensionDependency,
        // but log it for diagnostics if somehow activation proceeded without it.
        logger.warn('Activation', 'GitHub Copilot Chat not detected — AI features may be unavailable.');
    }

    // Auto-show the output channel on first activation if there were issues
    if (!deps.chatApi || !deps.lmApi || !tsharkRunner.isAvailable()) {
        logger.warn('Activation', 'Issues detected during activation — showing output panel for diagnostics');
        outputChannel.show(true); // true = preserve focus
    }
}

// ─── Helper Functions ─────────────────────────────────────────────────────

async function discoverCaptures(
    tsharkRunner: TsharkRunner,
    capturesTree: CapturesTreeProvider,
    streamsTree: StreamsTreeProvider
): Promise<void> {
    const log = Logger.get();
    log.debug('Discovery', 'Scanning workspace for capture files...');
    const files = await vscode.workspace.findFiles('**/*.{pcap,pcapng,cap,pcpap}', '**/node_modules/**');
    log.debug('Discovery', `Found ${files.length} capture file(s) via glob`);

    // Build set of already-known paths (from persisted captures) to avoid duplicates
    const knownPaths = new Set(capturesTree.getCaptures().map(c => c.filePath));

    let newCount = 0;
    for (const fileUri of files) {
        if (knownPaths.has(fileUri.fsPath)) {
            log.debug('Discovery', `Already tracked (persisted): ${path.basename(fileUri.fsPath)}`);
            continue;
        }
        try {
            const stat = await vscode.workspace.fs.stat(fileUri);
            const capture: CaptureFile = {
                filePath: fileUri.fsPath,
                name: path.basename(fileUri.fsPath),
                sizeBytes: stat.size,
                parsed: false,
            };

            // Detect role from folder name
            const parentDir = path.basename(path.dirname(fileUri.fsPath)).toLowerCase();
            if (parentDir === 'client') { capture.role = 'client'; }
            else if (parentDir === 'server') { capture.role = 'server'; }

            capturesTree.addCapture(capture);
            newCount++;
            log.debug('Discovery', `Tracked: ${capture.name} (${(stat.size / 1024).toFixed(0)} KB${capture.role ? ', role=' + capture.role : ''})`);
        } catch (e) {
            log.warn('Discovery', `Could not stat file ${fileUri.fsPath}: ${e}`);
        }
    }

    if (newCount > 0) { log.debug('Discovery', `Added ${newCount} new capture(s) from workspace`); }
    capturesTree.refresh();
}

async function addAndParseCapture(
    filePath: string,
    tsharkRunner: TsharkRunner,
    capturesTree: CapturesTreeProvider,
    streamsTree: StreamsTreeProvider
): Promise<void> {
    const log = Logger.get();
    log.info('Parse', `addAndParseCapture: ${path.basename(filePath)}`);

    // Check if already tracked
    const existing = capturesTree.getCaptures().find(c => c.filePath === filePath);
    if (existing && existing.parsed) {
        log.debug('Parse', `Already parsed: ${path.basename(filePath)} — skipping`);
        return;
    }

    let stat: vscode.FileStat;
    try {
        stat = await vscode.workspace.fs.stat(vscode.Uri.file(filePath));
    } catch (e) {
        log.warn('Parse', `Cannot stat file ${filePath}: ${e}`);
        return;
    }

    const capture: CaptureFile = existing || {
        filePath,
        name: path.basename(filePath),
        sizeBytes: stat.size,
        parsed: false,
    };

    // Detect role from folder name
    const parentDir = path.basename(path.dirname(filePath)).toLowerCase();
    if (parentDir === 'client') { capture.role = 'client'; }
    else if (parentDir === 'server') { capture.role = 'server'; }

    if (!existing) {
        capturesTree.addCapture(capture);
    }

    if (!tsharkRunner.isAvailable()) {
        vscode.window.showWarningMessage('tshark not available. Install Wireshark to parse captures.');
        return;
    }

    // Parse with progress
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: `Parsing ${capture.name}...`,
        cancellable: false,
    }, async (progress) => {
        try {
            progress.report({ message: 'Reading capture summary...' });
            capture.summary = await tsharkRunner.getCaptureSummary(filePath);
            capture.parsed = true;
            capturesTree.refresh();

            progress.report({ message: 'Extracting conversations...' });
            const streams = await tsharkRunner.getConversations(filePath);

            // Merge with existing streams
            const existingStreams = streamsTree.getStreams().filter(s => s.captureFile !== filePath);
            streamsTree.setStreams([...existingStreams, ...streams]);

            if (capture.summary) {
                vscode.window.showInformationMessage(
                    `${capture.name}: ${capture.summary.packetCount} packets, ${capture.summary.tcpStreamCount} TCP streams, ${capture.summary.durationSeconds.toFixed(1)}s`
                );
            }
        } catch (e) {
            vscode.window.showErrorMessage(`Failed to parse ${capture.name}: ${e}`);
        }
    });
}

function setCaptureRole(filePath: string, role: 'client' | 'server', capturesTree: CapturesTreeProvider): void {
    const captures = capturesTree.getCaptures();
    // Clear existing role assignment for this role
    for (const c of captures) {
        if (c.role === role) { c.role = undefined; }
    }
    // Set new role
    const target = captures.find(c => c.filePath === filePath);
    if (target) {
        target.role = role;
        capturesTree.refresh();
        vscode.window.showInformationMessage(`${target.name} set as ${role} capture.`);
    }
}

function getNestedValue(obj: any, key: string): any {
    const keyMap: Record<string, string[]> = {
        'scenarioId': ['scenarioId'],
        'summary': ['summary'],
        'symptom': ['symptom'],
        'clientIP': ['topology', 'clientIP'],
        'serverIP': ['topology', 'serverIP'],
        'topology': ['topology', 'description'],
        'notes': ['notes'],
    };
    const path = keyMap[key] || [key];
    let current = obj;
    for (const k of path) {
        if (current === undefined || current === null) { return undefined; }
        current = current[k];
    }
    return current;
}

function setNestedValue(obj: any, key: string, value: any): void {
    const keyMap: Record<string, string[]> = {
        'scenarioId': ['scenarioId'],
        'summary': ['summary'],
        'symptom': ['symptom'],
        'clientIP': ['topology', 'clientIP'],
        'serverIP': ['topology', 'serverIP'],
        'topology': ['topology', 'description'],
        'notes': ['notes'],
    };
    const pathKeys = keyMap[key] || [key];
    let current = obj;
    for (let i = 0; i < pathKeys.length - 1; i++) {
        if (!current[pathKeys[i]]) { current[pathKeys[i]] = {}; }
        current = current[pathKeys[i]];
    }
    current[pathKeys[pathKeys.length - 1]] = value;
}

export async function deactivate() {
    try {
        const log = Logger.get();
        log.info('Activation', 'Extension deactivating...');

        // Detect uninstall: check if this extension is marked in VS Code's .obsolete file.
        // VS Code writes the extension folder name into .obsolete when the user uninstalls,
        // then defers the actual folder deletion until all Code processes exit.
        // We clean up global storage here so data is removed immediately on uninstall.
        if (extensionContext && isMarkedForUninstall(extensionContext)) {
            log.info('Activation', 'Uninstall detected — cleaning up global storage...');
            await cleanupGlobalStorage(extensionContext, outputChannel);

            // If the user had a custom storagePath, we cannot safely delete it (it may contain
            // other data), but we inform them so they can clean it up manually.
            const customPath = vscode.workspace.getConfiguration('nettrace').get<string>('storagePath', '').trim();
            if (customPath) {
                vscode.window.showInformationMessage(
                    `NetTrace uninstalled. Your custom data folder was not deleted automatically:\n${customPath}\n\nYou can remove it manually if no longer needed.`,
                    'Reveal in Explorer'
                ).then(action => {
                    if (action === 'Reveal in Explorer') {
                        vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(customPath));
                    }
                });
            }
        }

        // Stop any live packet captures so tshark processes don't outlive VS Code.
        try {
            activeTsharkRunner?.stopAllLiveCaptures();
        } catch { /* ignore */ }

        log.divider('NetTrace Deactivated');
    } catch {
        // Logger may not be initialized if activation failed early
        outputChannel?.appendLine('Network Capture AI Diagnosis extension deactivated.');
    }
}

/**
 * Checks VS Code's .obsolete marker file to determine if this extension
 * has been queued for uninstall. The .obsolete file lives in the same
 * directory as the extension folder and contains a JSON object mapping
 * extension folder names to `true`.
 */
function isMarkedForUninstall(context: vscode.ExtensionContext): boolean {
    try {
        const extFolderName = path.basename(context.extensionUri.fsPath);
        const extensionsDir = path.dirname(context.extensionUri.fsPath);
        const obsoleteFile = path.join(extensionsDir, '.obsolete');

        if (!fs.existsSync(obsoleteFile)) {
            return false;
        }

        const content = fs.readFileSync(obsoleteFile, 'utf8');
        const obsolete: Record<string, boolean> = JSON.parse(content);
        return obsolete[extFolderName] === true;
    } catch {
        return false;
    }
}

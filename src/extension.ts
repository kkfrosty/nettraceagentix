import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
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
import { CaptureFile } from './types';

let outputChannel: vscode.OutputChannel;

export async function activate(context: vscode.ExtensionContext) {
    console.log('[NetTrace] Extension activate() called');
    outputChannel = vscode.window.createOutputChannel('NetTrace', { log: true });
    outputChannel.appendLine('Network Capture AI Diagnosis extension activating...');

    // ─── Core Services ────────────────────────────────────────────────────

    const tsharkRunner = new TsharkRunner(outputChannel);
    const configLoader = new ConfigLoader(outputChannel);
    const workspaceInitializer = new WorkspaceInitializer(outputChannel);

    // Detect tshark (non-blocking — don't await the user prompt)
    const tsharkPath = await tsharkRunner.detectTshark();
    if (tsharkPath) {
        outputChannel.appendLine(`tshark found at: ${tsharkPath}`);
    } else {
        outputChannel.appendLine('tshark NOT found.');
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

    console.log('[NetTrace] Core services initialized, registering tree views...');

    // ─── TreeView Providers ───────────────────────────────────────────────

    const capturesTree = new CapturesTreeProvider();
    const streamsTree = new StreamsTreeProvider(); // Internal data store — not shown in sidebar
    const scenarioDetailsTree = new ScenarioDetailsTreeProvider(configLoader);
    const agentsTree = new AgentsTreeProvider(configLoader);
    const knowledgeTree = new KnowledgeTreeProvider();

    context.subscriptions.push(
        vscode.window.registerTreeDataProvider('nettrace.captures', capturesTree),
        vscode.window.registerTreeDataProvider('nettrace.agents', agentsTree),
        vscode.window.registerTreeDataProvider('nettrace.knowledge', knowledgeTree),
        vscode.window.registerTreeDataProvider('nettrace.scenarioDetails', scenarioDetailsTree),
    );

    // Refresh knowledge tree when knowledge files change
    configLoader.onKnowledgeChanged(() => knowledgeTree.refresh());

    // ─── Context Assembler ────────────────────────────────────────────────

    const contextAssembler = new ContextAssembler(tsharkRunner, configLoader, outputChannel);

    // ─── Chat Participant ─────────────────────────────────────────────────

    const participant = new NetTraceParticipant(
        context, tsharkRunner, configLoader, contextAssembler,
        capturesTree, agentsTree, streamsTree, outputChannel
    );

    // ─── Custom Editor for pcap/pcapng/cap files ──────────────────────────

    context.subscriptions.push(
        CaptureEditorProvider.register(context, tsharkRunner, capturesTree, streamsTree, outputChannel)
    );

    // ─── Language Model Tools ─────────────────────────────────────────────

    try {
        registerLMTools(context, tsharkRunner, capturesTree, configLoader, outputChannel);
        console.log('[NetTrace] LM tools registered');
    } catch (e) {
        console.error('[NetTrace] Failed to register LM tools:', e);
    }

    // ─── Commands ─────────────────────────────────────────────────────────

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
                    'Capture Files': ['pcap', 'pcapng', 'cap'],
                    'All Files': ['*'],
                },
                title: 'Import Capture File',
            });

            if (!files || files.length === 0) { return; }

            const folders = vscode.workspace.workspaceFolders;
            if (!folders) {
                vscode.window.showErrorMessage('Open a folder first.');
                return;
            }

            for (const fileUri of files) {
                const fileName = path.basename(fileUri.fsPath);
                const destUri = vscode.Uri.joinPath(folders[0].uri, 'captures', fileName);

                // Copy file to workspace captures/ folder
                try {
                    await vscode.workspace.fs.createDirectory(vscode.Uri.joinPath(folders[0].uri, 'captures'));
                    await vscode.workspace.fs.copy(fileUri, destUri, { overwrite: false });
                    outputChannel.appendLine(`Imported: ${fileName}`);
                } catch {
                    // File may already be in the workspace — use it in place
                    outputChannel.appendLine(`Using in place: ${fileUri.fsPath}`);
                }

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
            const folders = vscode.workspace.workspaceFolders;
            if (!folders) {
                vscode.window.showErrorMessage('Open a workspace folder first.');
                return;
            }

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
            const agentsDir = vscode.Uri.joinPath(folders[0].uri, '.nettrace', 'agents');
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

            const folders = vscode.workspace.workspaceFolders;
            if (!folders) { return; }

            const agentsDir = vscode.Uri.joinPath(folders[0].uri, '.nettrace', 'agents');
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

            const folders = vscode.workspace.workspaceFolders;
            if (!folders) { return; }

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

            const agentsDir = vscode.Uri.joinPath(folders[0].uri, '.nettrace', 'agents');
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

            const folders = vscode.workspace.workspaceFolders;
            if (!folders) { return; }

            const agentUri = vscode.Uri.joinPath(folders[0].uri, '.nettrace', 'agents', `${agent.name}.json`);
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

    // Create Knowledge — create a new .md file in a knowledge category
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.createKnowledge', async () => {
            const folders = vscode.workspace.workspaceFolders;
            if (!folders) {
                vscode.window.showErrorMessage('Open a workspace folder first.');
                return;
            }

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

            const categoryDir = vscode.Uri.joinPath(folders[0].uri, '.nettrace', 'knowledge', (category as any).value);
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

    // Open in Wireshark
    context.subscriptions.push(
        vscode.commands.registerCommand('nettrace.openInWireshark', async (item: any) => {
            const filePath = item?.capture?.filePath || item?.resourceUri?.fsPath;
            if (!filePath) { return; }

            const wiresharkPath = vscode.workspace.getConfiguration('nettrace').get<string>('wiresharkPath') || 'wireshark';
            const terminal = vscode.window.createTerminal({ name: 'Wireshark', hideFromUser: true });
            terminal.sendText(`"${wiresharkPath}" "${filePath}"`);
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

    // ─── Auto-Discover Captures in Workspace ──────────────────────────────

    try {
        await configLoader.loadAll();
        console.log('[NetTrace] Config loaded');
    } catch (e) {
        console.error('[NetTrace] Config load failed (non-fatal):', e);
    }

    try {
        await discoverCaptures(tsharkRunner, capturesTree, streamsTree);
        console.log('[NetTrace] Capture discovery done');
    } catch (e) {
        console.error('[NetTrace] Capture discovery failed (non-fatal):', e);
    }

    // Watch for new pcap files
    const pcapWatcher = vscode.workspace.createFileSystemWatcher('**/*.{pcap,pcapng,cap}');
    pcapWatcher.onDidCreate(async (uri) => {
        const autoParse = vscode.workspace.getConfiguration('nettrace').get<boolean>('autoParseOnAdd', true);
        if (autoParse) {
            await addAndParseCapture(uri.fsPath, tsharkRunner, capturesTree, streamsTree);
        }
    });
    context.subscriptions.push(pcapWatcher);

    // ─── Check if workspace needs initialization ──────────────────────────

    if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
        const initialized = await workspaceInitializer.isInitialized();
        if (!initialized) {
            // Check if there are pcap files — if so, prompt to initialize
            const hasCaptures = capturesTree.getCaptures().length > 0;
            if (hasCaptures) {
                workspaceInitializer.promptInitialize();
            }
        }
    }

    outputChannel.appendLine('Network Capture AI Diagnosis extension activated.');
}

// ─── Helper Functions ─────────────────────────────────────────────────────

async function discoverCaptures(
    tsharkRunner: TsharkRunner,
    capturesTree: CapturesTreeProvider,
    streamsTree: StreamsTreeProvider
): Promise<void> {
    const files = await vscode.workspace.findFiles('**/*.{pcap,pcapng,cap}', '**/node_modules/**');

    for (const fileUri of files) {
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
    }

    // Auto-parse if tshark is available — do NOT parse all on startup,
    // just discover files. Parse on-demand when user opens a capture.
    // This prevents 75+ tshark processes blocking activation with many captures.
    capturesTree.refresh();
}

async function addAndParseCapture(
    filePath: string,
    tsharkRunner: TsharkRunner,
    capturesTree: CapturesTreeProvider,
    streamsTree: StreamsTreeProvider
): Promise<void> {
    // Check if already tracked
    const existing = capturesTree.getCaptures().find(c => c.filePath === filePath);
    if (existing && existing.parsed) { return; }

    let stat: vscode.FileStat;
    try {
        stat = await vscode.workspace.fs.stat(vscode.Uri.file(filePath));
    } catch {
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

export function deactivate() {
    outputChannel?.appendLine('Network Capture AI Diagnosis extension deactivated.');
}

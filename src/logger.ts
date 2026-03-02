import * as vscode from 'vscode';

/**
 * Structured logger for NetTrace extension.
 * Writes to both the OutputChannel (visible in "Output" panel) and console (visible in Debug Console).
 * Provides leveled logging with timestamps, categories, and duration tracking for activation steps.
 */

export enum LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
}

export class Logger {
    private static instance: Logger | undefined;
    private outputChannel: vscode.OutputChannel;
    private level: LogLevel = LogLevel.DEBUG;
    private activationTimers: Map<string, number> = new Map();

    private constructor(outputChannel: vscode.OutputChannel) {
        this.outputChannel = outputChannel;
    }

    /**
     * Initialize the singleton logger. Call once during activation.
     */
    static init(outputChannel: vscode.OutputChannel): Logger {
        Logger.instance = new Logger(outputChannel);
        return Logger.instance;
    }

    /**
     * Get the singleton instance. Throws if not initialized.
     */
    static get(): Logger {
        if (!Logger.instance) {
            throw new Error('Logger not initialized. Call Logger.init() first.');
        }
        return Logger.instance;
    }

    setLevel(level: LogLevel): void {
        this.level = level;
    }

    // ─── Core Logging Methods ─────────────────────────────────────────────

    debug(category: string, message: string, ...args: any[]): void {
        if (this.level > LogLevel.DEBUG) { return; }
        this.write('DEBUG', category, message, args);
    }

    info(category: string, message: string, ...args: any[]): void {
        if (this.level > LogLevel.INFO) { return; }
        this.write('INFO', category, message, args);
    }

    warn(category: string, message: string, ...args: any[]): void {
        if (this.level > LogLevel.WARN) { return; }
        this.write('WARN', category, message, args);
    }

    error(category: string, message: string, error?: unknown): void {
        const errMsg = error instanceof Error
            ? `${error.message}\n  Stack: ${error.stack}`
            : error !== undefined ? String(error) : '';
        this.write('ERROR', category, message, errMsg ? [errMsg] : []);
    }

    // ─── Activation Step Tracking ─────────────────────────────────────────

    /**
     * Start timing an activation step.
     */
    startStep(stepName: string): void {
        this.activationTimers.set(stepName, Date.now());
        this.info('Activation', `▶ ${stepName}...`);
    }

    /**
     * Mark an activation step as complete.
     */
    endStep(stepName: string, success: boolean = true, detail?: string): void {
        const start = this.activationTimers.get(stepName);
        const duration = start ? `${Date.now() - start}ms` : '?ms';
        this.activationTimers.delete(stepName);

        const icon = success ? '✓' : '✗';
        const status = success ? 'OK' : 'FAILED';
        const detailStr = detail ? ` — ${detail}` : '';
        this.info('Activation', `${icon} ${stepName} [${status}, ${duration}]${detailStr}`);
    }

    // ─── Environment Diagnostics ──────────────────────────────────────────

    /**
     * Log comprehensive environment info to help diagnose loading issues.
     */
    logEnvironment(): void {
        this.info('Environment', '─── Environment Diagnostics ───');
        this.info('Environment', `VS Code version: ${vscode.version}`);
        this.info('Environment', `Node version: ${process.version}`);
        this.info('Environment', `Platform: ${process.platform} (${process.arch})`);
        this.info('Environment', `PID: ${process.pid}`);

        // Workspace info
        const folders = vscode.workspace.workspaceFolders;
        if (folders && folders.length > 0) {
            this.info('Environment', `Workspace folders: ${folders.map(f => f.uri.fsPath).join(', ')}`);
        } else {
            this.warn('Environment', 'No workspace folder open');
        }
    }

    /**
     * Check required and optional dependencies and log their status.
     */
    async logDependencies(): Promise<{ copilotChat: boolean; chatApi: boolean; lmApi: boolean }> {
        this.info('Dependencies', '─── Dependency Check ───');

        // Check Copilot Chat extension (our hard dependency)
        const copilotChat = vscode.extensions.getExtension('github.copilot-chat');
        const copilotChatInstalled = copilotChat !== undefined;
        const copilotChatActive = copilotChat?.isActive ?? false;
        if (copilotChatInstalled) {
            this.info('Dependencies', `github.copilot-chat: installed (active=${copilotChatActive}, version=${copilotChat?.packageJSON?.version ?? 'unknown'})`);
        } else {
            this.error('Dependencies', 'github.copilot-chat: NOT INSTALLED — chat participant and LM tools will not work');
        }

        // Check VS Code API availability
        const chatApiAvailable = typeof vscode.chat?.createChatParticipant === 'function';
        const lmApiAvailable = typeof vscode.lm?.registerTool === 'function';

        this.info('Dependencies', `vscode.chat API: ${chatApiAvailable ? 'available' : 'NOT AVAILABLE'}`);
        this.info('Dependencies', `vscode.lm API: ${lmApiAvailable ? 'available' : 'NOT AVAILABLE'}`);

        if (!chatApiAvailable) {
            this.error('Dependencies', 'vscode.chat.createChatParticipant is not available — VS Code may be too old or Copilot Chat is not active');
        }
        if (!lmApiAvailable) {
            this.error('Dependencies', 'vscode.lm.registerTool is not available — VS Code may be too old or Copilot Chat is not active');
        }

        return {
            copilotChat: copilotChatInstalled,
            chatApi: chatApiAvailable,
            lmApi: lmApiAvailable,
        };
    }

    /**
     * Log a summary of all pcap files found in the workspace.
     */
    logCaptureSummary(captureCount: number, tsharkAvailable: boolean): void {
        this.info('Captures', `Found ${captureCount} capture file(s) in workspace`);
        this.info('Captures', `tshark available: ${tsharkAvailable}`);
    }

    /**
     * Scan all installed extensions and log their status.
     * Helps diagnose when other extensions are failing/conflicting on a new machine.
     */
    logExtensionEnvironment(): void {
        this.info('Extensions', '─── Installed Extensions Scan ───');

        const all = vscode.extensions.all;
        const nonBuiltin = all.filter(ext => !ext.id.startsWith('vscode.') && !ext.id.startsWith('ms-vscode.'));

        let activeCount = 0;
        let inactiveCount = 0;
        const failed: string[] = [];

        // Known extensions that can produce noisy errors
        const knownNoisy: Record<string, string> = {
            'ms-edgedevtools.vscode-edge-devtools': 'May log "Failed to load message bundle" — harmless, Edge DevTools i18n issue',
            'continue.continue': 'May fail to register YAML schema if RedHat YAML extension is not installed',
            'cweijan.vscode-postgresql-client2': 'May fail with "View provider already registered" if duplicate DB extensions exist',
            'cweijan.dbclient-jdbc': 'May conflict with vscode-postgresql-client2',
            'cweijan.vscode-mysql-client2': 'May conflict with vscode-postgresql-client2',
        };

        for (const ext of nonBuiltin) {
            if (ext.isActive) {
                activeCount++;
            } else {
                inactiveCount++;
            }

            // Log known noisy extensions with explanation
            if (knownNoisy[ext.id]) {
                const status = ext.isActive ? 'active' : 'INACTIVE';
                this.info('Extensions', `  ⚠ ${ext.id} v${ext.packageJSON?.version ?? '?'} [${status}] — ${knownNoisy[ext.id]}`);
            }
        }

        this.info('Extensions', `Total: ${nonBuiltin.length} extensions (${activeCount} active, ${inactiveCount} inactive/not-yet-activated)`);

        // Check for duplicate database extensions (common conflict source)
        const dbExtensions = nonBuiltin.filter(ext =>
            ext.id.includes('dbclient') || ext.id.includes('database') ||
            ext.id.includes('mysql-client') || ext.id.includes('postgresql-client')
        );
        if (dbExtensions.length > 1) {
            this.warn('Extensions', `Multiple database extensions detected (${dbExtensions.map(e => e.id).join(', ')}). These often conflict — consider keeping only one.`);
        }

        // Log any extensions that appear problematic for our use case
        this.info('Extensions', 'Note: Errors from OTHER extensions (Edge DevTools, Continue, Database Client, etc.) in the Debug Console are NOT from NetTrace. Look for lines prefixed with [NetTrace] for our logs.');
    }

    /**
     * Log a divider for readability.
     */
    divider(label?: string): void {
        if (label) {
            this.outputChannel.appendLine(`\n${'═'.repeat(20)} ${label} ${'═'.repeat(20)}`);
        } else {
            this.outputChannel.appendLine('═'.repeat(60));
        }
    }

    // ─── Internal ─────────────────────────────────────────────────────────

    private write(level: string, category: string, message: string, args: any[]): void {
        const timestamp = new Date().toISOString().substring(11, 23); // HH:mm:ss.sss
        const extra = args.length > 0 ? ' ' + args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' ') : '';
        const line = `[${timestamp}] [${level.padEnd(5)}] [${category}] ${message}${extra}`;

        this.outputChannel.appendLine(line);

        // Also log to Debug Console for visibility during development
        switch (level) {
            case 'ERROR':
                console.error(`[NetTrace] ${line}`);
                break;
            case 'WARN':
                console.warn(`[NetTrace] ${line}`);
                break;
            default:
                console.log(`[NetTrace] ${line}`);
                break;
        }
    }
}

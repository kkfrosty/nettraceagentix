import * as vscode from 'vscode';

/**
 * Manages the NetTrace storage location — where .nettrace/ config, agents,
 * knowledge, and filters are stored.
 *
 * Default: VS Code's globalStorageUri. Location on disk:
 *   Windows: %APPDATA%\Code\User\globalStorage\cognitiveagentics-krisfrost.nettrace-agentix\
 *   macOS:   ~/Library/Application Support/Code/User/globalStorage/cognitiveagentics-krisfrost.nettrace-agentix/
 *   Linux:   ~/.config/Code/User/globalStorage/cognitiveagentics-krisfrost.nettrace-agentix/
 *
 * Note: VS Code marks this folder for cleanup via .obsolete when the extension is uninstalled,
 * but deletion is deferred until all VS Code processes exit. The extension handles cleanup
 * proactively in deactivate() when an uninstall is detected.
 *
 * Override: User sets `nettrace.storagePath` setting to a custom folder.
 */

/**
 * Resolve the root URI where .nettrace/ data should be stored.
 *
 * Priority:
 * 1. `nettrace.storagePath` setting (if non-empty and valid)
 * 2. `context.globalStorageUri` (always available, managed by VS Code)
 */
export function getNetTraceRootUri(context: vscode.ExtensionContext): vscode.Uri {
    const customPath = vscode.workspace.getConfiguration('nettrace').get<string>('storagePath', '').trim();

    if (customPath) {
        return vscode.Uri.file(customPath);
    }

    return context.globalStorageUri;
}

/**
 * Files that must exist in the .nettrace/ structure.
 * Relative to the rootUri. Used for integrity checks and first-run provisioning.
 */
const REQUIRED_FILES = [
    '.nettrace/config.json',
    '.nettrace/scenario.json',
    '.nettrace/agents/general.json',
    '.nettrace/filters/exclude-noise.json',
    '.nettrace/knowledge/README.md',
    '.nettrace/knowledge/wisdom/analysis-false-positives.md',
    '.nettrace/knowledge/security/security-heuristics.md',
    '.nettrace/knowledge/known-issues/windows-tcp.md',
    '.nettrace/knowledge/known-issues/firewall-appliance-quirks.md',
];

/**
 * Directories that must exist (created even if empty).
 */
const REQUIRED_DIRS = [
    '.nettrace',
    '.nettrace/agents',
    '.nettrace/tools',
    '.nettrace/filters',
    '.nettrace/templates',
    '.nettrace/knowledge',
    '.nettrace/knowledge/wisdom',
    '.nettrace/knowledge/security',
    '.nettrace/knowledge/known-issues',
];

/**
 * Ensure all default files and directories exist at the given rootUri.
 * Copies missing files from the bundled resources/defaults/ folder.
 * NEVER overwrites existing files (preserves user edits).
 *
 * @returns Number of files that were created (0 = everything already existed)
 */
export async function ensureDefaultFiles(
    rootUri: vscode.Uri,
    extensionUri: vscode.Uri,
    outputChannel: vscode.OutputChannel
): Promise<number> {
    let createdCount = 0;

    // 1. Create required directories
    for (const dir of REQUIRED_DIRS) {
        const dirUri = vscode.Uri.joinPath(rootUri, dir);
        try {
            await vscode.workspace.fs.createDirectory(dirUri);
        } catch {
            // Already exists — fine
        }
    }

    // 2. Copy missing files from bundled defaults
    const defaultsUri = vscode.Uri.joinPath(extensionUri, 'resources', 'defaults');

    for (const relativePath of REQUIRED_FILES) {
        const targetUri = vscode.Uri.joinPath(rootUri, relativePath);
        const sourceUri = vscode.Uri.joinPath(defaultsUri, relativePath);

        try {
            // Check if file already exists — don't overwrite
            await vscode.workspace.fs.stat(targetUri);
        } catch {
            // File doesn't exist — copy from defaults
            try {
                await vscode.workspace.fs.copy(sourceUri, targetUri, { overwrite: false });
                outputChannel.appendLine(`[Storage] Created default file: ${relativePath}`);
                createdCount++;
            } catch (e) {
                outputChannel.appendLine(`[Storage] Warning: Could not copy default file ${relativePath}: ${e}`);
            }
        }
    }

    if (createdCount > 0) {
        outputChannel.appendLine(`[Storage] Provisioned ${createdCount} default file(s) at ${rootUri.fsPath}`);
    } else {
        outputChannel.appendLine(`[Storage] All default files present at ${rootUri.fsPath}`);
    }

    return createdCount;
}

/**
 * Validate that the custom storage path exists and is accessible.
 * Shows user-facing error with recovery options if not.
 *
 * @returns true if the path is valid, false if we should fall back to globalStorageUri
 */
export async function validateCustomStoragePath(
    customPath: string,
    outputChannel: vscode.OutputChannel
): Promise<boolean> {
    if (!customPath.trim()) {
        return true; // Empty = use default, always valid
    }

    const uri = vscode.Uri.file(customPath.trim());

    try {
        const stat = await vscode.workspace.fs.stat(uri);
        if (stat.type !== vscode.FileType.Directory) {
            const action = await vscode.window.showErrorMessage(
                `NetTrace storage path is not a folder: ${customPath}`,
                'Reset to Default'
            );
            if (action === 'Reset to Default') {
                await vscode.workspace.getConfiguration('nettrace').update('storagePath', '', vscode.ConfigurationTarget.Global);
            }
            return false;
        }
        return true;
    } catch {
        // Folder doesn't exist — offer to create or reset
        const action = await vscode.window.showErrorMessage(
            `NetTrace storage folder not found: ${customPath}`,
            'Create Folder',
            'Reset to Default'
        );

        if (action === 'Create Folder') {
            try {
                await vscode.workspace.fs.createDirectory(uri);
                outputChannel.appendLine(`[Storage] Created custom storage folder: ${customPath}`);
                return true;
            } catch (e) {
                outputChannel.appendLine(`[Storage] Failed to create folder: ${e}`);
                vscode.window.showErrorMessage(`Could not create folder: ${e}`);
                return false;
            }
        } else if (action === 'Reset to Default') {
            await vscode.workspace.getConfiguration('nettrace').update('storagePath', '', vscode.ConfigurationTarget.Global);
        }

        return false;
    }
}

/**
 * Delete the globalStorageUri folder for this extension.
 * Called during deactivate() when an uninstall is detected.
 *
 * @returns true if cleanup succeeded or folder didn't exist; false on error
 */
export async function cleanupGlobalStorage(
    context: vscode.ExtensionContext,
    outputChannel: vscode.OutputChannel | undefined
): Promise<boolean> {
    try {
        await vscode.workspace.fs.delete(context.globalStorageUri, { recursive: true });
        outputChannel?.appendLine(`[Storage] Cleaned up global storage on uninstall: ${context.globalStorageUri.fsPath}`);
        return true;
    } catch (e: unknown) {
        // If the folder doesn't exist (already cleaned), that's fine
        if (e instanceof vscode.FileSystemError && e.code === 'FileNotFound') {
            outputChannel?.appendLine(`[Storage] Global storage already removed.`);
            return true;
        }
        outputChannel?.appendLine(`[Storage] Warning: Could not clean up global storage: ${e}`);
        return false;
    }
}

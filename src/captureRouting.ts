import { CaptureFile } from './types';
import { CapturesTreeProvider } from './views/capturesTreeProvider';
import { CaptureWebviewPanel } from './views/captureWebviewPanel';
import { LiveCaptureWebviewPanel } from './views/liveCaptureWebviewPanel';

interface RoutingLogger {
    appendLine(message: string): void;
}

export interface OpenCaptureResolution {
    activeCapture?: CaptureFile;
    openCaptures: CaptureFile[];
    rehydrated: boolean;
}

export function resolveOpenCaptures(
    capturesTree: CapturesTreeProvider,
    outputChannel?: RoutingLogger,
    logPrefix: string = 'CaptureRouting'
): OpenCaptureResolution {
    const activeCapture = capturesTree.getActiveCapture();
    if (activeCapture) {
        outputChannel?.appendLine(`[${logPrefix}] Active capture (${activeCapture.openInPanel ?? 'tree'}): ${activeCapture.filePath}`);
        return {
            activeCapture,
            openCaptures: capturesTree.getOpenCaptures(),
            rehydrated: false,
        };
    }

    let openCaptures = capturesTree.getOpenCaptures();
    let rehydrated = false;

    // When multiple viewer panels are open, the tree alone cannot tell which one
    // is active. Ask the panel registry which viewer is visible and sync that back
    // into the tree before we decide the routing is ambiguous.
    const activeViewerPath = CaptureWebviewPanel.getActiveCaptureFile();
    if (activeViewerPath) {
        capturesTree.markOpenInPanel(activeViewerPath, 'viewer');
        const viewerCapture = capturesTree.getCaptures().find(c => c.filePath === activeViewerPath);
        if (viewerCapture) {
            outputChannel?.appendLine(`[${logPrefix}] Active viewer capture: ${activeViewerPath}`);
            return {
                activeCapture: viewerCapture,
                openCaptures: capturesTree.getOpenCaptures(),
                rehydrated: false,
            };
        }
    }

    if (openCaptures.length === 0) {
        const livePath = LiveCaptureWebviewPanel.getActiveCaptureFile();
        if (livePath) {
            capturesTree.markOpenInPanel(livePath, 'live');
            rehydrated = true;
        }

        const viewerPanels = CaptureWebviewPanel.getOpenCapturePanels();
        for (const panel of viewerPanels) {
            capturesTree.markOpenInPanel(panel.filePath, 'viewer');
            rehydrated = true;
        }

        openCaptures = capturesTree.getOpenCaptures();
        if (rehydrated && openCaptures.length > 0) {
            outputChannel?.appendLine(`[${logPrefix}] Rehydrated ${openCaptures.length} open capture(s) from panel registries`);
        }
    }

    return {
        activeCapture: capturesTree.getActiveCapture(),
        openCaptures,
        rehydrated,
    };
}

export function resolveDefaultCaptureFile(
    capturesTree: CapturesTreeProvider,
    outputChannel?: RoutingLogger,
    logPrefix: string = 'CaptureRouting'
): string | undefined {
    const resolution = resolveOpenCaptures(capturesTree, outputChannel, logPrefix);
    if (resolution.activeCapture) {
        return resolution.activeCapture.filePath;
    }

    if (resolution.openCaptures.length > 1) {
        outputChannel?.appendLine(
            `[${logPrefix}] ${resolution.openCaptures.length} captures open but none unambiguous — returning undefined`
        );
        return undefined;
    }

    const captures = capturesTree.getCaptures();
    const clientCapture = captures.find(c => c.role === 'client');
    if (clientCapture) {
        outputChannel?.appendLine(`[${logPrefix}] No active panel — using client-role capture: ${clientCapture.filePath}`);
        return clientCapture.filePath;
    }

    if (captures.length === 1) {
        outputChannel?.appendLine(`[${logPrefix}] Single capture in tree (no panel): ${captures[0].filePath}`);
        return captures[0].filePath;
    }

    outputChannel?.appendLine(`[${logPrefix}] No unambiguous capture file — returning undefined`);
    return undefined;
}

export function applyFilterToActiveCapturePanel(
    filter: string,
    capturesTree: CapturesTreeProvider,
    outputChannel?: RoutingLogger,
    logPrefix: string = 'CaptureRouting'
): boolean {
    const resolution = resolveOpenCaptures(capturesTree, outputChannel, logPrefix);
    const targetCapture = resolution.activeCapture
        ?? (resolution.openCaptures.length === 1 ? resolution.openCaptures[0] : undefined);

    if (!targetCapture?.openInPanel) {
        outputChannel?.appendLine(`[${logPrefix}] No active panel to push filter to`);
        return false;
    }

    if (targetCapture.openInPanel === 'live') {
        const applied = LiveCaptureWebviewPanel.applyFilterToActive(filter);
        outputChannel?.appendLine(`[${logPrefix}] Dispatched filter to live panel → ${applied}`);
        return applied;
    }

    CaptureWebviewPanel.applyFilterToActive(filter);
    outputChannel?.appendLine(`[${logPrefix}] Dispatched filter to viewer panel`);
    return true;
}
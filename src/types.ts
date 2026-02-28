/**
 * Shared types for the Network Capture AI Diagnosis extension.
 */

// ─── Capture & Packet Types ───────────────────────────────────────────────

export interface CaptureFile {
    /** Absolute file path */
    filePath: string;
    /** Display name (filename without path) */
    name: string;
    /** File size in bytes */
    sizeBytes: number;
    /** Whether this file has been parsed */
    parsed: boolean;
    /** Parsed summary (populated after tshark analysis) */
    summary?: CaptureSummary;
    /** Role in client/server comparison */
    role?: 'client' | 'server';
}

export interface CaptureSummary {
    /** Total number of packets */
    packetCount: number;
    /** Capture duration in seconds */
    durationSeconds: number;
    /** Protocol breakdown (protocol name → packet count) */
    protocolBreakdown: Record<string, number>;
    /** Number of TCP streams */
    tcpStreamCount: number;
    /** Number of UDP streams */
    udpStreamCount: number;
    /** Start timestamp */
    startTime: string;
    /** End timestamp */
    endTime: string;
    /** Expert info summary */
    expertInfo?: ExpertInfoSummary;
}

export interface ExpertInfoSummary {
    errors: number;
    warnings: number;
    notes: number;
    chats: number;
    details: ExpertInfoEntry[];
}

export interface ExpertInfoEntry {
    severity: 'error' | 'warning' | 'note' | 'chat';
    group: string;
    message: string;
    packetNumber: number;
    protocol: string;
}

// ─── Stream / Conversation Types ──────────────────────────────────────────

export interface TcpStream {
    /** TCP stream index */
    index: number;
    /** Source IP:port */
    source: string;
    /** Destination IP:port */
    destination: string;
    /** Number of packets in this stream */
    packetCount: number;
    /** Total bytes transferred */
    totalBytes: number;
    /** Duration of the stream in seconds */
    durationSeconds: number;
    /** Detected application protocol (HTTP, TLS, DNS, etc.) */
    appProtocol?: string;
    /** Anomaly flags detected */
    anomalies: StreamAnomaly[];
    /** Anomaly score (higher = more suspicious) */
    anomalyScore: number;
    /** Whether this stream is excluded from analysis */
    excluded: boolean;
    /** Which capture file this stream belongs to */
    captureFile: string;
}

export interface StreamAnomaly {
    type: 'retransmission' | 'rst' | 'zero-window' | 'tls-alert' | 'http-error' | 'timeout' | 'duplicate-ack' | 'out-of-order'
        | 'malformed' | 'fragment' | 'checksum-error' | 'suspicious-flags' | 'icmp-error';
    count: number;
    description: string;
    /** Packet numbers where this anomaly occurs */
    packetNumbers: number[];
}

// ─── Configuration Types ──────────────────────────────────────────────────

export interface NetTraceConfig {
    tsharkPath?: string;
    captureDirectories?: string[];
    outputDirectory?: string;
    defaultAgent?: string;
    defaultFilters?: FilterConfig;
    tokenBudget?: TokenBudgetConfig;
    captureMapping?: CaptureMapping;
}

export interface FilterConfig {
    excludeProtocols?: string[];
    excludeIPs?: string[];
    includeFilter?: string;
    excludeFilter?: string;
    maxPacketsPerStream?: number;
}

export interface TokenBudgetConfig {
    maxInputTokens?: number;
    reserveForResponse?: number;
    summaryBudget?: number;
    perStreamBudget?: number;
}

export interface CaptureMapping {
    mode: 'single' | 'client-server';
    pairs?: CapturePair[];
}

export interface CapturePair {
    client: string;
    server: string;
    clientIP?: string;
    serverIP?: string;
    timeOffset?: string;
}

// ─── Scenario Details ──────────────────────────────────────────────────────

export interface ScenarioDetails {
    scenarioId?: string;
    summary?: string;
    symptom?: string;
    topology?: {
        description?: string;
        clientIP?: string;
        serverIP?: string;
        relevantPorts?: number[];
    };
    capturePoints?: Record<string, string>;
    notes?: string;
}

// ─── Agent Definition ─────────────────────────────────────────────────────

export interface AgentDefinition {
    name: string;
    displayName: string;
    description: string;
    icon?: string;
    systemPrompt: string;
    autoFilters?: {
        displayFilter?: string;
        excludeProtocols?: string[];
        groupBy?: string;
    };
    tools?: string[];
    contextPriority?: {
        prioritySignals?: string[];
        alwaysInclude?: string[];
        maxStreamsToAnalyze?: number;
    };
    followups?: Array<{
        label: string;
        prompt: string;
    }>;
    /** Advisors to exclude from this agent (e.g., ['security'] to skip security heuristics) */
    excludeAdvisors?: string[];
}

// ─── Knowledge Base Types ─────────────────────────────────────────────────

/**
 * A piece of analysis knowledge loaded from .nettrace/knowledge/.
 * Always-loaded wisdom goes in wisdom/, conditionally-loaded security heuristics in security/.
 */
export interface KnowledgeEntry {
    /** Relative path of the source file */
    source: string;
    /** Category: 'wisdom' (always loaded), 'security' (conditional), 'known-issues' (always loaded) */
    category: 'wisdom' | 'security' | 'known-issues';
    /** The markdown content */
    content: string;
}

/**
 * Describes which anomaly types were detected across all captures.
 * Used to decide whether to activate conditional advisors (e.g., security).
 */
export interface CaptureSignals {
    hasMalformedPackets: boolean;
    hasFragments: boolean;
    hasChecksumErrors: boolean;
    hasSuspiciousFlags: boolean;
    hasIcmpErrors: boolean;
    /** Total count of security-relevant anomalies */
    securityAnomalyCount: number;
    /** All distinct anomaly types found */
    anomalyTypes: Set<string>;
}

// ─── Tool Definition ──────────────────────────────────────────────────────

export interface ToolDefinition {
    name: string;
    displayName: string;
    description: string;
    type: 'tshark-filter' | 'tshark-stats' | 'script' | 'composite';
    config: TsharkToolConfig | ScriptToolConfig | CompositeToolConfig;
}

export interface TsharkToolConfig {
    displayFilter?: string;
    fields?: string[];
    statistics?: string;
    outputFormat?: 'table' | 'json' | 'detailed' | 'fields';
    followStream?: boolean;
}

export interface ScriptToolConfig {
    runtime: 'python' | 'node' | 'powershell';
    script: string;
    args?: string[];
    outputFormat?: 'json' | 'text';
}

export interface CompositeToolConfig {
    steps: Array<{
        tool: string;
        inputMapping?: Record<string, string>;
    }>;
}

// ─── Prompt / Context Assembly ────────────────────────────────────────────

export interface AssembledContext {
    /** The system prompt including agent persona */
    systemPrompt: string;
    /** The capture summary section */
    captureSummary: string;
    /** Prioritized stream details */
    streamDetails: string;
    /** Scenario details section */
    scenarioContext: string;
    /** Actual packet data from the capture (first N packets) */
    packetData: string;
    /** Analysis knowledge injected into the prompt */
    knowledgeContext: string;
    /** Total estimated token count */
    estimatedTokens: number;
    /** Coverage info — tells the user what was loaded */
    coverage: {
        mode: 'complete' | 'sampled';
        totalPackets: number;
        packetsIncluded: number;
        uncoveredRanges?: Array<[number, number]>;
    };
}

// ─── TreeView Item Types ──────────────────────────────────────────────────

export type TreeItemType =
    | 'captureFolder'
    | 'captureFile'
    | 'stream'
    | 'agent'
    | 'scenarioField';

# NetTrace AI Analysis Workspace

This is the working workspace for analyzing network captures with the NetTrace AI Diagnosis extension.

## Getting Started

1. **Open this folder in VS Code** — either as the root workspace, or launch via F5 from the extension project
2. **Drop `.pcap`, `.pcapng`, or `.cap` files** into the `captures/` folder
3. **Click a capture** in the NetTrace sidebar to open the viewer
4. **Type `@nettrace what's wrong?`** in Copilot Chat

## Folder Structure

```
NetTraceAIAnalysisWorkspace/
├── captures/           ← Drop your capture files here (gitignored — never committed)
├── .nettrace/          ← Extension configuration (committed)
│   ├── config.json     ← Workspace settings
│   ├── scenario.json   ← Optional: scenario context for targeted diagnosis
│   └── knowledge/      ← Domain knowledge files (.md) injected into AI analysis
└── .gitignore          ← Keeps capture files out of the repo
```

## Important

**Capture files are gitignored** — they may contain customer/sensitive data and must never be committed to the repository. Each user drops in their own captures locally.

The `.nettrace/` configuration IS committed so workspace settings are shared across the team.

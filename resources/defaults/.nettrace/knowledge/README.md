# NetTrace Knowledge Base

This folder contains markdown files that teach the analysis agent about common patterns,
false positives, and known issues. The agent reads these before analyzing your capture.

## Folder Structure

- **wisdom/** — Always loaded. Contains expert knowledge about false positives, capture
  artifacts, and things that look wrong but aren't. Edit these when the agent flags
  something that shouldn't be flagged.

- **security/** — Conditionally loaded. Only injected when the capture contains
  security-relevant anomalies (malformed packets, IP fragments, suspicious TCP flags).
  If your capture is just a client not getting a response, this won't activate.

- **known-issues/** — Always loaded. Vendor-specific bugs, OS behaviors, firewall
  quirks, and other "it's not a bug, it's a feature" situations.

## How to Customize

1. **Agent getting it wrong?** Edit the relevant .md file to add guidance.
2. **New pattern to teach?** Create a new .md file in the appropriate folder.
3. **Changes take effect immediately** — the extension hot-reloads on file save.

## Examples

### Teaching the agent about a specific firewall behavior
Create `known-issues/checkpoint-quirks.md`:
```markdown
# Known Issues — Check Point Firewalls
## SmartDefense TCP Sequence Verification
Check Point's SmartDefense feature verifies TCP sequence numbers and may drop
packets it considers "out of window." This can cause legitimate retransmissions
to be dropped, making packet loss appear worse than it actually is.
```

### Correcting a false positive
Edit `wisdom/analysis-false-positives.md` and add:
```markdown
### Our Load Balancer Sends RST on Health Check Failure
Our F5 sends RST to the server when a health check fails. This looks like
a connection error but is expected behavior. The server IP is 10.0.1.50.
```

# Known Issues — Windows TCP/IP Stack

## Windows TCP RST Behavior
- Windows sends RST (instead of ignoring) when it receives a packet for a connection in TIME_WAIT state. This is RFC-compliant but generates RST traffic that looks suspicious if you're not expecting it.
- After a socket close with pending data, Windows sends RST instead of FIN. This is `SO_LINGER` with timeout=0 behavior. Some applications do this intentionally for fast connection teardown.

## Windows TCP Chimney / Offload Issues (Legacy)
- On older Windows versions (2008 R2, 2012), TCP Chimney Offload could cause packets to disappear from captures (offloaded to NIC, invisible to tcpdump/netmon capture). If you see gaps in sequence numbers with no retransmissions, check if TCP offload was enabled.
- Recommendation: Check `netsh int tcp show global` for offload settings.

## Windows TCP Auto-Tuning
- Windows TCP receive window auto-tuning can cause drastic window size changes that look like misbehavior. The receive window may go from 64KB to 16MB between packets.
- If someone has disabled auto-tuning (`netsh int tcp set global autotuninglevel=disabled`), small receive windows (64KB) with high-bandwidth paths will cause throughput bottlenecks. This is a common misconfiguration, not a protocol error.

## Windows Firewall (WFP) Behaviors
- Windows Filtering Platform may drop packets silently (no RST, no ICMP unreachable). If SYN packets are sent but no SYN-ACK is received AND the server is known to be running, check Windows Firewall rules.
- `netsh wfp show state` can reveal active filters that might be dropping traffic.

## SMB / CIFS Known Behaviors
- SMB multichannel creates multiple TCP connections between the same client and server. This is intentional redundancy, not a connection leak.
- SMB signing adds latency per-packet that can look like server-side processing delay.
- SMB dialect negotiation (2.0.2 → 3.1.1) can result in connection resets during negotiation if the server doesn't support the requested dialect.

## DNS Client Behavior
- Windows DNS client caches negative responses (NXDOMAIN) for the TTL period. Repeated NXDOMAIN in a trace might be from different processes querying the same non-existent name.
- Windows DNS client sends both A and AAAA queries simultaneously. If AAAA fails or times out, this can add latency to resolution but is not an error.

## WinHTTP / WinInet
- WinHTTP has a default connection timeout of 60 seconds and a send/receive timeout of 30 seconds. If you see connections dropping at exactly these intervals, it's client-side timeout, not server issue.
- Connection pooling means TCP connections may persist long after the HTTP request is complete. Idle connections terminated by RST are normal pool cleanup.

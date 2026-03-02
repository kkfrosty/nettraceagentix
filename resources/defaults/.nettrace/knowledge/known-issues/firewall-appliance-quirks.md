# Known Issues — Firewalls & Network Appliances

## General Firewall Behaviors

### Stateful Firewall Connection Timeouts
Most stateful firewalls have connection tracking timeouts:
- **TCP established:** 1 hour (common default, varies by vendor)
- **TCP half-open:** 30-120 seconds
- **UDP:** 30-60 seconds
- **ICMP:** 10-30 seconds

When a tracked connection times out, the next packet in either direction will be:
- Silently dropped (most common)
- RST'd (some firewalls inject RST to both sides)
- Logged as "deny" even though the original session was permitted

**Diagnosis pattern:** Look for an idle gap (no packets for > timeout period) followed by a dropped packet or RST. The idle gap is the clue.

### Asymmetric Routing + Stateful Firewalls
If outbound traffic goes through Firewall A but return traffic comes through Firewall B, Firewall B has no state for the connection and will drop or RST return packets. Symptoms:
- SYN goes out, SYN-ACK never arrives (if firewalls are different)
- Intermittent drops on established connections (if traffic sometimes takes asymmetric path)

### Firewall-Injected RST Identification
When a firewall blocks a connection by injecting RST, you can sometimes identify it:
- The RST packet has a different TTL than other packets from the "source" — the firewall is on a different hop count
- The RST arrives suspiciously fast (< 1ms after the packet it's responding to)
- The RST has no matching SYN or established connection from that endpoint

## Vendor-Specific Known Issues

### Palo Alto
- PAN-OS connection table overflow causes silent drops. Check `show resource-monitor` for connection table utilization.
- SSL decryption can cause TLS errors if the firewall's CA is not trusted by the client. Look for: TLS Alert "unknown CA" after the firewall re-signs the certificate.
- App-ID reclassification can cause a connection to be dropped mid-stream if it was initially allowed as one application but later identified as a different (blocked) application.

### Cisco ASA / Firepower
- ASA default TCP timeout is 1 hour. Half-closed timeout is 10 minutes.
- ASA silently drops packets that don't match any ACL (implicit deny) — no RST, no ICMP. Just vanishes.
- Firepower IPS inspection can add 1-5ms per packet for complex rule sets. This shows up as consistent added latency on first packet of a flow.
- TCP normalization on ASA can strip TCP options the server was expecting, causing performance degradation (e.g., stripping TCP timestamps, window scaling).

### Azure NSG / Firewall
- Azure NSG is stateless at the packet level — it tracks flows, not packets. Flow tracking timeout is 4 minutes (240 seconds) for idle TCP connections.
- Azure Firewall has a TCP idle timeout of 4 minutes (not configurable pre-2023). Long-lived connections with idle periods > 4 minutes will be dropped.
- Azure Load Balancer sends TCP RST when a backend health probe fails. This can cause existing connections to be reset even if the backend is partially functional.
- SNAT port exhaustion on Azure Load Balancer causes connection failures. Look for SYN packets with no response — different from firewall blocking because the SYN never reaches the target.

### F5 BIG-IP
- Connection mirroring between active/standby can cause duplicate packets visible in captures on the server side.
- OneConnect (connection pooling) means the client-side and server-side TCP connections are different. Sequence numbers, window sizes, and timing will not match between client and server captures.
- iRules processing adds variable latency that shows up as jitter in server-side captures.

## VPN-Related Issues
- IPSec tunnels reduce effective MTU by 50-80 bytes. If PMTUD is broken (ICMP blocked), you'll see fragmentation or connections that hang after the initial handshake (small packets work, large packets don't).
- SSL VPN (e.g., AnyConnect, GlobalProtect) wraps TCP-in-TCP, which can cause catastrophic retransmission amplification when the outer TCP retransmits packets that the inner TCP also retransmits.
- Split tunneling changes can cause DNS resolution to work differently — queries may go through the tunnel or directly, producing confusing DNS behavior.

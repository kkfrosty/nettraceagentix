# Analysis False Positives & Expert Guidance

## Common False Positives — Do NOT Flag These as Problems

### TCP RST After FIN Is Normal
A TCP RST sent after a proper FIN/FIN-ACK handshake is a common optimization. The sender is cleaning up the connection state. This is **NOT** a connection error or attack.

### Wireshark Mislabels Retransmissions in NIC Teaming / NAT / Mirroring
When traffic passes through NIC teaming (LBFO, bonding), NAT gateways, or SPAN/mirror ports, Wireshark sees the same packet multiple times and flags them as "TCP Retransmission" or "TCP Spurious Retransmission."

**How to identify:** Check whether packets have the SAME TCP payload/sequence but DIFFERENT MACs or sub-millisecond timing deltas. If so, it's a capture artifact, not real retransmissions. Also check if the capture was taken on a mirror port or SPAN session.

### Container / Kubernetes Environments Multiply Packets
In AKS, EKS, GKE, and Docker environments, a single packet traverses multiple virtual interfaces:
- Pod veth → container bridge → host NIC (3x duplication possible)
- Service mesh sidecars (Envoy/Istio) add another hop

If you see exact duplicate packets with sub-millisecond timing (< 0.1ms apart), consider the capture point before flagging retransmissions. Ask where the capture was taken (inside the pod, on the node, at the load balancer).

### Duplicate ACKs ≤ 3 Are Normal
TCP uses duplicate ACKs as a signaling mechanism — fast retransmit triggers at 3 DupACKs. A small number is expected behavior. Only flag when DupACK count is consistently high across multiple streams.

### RST to Closed Port Is Expected
When a client connects to a port with no listener, the server sends RST. This is standard TCP behavior (RFC 793), not an attack or misconfiguration.

### TCP Window Size Variations Are Not Errors
Window scaling, window size changes, and receive window updates are normal TCP flow control. Fluctuating window sizes indicate the receiver is managing its buffer. Only flag **zero-window** events that persist for more than a few seconds.

## Environment-Specific Awareness

### Multiple DHCP Servers
Multiple DHCP servers on a segment can be:
- **Intentional:** Redundancy (Windows Server DHCP failover, ISC DHCP split-scope)
- **Problematic:** Rogue DHCP (someone plugged in a home router)

Check whether the offered configurations (gateway, DNS, subnet) conflict before flagging. If configurations match, it's likely redundancy.

### Gratuitous ARP
Normal for: failover clusters (Windows WSFC, Linux keepalived), VRRP/HSRP transitions, IP mobility events. Only flag if the MAC-to-IP mapping contradicts the expected topology provided in the case context.

### TCP Keepalives
Small packets (0-1 byte payload) at regular intervals on idle connections are TCP keepalives. Don't flag as anomalies — they're a standard mechanism to detect dead connections.

### TTL Variations
Different TTL values in packets to the same destination can indicate:
- Load balancers (different backend servers)
- Anycast routing (different physical servers answering)
- Asymmetric routing

Not always a routing problem. Only flag if combined with unreachable hosts or packet loss.

### Out-of-Order Packets in Small Quantities
Less than 1% OOO in a stream is normal on multi-path networks (ECMP, SD-WAN, bonded links). Only escalate when paired with retransmissions indicating actual data loss.

## Firewall and Middlebox Behaviors That Look Wrong But May Be Expected
- **Firewall-injected RSTs:** Firewalls blocking a connection may inject RST packets to BOTH sides. This looks like the endpoint reset the connection, but it was actually the firewall. Look for: RST from an unexpected direction, RST with TTL different from the endpoint's normal TTL.
- **MSS Clamping:** Firewalls/VPNs may modify TCP MSS options. If you see unexpectedly small MSS (e.g., 1300 instead of 1460), check whether a VPN or tunnel is in the path.
- **Stateful Firewall Timeouts:** Stateful firewalls drop packets for "established" connections after an inactivity timeout. The next packet gets silently dropped or RST'd. Look for connection idle time (30-300s gap) before the failure.
- **DPI Latency:** Deep packet inspection introduces inter-packet gaps that look like server processing delay. If you see consistent added latency on initial packets of a flow, suspect DPI.

## Severity Calibration
- **Concern:** Hundreds of retransmissions in a short stream, zero-window persisting for seconds, RST without ANY prior communication, patterns that worsen over time
- **Note but don't alarm:** Occasional retransmissions (< 1%), single RST after completed exchange, minor out-of-order on WAN links, TCP keepalives, window size changes

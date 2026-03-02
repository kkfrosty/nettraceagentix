# Security Analysis Heuristics

These heuristics are activated when the capture contains security-relevant anomalies
(malformed packets, IP fragments, suspicious TCP flag combinations, etc.).

## Principle 1: Protocol Violations Are Assumed Hostile
Any packet where a protocol field contradicts another field is a CRITICAL finding.
- Length mismatches (stated vs actual payload size)
- Impossible flag combinations (e.g., SYN+FIN, SYN+RST, all flags set "Christmas tree")
- Header values that would cause buffer overflow (IP total length < header length, TCP data offset > packet size)
- Checksums that don't match (when not offloaded — check if ALL packets have bad checksums, which indicates NIC offload, not corruption)

**WHY:** Legitimate TCP/IP stacks do not produce malformed packets. Malformed = intentional crafting or catastrophic hardware failure.

**EXCEPTION:** If ALL packets in the capture have bad checksums, this is almost certainly TCP checksum offload (the NIC calculates checksums after the capture point). Do NOT flag this as an attack.

## Principle 2: Fragmentation Is Suspicious by Default
IP fragmentation is rare in modern networks. Path MTU Discovery (PMTUD) and MSS negotiation handle sizing.
Flag as SUSPICIOUS and investigate if you see:
- Any IP fragments at all (increasingly uncommon post-2005)
- Fragments smaller than 256 bytes (almost never legitimate)
- Multiple fragments with inconsistent total sizes declared in their IP headers
- Fragments where offsets would cause overlap (classic teardrop/Rose attack signature)
- Fragments to/from hosts that also have normal-sized packets on other connections

**WHY:** Fragmentation is the basis for an entire class of attacks:
- **Teardrop:** Overlapping fragment offsets crash the reassembly code
- **Ping of Death:** Fragments that reassemble to > 65535 bytes
- **Tiny Fragment:** Fragments so small the TCP header spans two fragments, bypassing firewall rules
- **Rose/Jolt:** Repeated fragment floods causing CPU exhaustion

## Principle 3: Subnet Anomalies Suggest Spoofing
If a packet's source IP belongs to a different subnet than other traffic from the same MAC address or physical segment, flag as LIKELY SPOOFED.

**WHY:** Legitimate hosts don't change subnets mid-conversation. Exceptions: DHCP renewal, VPN connect/disconnect.

## Principle 4: Timing Correlation Reveals Intent
If reconnaissance activity (DNS queries for many hosts, TCP SYN to many ports, ARP requests sweeping a range) is followed within seconds by anomalous traffic to a discovered target, flag the entire sequence as an ATTACK CHAIN.

**WHY:** The recon→exploit pattern is universal across attack methodologies.

## Principle 5: Expert Info Errors in Security Context Are Critical
When malformed packets or fragments are present, Wireshark expert "errors" and "warnings" take on elevated importance.
- NEVER treat expert errors as secondary/informational findings in this context
- For each expert error, ask: "What would cause a legitimate system to produce this?"
- If the answer is "nothing reasonable" → it is an attack or severe misconfiguration

## Principle 6: Absence Is Evidence
No TCP connections completing (3-way handshake) in a capture where connections are expected = something is PREVENTING them.
Consider:
- DoS flooding (attack traffic crowding out legitimate traffic)
- ARP poisoning (traffic misdirected to wrong MAC)
- Firewall drops (stateful firewall rejecting without RST)
- SYN flood (half-open connections exhausting server resources)

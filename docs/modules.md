# Modules

Each compiled module declares ID, semantic version, risk class, required tool,
required capability, supported platforms, and concurrency limit. The interface has
separate `Validate` and `Execute` phases. The executor validates the signed envelope
before selecting a module, then requires exact risk-class compatibility and an
available capability.

| Module | Implementation | Risk | Main controls |
|---|---|---|---|
| `network.ping` | fixed platform adapter | SAFE_ACTIVE | count 1–5; bounded timeout |
| `network.route` | traceroute/tracert adapter | SAFE_ACTIVE | max 30 hops; no user flags |
| `network.dns` | Go resolver | SAFE_ACTIVE | record-type allowlist |
| `network.tcp` | `net.Dialer` | SAFE_ACTIVE | validated port and timeout |
| `network.http` | `net/http` | SAFE_ACTIVE | HEAD/GET; body/redirect bounds; same-host redirects |
| `network.tls` | `crypto/tls` | SAFE_ACTIVE | server-name validation; metadata only |
| `nmap.discovery` | fixed Nmap XML profile | SAFE_ACTIVE | no NSE/evasion/spoofing/free args |
| `nmap.services` | fixed Nmap XML profile | CONTROLLED_ACTIVE | controlled endpoint + authorization |
| `traffic.tshark` | offline PCAP adapter | PASSIVE | three fixed profiles; no live capture/filter input |
| `traffic.zeek` | offline PCAP adapter | PASSIVE | isolated temp directory; expected logs only |
| `security.suricata` | offline EVE JSON adapter | PASSIVE | no IPS or traffic alteration |
| `performance.iperf3` | fixed JSON profile | CONTROLLED_ACTIVE | controlled endpoint; 30s max; fixed UDP rate |

Tools are never installed automatically. No Greenbone adapter is part of the base
Agent. v0.1 cannot load server-supplied `.so` files or any other executable plugin.

New modules must define a narrow schema, risk class, target invariants, required
authorization, output normalization, failure codes, resource bounds, concurrency,
platform behavior, and documentation before registry inclusion.

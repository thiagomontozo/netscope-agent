# Modules

All module IDs, versions, risk classes, capability IDs and parameter names match the current Control Plane catalog.

| Module | Parameters |
|---|---|
| `network.ping` | `samples` 1-10, `timeoutMs` 100-10000 |
| `network.route` | `maxHops` 1-32, `timeoutMs` 100-10000 |
| `network.dns` | `recordType`: A, AAAA, CNAME, MX, TXT, NS |
| `network.tcp` | `port` 1-65535, `timeoutMs` 100-10000 |
| `network.http` | HEAD/GET, redirect limit 0-5, expected status, bounded response bytes |
| `network.tls` | port and expiry-warning days |
| `nmap.discovery` | `DISCOVERY`, max 256 hosts |
| `nmap.services` | controlled service profile, max 64 hosts |
| PCAP adapters | artifact ID and compiled preset; unavailable until content delivery exists |
| `performance.iperf3` | endpoint ID and duration; unavailable until endpoint resolution exists |

DNS, TCP, HTTP and TLS use Go. Ping and route use OS adapters. Nmap uses only `-sn` or a fixed connect/service profile with XML output. There are no arbitrary NSE scripts, stealth/evasion/spoofing controls or free-form arguments.

The registry is compiled. A module must match the envelope's exact `moduleVersionRequirement` (`0.1.0` today), risk class and reported capability before execution.

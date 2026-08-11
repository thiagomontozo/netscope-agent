# Capabilities

Discovery runs at startup and reports OS, architecture, supported Go-native network
operations, and presence of expected binaries. The capability set includes `PING`,
`TRACEROUTE`, `DNS`, `TCP`, `HTTP`, `TLS`, `NMAP`, `TSHARK`, `ZEEK`, `SURICATA`, and
`IPERF3`.

Version detection uses only each adapter's fixed version/help arguments, a two-second
deadline, a minimal environment, and a 256-byte summary of the first output line.
Full tool output is not reported. A binary that is absent produces
`available=false`; the Agent never downloads or installs it.

The heartbeat sends a SHA-256 hash of the capability report. A changed hash allows
the Control Plane to request/refetch the current report and emit
`agent.capabilities_changed`. Module descriptors additionally expose supported
module versions so the scheduler can avoid incompatible jobs.

Availability does not equal authorization. A label, network zone, installed binary,
or reported capability cannot by itself authorize an active assessment.

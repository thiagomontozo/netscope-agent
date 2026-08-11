# Continuous Integration

NetScope Agent uses GitHub Actions on pushes and pull requests targeting
`main`, with an optional manual trigger.

## Gates

- Go formatting and module checksum verification.
- `go vet` and package tests using the Go version declared in `go.mod`.
- CGO-disabled compilation for Linux (`amd64`, `arm64`), Windows (`amd64`) and
  macOS (`amd64`, `arm64`).
- A non-privileged container image build after the quality gates succeed.

The workflow has read-only repository permissions, pins actions to reviewed
commit SHAs, cancels superseded runs and applies job timeouts. Cross-compiled
binaries are transient validation outputs and are not published as releases.

## Safety boundary

CI never starts the agent and never executes a diagnostic adapter. It does not
contact a Control Plane, enroll an identity, inspect a target, capture packets,
or invoke Ping, Traceroute, Nmap, Zeek, Suricata, TShark or iperf3. The workflow
only examines and compiles source code and builds the agent container.

## Branch protection

After the first workflow run, repository administrators should require `Go
quality gates`, all supported platform build checks and `Container build` before
merging into `main`.

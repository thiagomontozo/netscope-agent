# Linux deployment

Create a system account without login, install the binary at
`/usr/local/bin/netscope-agent`, configuration at `/etc/netscope-agent/agent.env`,
and a mode-`0700` state directory at `/var/lib/netscope-agent` owned by `netscope`.
Copy `packaging/systemd/netscope-agent.service`, review its hardening settings, then
enable it according to local change-control practice.

Keep the enrollment token only for the first successful start, then remove it from
`agent.env` and restart. The Agent also clears the token from its own process
environment after successful enrollment. Protect `NETSCOPE_SERVER_CA_CERT` and the
state directory from all users except the service identity. The generated key,
client certificate, enrollment CA, fingerprint, and metadata are kept below
`/var/lib/netscope-agent/identity`; the private key is created with mode `0600` and
the identity directory with mode `0700`. Prefer journald for structured logs.

Certificate rotation is exposed by the Control Plane. Monitor the stored
certificate expiry and perform an administratively approved re-enrollment before it
expires. Do not delete a working identity as an automated recovery mechanism.

The base unit grants no capabilities. Go-native DNS/TCP/HTTP/TLS need none. ICMP or
capture-related tools may require narrowly scoped Linux capabilities depending on
distribution and implementation; grant only the minimum after security review. Do
not run the entire Agent as root. Docker deployments likewise should not default to
`--privileged`; add a specific capability only for an enabled module that requires it.

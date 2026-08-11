# Linux deployment

Create a system account without login, install the binary at
`/usr/local/bin/netscope-agent`, configuration at `/etc/netscope-agent/agent.env`,
and a mode-`0700` state directory at `/var/lib/netscope-agent` owned by `netscope`.
Copy `packaging/systemd/netscope-agent.service`, review its hardening settings, then
enable it according to local change-control practice.

Keep the enrollment token only for the first successful start, then remove it from
`agent.env` and restart. Protect custom CA, mTLS key, and Control Plane signing-key
files from all users except the service identity. Prefer journald for structured
logs instead of a separate writable log directory.

The base unit grants no capabilities. Go-native DNS/TCP/HTTP/TLS need none. ICMP or
capture-related tools may require narrowly scoped Linux capabilities depending on
distribution and implementation; grant only the minimum after security review. Do
not run the entire Agent as root. Docker deployments likewise should not default to
`--privileged`; add a specific capability only for an enabled module that requires it.

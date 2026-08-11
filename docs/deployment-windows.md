# Windows deployment

Install the amd64 binary under `C:\Program Files\NetScope Agent` and store state in
`%ProgramData%\NetScope Agent`. Create a dedicated service identity without local
administrator membership. Grant it read/execute access to the binary, read access
to configured certificate material, and write access only to the state directory.

Register the binary directly as a Windows Service through an approved service
manager. Do not use a free-form PowerShell or `cmd.exe` wrapper and do not place the
enrollment token or credentials on the command line. Inject protected environment
configuration, start once to enroll, then remove the enrollment token. The Agent
also clears the token from its process environment after successful enrollment.

Windows filesystem ACL policies should protect the generated files below
`%ProgramData%\NetScope Agent\identity`, especially `client-private-key.pem`.
The identity also contains the client certificate, enrollment CA, fingerprint, and
metadata. Certificate rotation is not yet exposed by the Control Plane, so expiry
must be operationally monitored. `tracert`/`ping` availability is detected; other
tools are optional and separately governed. The Agent does not install them. Review
service recovery, outbound firewall allowlists, log collection, and upgrade rollback
under the organization's deployment policy.

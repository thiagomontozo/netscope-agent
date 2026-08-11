# Windows deployment

Install the amd64 binary under `C:\Program Files\NetScope Agent` and store state in
`%ProgramData%\NetScope Agent`. Create a dedicated service identity without local
administrator membership. Grant it read/execute access to the binary, read access
to configured certificate material, and write access only to the state directory.

Register the binary directly as a Windows Service through an approved service
manager. Do not use a free-form PowerShell or `cmd.exe` wrapper and do not place the
enrollment token or credentials on the command line. Inject protected environment
configuration, start once to enroll, then remove the enrollment token.

Windows certificate and filesystem ACL policies should protect the client key and
identity. `tracert`/`ping` availability is detected; other tools are optional and
must be installed and governed separately. The Agent does not install them. Review
service recovery, outbound firewall allowlists, event/log collection, and upgrade
rollback under the organization's deployment policy.

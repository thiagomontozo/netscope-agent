# Windows service packaging

Install the release binary in `C:\Program Files\NetScope Agent` and keep state
under `%ProgramData%\NetScope Agent`. Use a dedicated, non-administrator service
account and a service manager that passes configuration as protected environment
variables. Grant that account read access to the configured CA/client certificate
and write access only to its data directory.

The service command is the binary itself; no `cmd /c`, PowerShell command string,
or wrapper script is required. Recovery may restart the service after failure.
Never place the enrollment token in the service command line. Remove it from the
service environment after successful enrollment.

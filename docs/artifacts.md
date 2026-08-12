# Artifacts

Artifacts are not placed in the small result spool. A transfer uses an
Agent/job/artifact/purpose-scoped short-lived token over the existing
authenticated channel. Downloads stream into a 0600 temporary file through a
hard limit and SHA-256 writer; a size or checksum mismatch deletes the partial
file and returns `ARTIFACT_CHECKSUM_MISMATCH`. Uploads accept only regular files,
declare length/checksum and stream with a local maximum. Original filenames are
never local destination paths.

Configure local and Control Plane maxima consistently. Multipart resume and
large-artifact offline queuing are outside v0.2.

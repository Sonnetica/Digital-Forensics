# E-TRACE

Email Timeline Reconstruction and Artifact Correlation Engine.

## Installation

Use Python 3.12 or later. From the repository root:

```powershell
python -m venv E:\etrace-env
E:\etrace-env\Scripts\python -m pip install .
```

On Linux or macOS, use `python3 -m venv ~/etrace-env` and
`~/etrace-env/bin/python -m pip install .`. Activate the environment or use the
full path to its `etrace` executable for the commands below.

## Create and acquire a case

Keep case databases, input evidence, and exports outside this repository.

```powershell
etrace init E:\cases\incident.db --name "Email incident"
etrace ingest E:\cases\incident.db E:\evidence
etrace info E:\cases\incident.db
etrace verify E:\cases\incident.db
etrace export E:\cases\incident.db --output E:\cases\incident.json
```

Ingestion accepts individual `.eml` and `.msg` files or recursively scans a
directory. It reads the source, stores its exact bytes and SHA-256 in SQLite,
and records each source location. Identical files share one evidence identity;
different files with the same Message-ID remain separate evidence items.
Files larger than 25 MiB, empty files, unsupported formats, and exceeded parsing
limits are rejected. Per-file errors do not discard successful acquisitions.
An ingest command returns a nonzero exit status when any file fails.

## Evidence interpretation

Date and Received timestamps retain their raw values and are normalized to UTC
only when an offset is available. Missing or ambiguous dates remain unknown.
Header values, including sender identities, IP addresses and authentication
results, are observations and are not independently authenticated.

Attachment hashes cover transfer-decoded bytes, not their encoded MIME text.
Attached emails and embedded Outlook items remain in the original source and
are not flattened into the outer message. URL extraction covers text bodies,
HTML links and resource attributes; it does not inspect attachment contents,
follow redirects, fetch remote resources or execute email HTML.

`verify` checks source hashes, parsed-record hashes, the artifact index and the
audit chain. This detects internal inconsistencies, but is not a digital
signature or independent proof of custody. Retain the exported audit head in a
separate trusted location. Source originals remain necessary for independent
verification. Exports contain sensitive evidence metadata and body previews.

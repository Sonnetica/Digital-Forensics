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
etrace analyze E:\cases\incident.db --window-seconds 3600
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

## Correlation rules

| Rule | Trigger | Interpretation |
| --- | --- | --- |
| Attachment reuse | Same SHA-256 in at least two distinct source files | Equal decoded bytes; direction is not inferred |
| URL reuse | Same conservatively normalized HTTP(S) URL in at least two source files | Shared URL; no network lookup |
| Reply | In-Reply-To resolves to one unambiguous Message-ID; otherwise the last References identifier when In-Reply-To is absent | Header-linked relationship; References fallback is explicitly qualified |
| Possible coordination | At least two distinct categories among attachment hash, URL, normalized subject and claimed origin IP, within an inclusive time window | Reviewable hypothesis; excludes resolved reply components |

Each result includes rule version, all parameters, source SHA-256 identities,
exact matched values, header/MIME locations, supporting observations and
separate contextual limitations. Ambiguous parents and missing sources appear
as diagnostics; reply cycles and time reversals remain visible.

Subject matching removes leading Re/Fw/Fwd prefixes, folds case and collapses
whitespace. URL matching lowercases scheme/host, converts international hostnames
to IDNA, removes default ports and normalizes an empty path to `/`. Query order,
values, percent encoding, path case and fragments are preserved. IP matching uses
one X-Originating-IP claim or the `from` clause of the oldest Received header;
shared relay addresses are not automatically treated as senders.

Use `--minimum-signals 3` for a stricter coordination hypothesis or
`--timestamp-source received` to use the top Received header instead of Date.
There is no silent time-source fallback. Parameters are saved with every run.
Unknown times exclude messages only from temporal coordination. Repeating a run
with the same evidence and parameters produces the same identifier. New evidence
requires a new analysis; old runs remain available in the export.

Resource limits abort analysis without saving partial results. Defaults allow
250,000 distinct coordination candidates, 2,000,000 candidate comparisons and
50,000 events. CLI options `--max-candidates` and `--max-events` change those
limits; the comparison limit is eight times the candidate limit.

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

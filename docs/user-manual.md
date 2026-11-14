# E-Trace user manual

Start with the [README](../README.md) for installation and a first run. The commands below run from the repository root in Windows PowerShell. They call the virtual environment directly, so activation is unnecessary. On macOS or Linux, use `./.venv/bin/python` in place of `.\.venv\Scripts\python.exe`.

## Create and acquire a case

Keep real evidence and shared case data outside this repository. For local demonstrations, `work/` is ignored by Git.
The `samples/quick-demo/` folder contains 14 fictional EML files for a local trial;
its [scenario guide](../samples/quick-demo/README.md) explains the expected relationships.

```powershell
.\.venv\Scripts\python.exe -m etrace init .\work\incident.db --name "Email incident"
.\.venv\Scripts\python.exe -m etrace ingest .\work\incident.db .\samples\quick-demo
.\.venv\Scripts\python.exe -m etrace info .\work\incident.db
.\.venv\Scripts\python.exe -m etrace analyze .\work\incident.db --window-seconds 3600
.\.venv\Scripts\python.exe -m etrace verify .\work\incident.db
.\.venv\Scripts\python.exe -m etrace export .\work\incident.db --output .\work\incident.json
.\.venv\Scripts\python.exe -m etrace export .\work\incident.db --bundle --output .\work\incident-bundle.zip
```

Ingestion accepts individual `.eml` and `.msg` files or recursively scans a
directory. It reads the source, stores its exact bytes and SHA-256 in SQLite,
and records each source location. Identical files share one evidence identity;
different files with the same Message-ID remain separate evidence items.
Files larger than 25 MiB, empty files, unsupported formats, and exceeded parsing
limits are rejected. Per-file errors do not discard successful acquisitions.
An ingest command returns a nonzero exit status when any file fails.

## Case handoff bundle

The case database already holds the original bytes, parsed records, every run and
its settings, and the audit trail. A bundle packages the same material as plain
files so another investigator can check it with standard tools and reproduce the
analysis without access to the original database:

```powershell
.\.venv\Scripts\python.exe -m etrace export .\work\incident.db --bundle --output .\work\incident.zip
.\.venv\Scripts\python.exe -m etrace import-bundle .\work\incident.zip --case .\work\incident-rebuilt.db
```

The zip contains `sources/` (each original EML/MSG named by its SHA-256),
`case-export.json` (the JSON export, including the audit trail and integrity
check), `manifest.json` (hashes, sizes, every acquisition name and time, runs and
their findings digests), `SHA256SUMS` and a short `README.txt`. On Linux or macOS
`sha256sum -c SHA256SUMS` checks every file; on Windows compare
`Get-FileHash -Algorithm SHA256` output with `SHA256SUMS`. **Export bundle** in the
interface downloads the same zip.

`import-bundle` refuses a bundle with any altered, missing, unlisted or oddly
named file, before creating the case. It also checks that the manifest, JSON
export and acquisition audit agree. It then recomputes the original audit hash
chain, ingests every acquisition under its original name, records an
`import_bundle` entry (bundle SHA-256 and original audit head) in the new case's
audit trail, and re-runs each saved analysis with its saved settings on the
evidence that run used. The report states per run whether the findings (copy
groups, relationships, diagnostics and statistics) match. Run identifiers also
match when the Python and extract-msg versions are the same; parsed records note
those versions, so another machine can give a different identifier with identical
findings. Runs made with other rule or parser versions are reported as not
comparable. Matching runs are saved in their original acquisition order, even
when later files made a run stale. The command exits with status 1 when the
original audit chain or a comparable run does not reproduce.
The rebuilt case has its own acquisition times and audit trail; the original
trail stays in `case-export.json`.

## Investigator interface

```powershell
.\.venv\Scripts\python.exe -m etrace serve .\work\incident.db --port 8765
```

Open `http://127.0.0.1:8765` in a current browser. Stop the server with Ctrl+C.
The interface binds only to this computer's loopback address and does not need
an internet connection after installation. It is a local, single-investigator
application, not a hosted service with user accounts.

1. Select **Import evidence**, choose EML/MSG files, then **Acquire evidence**.
   Uploads allow 100 files per batch, 25 MiB each, and a 100 MiB request limit.
   Every rejected file is listed; valid files in the same batch are retained.
2. Select **Run analysis**. Set the coordination window, minimum number of
   artifact categories, timestamp source and routine-background test. Defaults are
   3,600 seconds, two categories, Date, at least ten occurrences outside a pair's
   window at a 5:1 outside-to-inside ratio. The investigated organisation's own
   domain is left empty: enter it, or select **Use suggested domain** after
   checking that the suggestion is your organisation and not a supplier. Further
   URL domains can be excluded from coordination. The case is verified before
   analysis.
3. Use **Evidence** to search subjects, addresses, body previews, URLs and hashes.
   Select a subject to inspect raw headers, timestamp observations, artifacts,
   acquisition locations and a safe text preview. **Download preserved source**
   returns the original bytes as an attachment.
4. Use **Timeline** to filter by relationship type, UTC date range and search
   term. The date filter selects relationships overlapping the requested range;
   unknown-time relationships are excluded when a date filter is active.
   Select **Inspect evidence** to see the rule, exact observations, participating
   source messages and contextual counter-evidence.
5. Use **Relationship graph** to explore the same filters. Circles are messages;
   diamonds are relationships. Reply arrows point from the candidate parent
   through the relationship to the child. Pan, zoom, drag nodes or select a node
   to inspect it. Keyboard users can Tab to nodes and press Enter. The graph
    hides coordination clusters by default and limits its display to 180 nodes;
    use **Show coordination clusters** to include them. The timeline and export remain
   complete, including groups too large to fit in the graph.
 6. **Case integrity** checks hashes and the audit trail and lists copy and
    relationship diagnostics. **Export case** downloads structured JSON containing all
   evidence metadata, every analysis run, provenance and the audit chain.

The analysis selector reopens older runs. The Relationships card and the notice
follow the run being viewed; an older run shows its own count next to the latest
run's. A visible notice marks the latest run out of date when evidence
was added after it, or when it was made with an older rule or parser version (or
one it did not record), or when the parsed evidence no longer matches the record
digest saved with the run, and names the reason. An analysis of an empty case is
current; `etrace info` reports the same
`latest_run` status. Older runs are never altered and stay available for review. Select **Apply** after changing filters; **Reset** clears them.

Browser uploads retain filenames as acquisition labels; use CLI ingestion when
the original full source path should be recorded. Evidence HTML is never
inserted into the page, links are not opened automatically, and uploaded
attachments are neither executed nor written to their claimed filenames.


## Troubleshooting

- **Command not found:** use the full path to the environment's `etrace`
  executable, or run `python -m etrace` with that environment's Python.
- **Port already in use:** stop the other local instance or choose another
  `--port`. Keep the browser URL on the port shown in the server console.
- **Request rejected after restarting the server:** reload the browser page to
  renew its local session and request token.
- **Case already exists:** choose a new case path or open the existing case.
  Case creation and CLI exports never overwrite existing files.
- **Integrity mismatch:** retain the affected database and original evidence,
  compare against your separately held export, and acquire into a new case for
  further analysis. Do not edit SQLite records to hide a mismatch.
- **Analysis limit exceeded:** use a smaller, justified evidence selection or
  raise the explicit CLI limits. The failed run is not saved as a complete result.

Parsing and relationship semantics are informed by
[RFC 5322](https://www.rfc-editor.org/rfc/rfc5322.html) and its
[RFC 6854](https://www.rfc-editor.org/rfc/rfc6854.html) originator-field update, URL normalization by
[RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html), and implementation APIs by
the [Python email documentation](https://docs.python.org/3/library/email.parser.html)
and [Flask security documentation](https://flask.palletsprojects.com/en/stable/web-security/).

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

MSG files are read with extract-msg (installed with E-Trace). The HTML body
property is binary (MS-OXPROPS `PidTagHtml`); it is decoded with the message's
`PidTagInternetCodepage`, then an HTML `<meta charset>`, then UTF-8, and finally
Windows-1252 with replacement and a `charset_fallback` warning. The codec used and
its basis are recorded with the part. When no HTML property is stored, Outlook
often keeps the HTML inside the compressed RTF body; E-Trace then reconstructs it
(RTF de-encapsulation) so link targets are searched, labels the part as derived
from `PidTagRtfCompressed` and adds a `msg_body_from_rtf` observation. Plain RTF
without encapsulated HTML or text, RTF bodies over 5 MiB, malformed RTF and
encrypted bodies remain in the source with a limitation warning. Unsupported text MIME
types, nested email attachments, malformed encodings and timestamp issues are
visible in the evidence record. Plain-text URL punctuation is preserved because
it may be part of a valid path; this conservative choice can miss a reuse match
when a sentence ends with punctuation attached to its URL. HTML attributes
provide more precise URL boundaries. Limits are 1,000 MIME parts/MSG attachments,
30 MIME nesting levels, 2,000,000 total decoded text characters and 20,000
artifact observations per message. Evidence exceeding a limit is rejected.

PST/OST archives, mailbox acquisition, deleted-message recovery, attachment
malware scanning, DNS lookups and independent SPF/DKIM verification are outside
the implemented scope. Export individual EML/MSG files from your acquisition
tool before ingestion. Sharing a URL or attachment does not establish a phishing
campaign, a transfer path or the identity of a sender.

`verify` checks source hashes, parsed-record hashes, the artifact index and the
audit chain. This detects internal inconsistencies, but is not a digital
signature or independent proof of custody. Retain the exported audit head in a
separate trusted location. Source originals remain necessary for independent
verification. Exports contain sensitive evidence metadata and body previews.

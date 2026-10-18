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

For the exact submitted dependency set, install `requirements.txt` first and
then install the project with `python -m pip install --no-deps .`. The application
has no cloud services, API keys or external JavaScript/CDN requirements.

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

## Investigator interface

```powershell
etrace serve E:\cases\incident.db --port 8765
```

Open `http://127.0.0.1:8765` in a current browser. Stop the server with Ctrl+C.
The interface binds only to this computer's loopback address and does not need
an internet connection after installation. It is a local, single-investigator
application, not a hosted service with user accounts.

1. Select **Import evidence**, choose EML/MSG files, then **Acquire evidence**.
   Uploads allow 100 files per batch, 25 MiB each, and a 100 MiB request limit.
   Every rejected file is listed; valid files in the same batch are retained.
2. Select **Run analysis**. Set the coordination window, minimum number of
   artifact categories, and timestamp source. Defaults are 3,600 seconds,
   two categories and Date. The case is verified before analysis.
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
   explicitly limits its display to 180 nodes; the timeline and export remain
   complete, including groups too large to fit in the graph.
6. **Case integrity** checks hashes and the audit trail and lists unresolved
   parent identifiers. **Export case** downloads structured JSON containing all
   evidence metadata, every analysis run, provenance and the audit chain.

The analysis selector reopens older runs. Summary cards describe the latest
selected analysis. A visible notice identifies a stale current run after new evidence is
added. Select **Apply** after changing filters; **Reset** clears them.

Browser uploads retain filenames as acquisition labels; use CLI ingestion when
the original full source path should be recorded. Evidence HTML is never
inserted into the page, links are not opened automatically, and uploaded
attachments are neither executed nor written to their claimed filenames.

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
with the same parsed evidence and parameters produces the same identifier.
Each source record includes its Python and, for MSG, extract-msg parser version;
changing parser runtimes can change extraction and therefore run identifiers. New evidence
requires a new analysis; old runs remain available in the export.

Resource limits abort analysis without saving partial results. Defaults allow
250,000 distinct coordination candidates, 2,000,000 candidate comparisons and
50,000 events. CLI options `--max-candidates` and `--max-events` change those
limits; the comparison limit is eight times the candidate limit.

## Reproducible evaluation

After installing the package, run these commands from the repository root. The
generator and evaluator refuse to write generated data inside the repository.

```powershell
python evaluation/generate.py --output E:\evaluation\simple --tier simple --seed 47
python evaluation/evaluate.py E:\evaluation\simple --output E:\evaluation\simple-results.json
python evaluation/generate.py --output E:\evaluation\medium --tier medium --seed 47
python evaluation/evaluate.py E:\evaluation\medium --output E:\evaluation\medium-results.json
python evaluation/generate.py --output E:\evaluation\complex --tier complex --seed 47
python evaluation/evaluate.py E:\evaluation\complex --output E:\evaluation\complex-results.json
```

Use the Python executable from your installed environment. Output directories
must be empty and result files must not already exist. `--noise 1000` adds a
larger unrelated-message workload. Change `--seed` for another deterministic
corpus. The generator creates original EML bytes, a SHA-256 manifest and ground
truth specified from the planted scenarios, without invoking the correlation
engine. It includes artifact reuse, normal reply chains, one-artifact controls,
window-boundary cases, uncertain dates, duplicate Message-IDs, reply cycles,
duplicate acquisitions and URL distinctions according to the selected tier.

The evaluator verifies corpus hashes before parsing. It reports TP, FP, FN, TN,
precision, recall, F1, false positive rate and false negative rate per rule and
as micro totals. Artifact groups expand to unordered message pairs; reply pairs
are directed parent-to-child pairs. The negative universe is every distinct
source pair for that rule, rather than only pairs generated by the engine.
Undefined metrics are JSON `null`. Error lists name the exact message pairs.

The comparison baseline labels any reused URL or attachment within the same
window as possible coordination and does not exclude reply threads. This is an
internal ablation with the same parser, not a comparison with a commercial tool.
Recorded parse/correlation timings include `tracemalloc` overhead; peak memory
is traced Python allocation, not total process memory. Synthetic results measure
controlled rule behavior. They do not establish real-world detection accuracy,
malicious intent, or human investigation time savings.

The evaluator exits 0 for no false positives/negatives, 1 for measured mismatches,
and 2 for invalid input. It accepts the same window, minimum-signal and time-source
options for separate parameter experiments; the result states whether they match
the fixed reference parameters. Do not overwrite reference results with tuning
results. To inspect a corpus visually, ingest its directory into a new case and
open the investigator interface.

## Code map and packaging

| Location | Responsibility |
| --- | --- |
| `src/etrace/parser.py`, `normalize.py` | EML/MSG extraction and conservative normalization |
| `src/etrace/case.py` | SQLite evidence, acquisition history, saved runs and verification |
| `src/etrace/correlate.py`, `model.py` | Indexed deterministic rules, parameters and provenance |
| `src/etrace/cli.py` | Case acquisition, analysis, export and server commands |
| `src/etrace/web.py`, `templates/`, `static/` | Local investigator API and browser interface |
| `evaluation/` | Reproducible corpus generator and quantitative evaluator |

The `pyproject.toml` builds an installable Python wheel. Build from a source copy
outside the repository with `python -m build --wheel --outdir E:\packages` after
installing the `build` package. A wheel installs with `python -m pip install
<wheel-path>` and provides the same `etrace` command. Runtime dependencies are
listed in `requirements.txt`; build tools and development tests are not runtime
dependencies. Source archives contain the application, evaluator and manual,
not generated evidence, databases, exports, build products, reports or slides.

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
[RFC 5322](https://www.rfc-editor.org/rfc/rfc5322.html), URL normalization by
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

Only stored plain-text and HTML bodies are extracted from MSG files. RTF-only
and encrypted bodies remain in the source and produce a limitation warning.
The extractor does not synthesize HTML or decompress RTF. Unsupported text MIME
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

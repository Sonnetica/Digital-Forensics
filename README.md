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
These three tiers check implementation conformance to specified rules. Changing
the random seed changes message values, not the scenario structures, and is not
an independent validation of the underlying forensic hypotheses.

The evaluator verifies corpus hashes before parsing. It reports TP, FP, FN, TN,
precision, recall, F1, false positive rate and false negative rate per rule and
as micro totals. Artifact groups expand to unordered message pairs; reply pairs
are directed parent-to-child pairs. The negative universe is every distinct
source pair for that rule, rather than only pairs generated by the engine.
Undefined metrics are JSON `null`. Error lists name the exact message pairs.
For partially labelled data, that universe is restricted to explicitly labelled
pairs and declared complete subsets. Unlabelled background relationships are
never treated as negatives. Each rule reports its assessed candidate count and
unassessed prediction count; micro metrics cover only the assessed scope.

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
On entirely unlabelled input, exit status 0 means processing completed; its null
accuracy metrics do not constitute a passed detection benchmark.

### Public email and mixed workloads

The following commands download three pinned February 2003 archives from the
[Apache SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/readme.html).
They contain 3,250 unique messages in total. Archive SHA-256 values are pinned
in `evaluation/corpora.py`. Downloads and generated evidence stay outside Git.
The script reads regular archive members without extracting archive paths or
executing the included `cmds` files. A mismatched cached/downloaded archive fails
verification; it is never silently accepted.

```powershell
python evaluation/corpora.py --cache E:\evaluation\downloads --output E:\evaluation\public-1000 --count 1000 --seed 47
python evaluation/evaluate.py E:\evaluation\public-1000 --output E:\evaluation\public-results.json
python evaluation/mix.py E:\evaluation\public-1000 --output E:\evaluation\mixed-1000 --seed 97
python evaluation/evaluate.py E:\evaluation\mixed-1000 --output E:\evaluation\mixed-results.json
```

Selection is a seeded contiguous window of messages sorted by their aware Date
and SHA-256, with unknown dates last. It is independent of E-TRACE output and
retains temporal neighbours, but does not guarantee complete conversations.
Use `--count 3250` for the complete pinned population. Evidence gets a `.eml`
filename; its bytes remain identical to the archive member. The manifest records
original member names, archive hashes, selection settings, date coverage and
upstream modifications. This historical collection contains obfuscated addresses
and other edits described by Apache; it is not representative of every modern
email environment. Its spam/ham classes are not E-TRACE relationship labels.

The mixed dataset adds eight controlled messages within the observed public date
range. Real messages are unchanged. All pairs within the planted subset are
labelled; public-public and public-planted pairs remain unknown. The planted
artifacts use distinctive reserved-domain values, so recovering them establishes
survival in a real workload, not resistance to all realistic confounders. Report
their recovery separately from public-mail candidate volume and extraction
warnings. `peak_traced_python_bytes` covers parsing and correlation only, not
pairwise scoring, downloads, disk use or total process memory.

Each evaluation JSON includes a `review_queue`: up to 20 uniformly sampled
unassessed predictions per rule with fixed seed 47. Make a copy outside Git.
Review the named original messages independently, then set each completed entry's
`label` to `positive` or `negative`, and record `reviewer` and `rationale` with
the specific header, URL or decoded attachment evidence. Leave uncertain cases
`unassessed`. For coordination, assess observable support for the rule; do not
interpret that label as proof of a shared plan or malicious intent.

```powershell
python evaluation/evaluate.py E:\evaluation\mixed-1000 --reviews E:\evaluation\reviewed-results.json --output E:\evaluation\assessed-results.json
```

Reviews must match the exact analysis run and cannot override the fixed planted
labels. This is a review aid, not an automatically completed human study. A
sample of predicted pairs cannot estimate global recall. Report the number of
reviewed and uncertain cases, the selection procedure, assessor agreement and
sampling limitations. Do not describe reviewed-sample precision as whole-corpus
accuracy. Have a second group member assess the same sample before resolving
disagreements; do not replace independent assessment with the engine's explanation.

### Independent threading labels

[Minkov, Cohen and Ng's CMU release](https://www.cs.cmu.edu/~einat/datasets.html)
provides published queries and correct adjacent-message answers for Farmer and
Germany mailboxes. The [SIGIR 2006 paper](https://www.cs.cmu.edu/~einat/sigir-06.pdf),
section 5.4, identifies parents using subject and timestamp. This is an external
related-message retrieval task, not an all-rule E-TRACE forensic benchmark.

```powershell
python evaluation/cmu_threads.py --cache E:\evaluation\downloads --output E:\evaluation\cmu-test --split test
```

The script evaluates all published test queries against their complete mailbox
subsets. It maps directed reply edges to undirected adjacency for this one task.
It preserves the pinned source archives and writes separately hashed derivatives
with the release's leading blank lines removed. It never invents missing headers.
Results include every query, expected answer, original/derived hash and header
coverage count. The supplied 5,293 files lack Message-ID, In-Reply-To and References;
E-TRACE consequently recovers none of the 161 test query-answer relationships
(152 queries). Precision is undefined because it proposes no reply edges.
Keep this result: header-linked reconstruction cannot recover conversations when
those headers are unavailable. This does not implement or reproduce the paper's
ranking algorithm and does not evaluate URL, attachment or campaign detection.

### Challenge cases and claim boundaries

```powershell
python evaluation/generate.py --output E:\evaluation\challenge --tier challenge --seed 47
python evaluation/evaluate.py E:\evaluation\challenge --output E:\evaluation\challenge-results.json
```

This 15-message tier deliberately changes the coordination target: positive labels
represent membership in a declared planned distribution, independently of whether
the heuristic fires. It includes independent sharing of a common bulletin, planned
distribution through reply chains, personalised URLs/attachments, delayed sending,
and a straightforward positive control. The other three rules still use observable
relationship labels. These are constructed counterexamples, not estimated real-world
error rates. At default settings, coordination has 3 TP, 3 FP and 9 FN against this
intent target (precision 0.50, recall 0.25). Exit status 1 is expected. This exposes
the gap between the heuristic and a stronger campaign claim; do not hide these
cases or tune the defaults against them and then call them a held-out evaluation.

For a separately reported sensitivity experiment, repeat the evaluator with
`--window-seconds 7200` or `--minimum-signals 3` into distinct result files. Keep
the reference labels fixed. Compare candidate volume and labelled errors, and
explain the tradeoff without treating unassessed public matches as false positives.

The use of controlled evidence follows the general testing approach described by
[NIST CFReDS](https://cfreds-archive.nist.gov/): documented inputs allow expected
tool behaviour to be checked. E-TRACE is not NIST certified, and these scenarios
are not NIST datasets. No single dataset here supplies authenticated real-incident
ground truth for all four rules. Observable reuse, header-linked replies and
possible-coordination hypotheses must remain distinct in any presentation.

For additional acquisition validation, the group can record send/reply/forward
and independent-reuse actions through actual mail clients in a controlled mailbox,
export EML/MSG, and retain a separate action log before running E-TRACE. Record
client versions, export method, original hashes and missing messages. Such a lab
remains a simulation. No client study or human time-saving result is implied by
the automated evaluations above.

## Code map and packaging

| Location | Responsibility |
| --- | --- |
| `src/etrace/parser.py`, `normalize.py` | EML/MSG extraction and conservative normalization |
| `src/etrace/case.py` | SQLite evidence, acquisition history, saved runs and verification |
| `src/etrace/correlate.py`, `model.py` | Indexed deterministic rules, parameters and provenance |
| `src/etrace/cli.py` | Case acquisition, analysis, export and server commands |
| `src/etrace/web.py`, `templates/`, `static/` | Local investigator API and browser interface |
| `evaluation/` | Controlled/challenge generator, scoped evaluator, public-corpus preparation, mixing and external threading assessment |

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

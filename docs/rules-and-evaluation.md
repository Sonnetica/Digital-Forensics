# E-Trace rules and evaluation

These are technical details and repeatable experiments. Run commands from the repository root after installing the project. In the examples, `python` means the Python executable from the installed virtual environment. Generated corpora and results go outside the clone. See the [README](../README.md) for a first run and the [sample guide](../samples/README.md) for ready-to-use mail.

## Correlation rules

| Rule | Trigger | Interpretation |
| --- | --- | --- |
| Attachment reuse | Same SHA-256 in at least two distinct logical messages | Equal decoded bytes; direction is not inferred |
| URL reuse | Same conservatively normalized HTTP(S) URL in at least two distinct logical messages | Shared URL; no network lookup |
| Reply | Each In-Reply-To identifier resolves to one unambiguous copy group; otherwise the last References identifier when In-Reply-To is absent | Header-linked relationship; References fallback and multi-parent In-Reply-To are explicitly qualified |
| Inline image reuse | Same inline image SHA-256 (for example a signature logo or embedded QR code) in at least two distinct logical messages | Informational review aid; never a coordination signal and not scored by the evaluator |
| Possible coordination | A pair of distinct logical messages shares enough non-routine categories among attachment hash, URL, normalized subject and claimed origin IP within an inclusive time window | Reviewable cluster of supported pairs; excludes resolved reply components; bulk-mail headers are labelled |

Each result includes rule version, all parameters, source SHA-256 identities,
exact matched values, header/MIME locations, supporting observations and
separate contextual limitations. Ambiguous parents and missing sources appear
as diagnostics; provisional copy groups, reply cycles and time reversals remain visible.
RFC 5322 allows In-Reply-To to list several parents. Each resolvable parent then
receives its own edge, marked `multiple_in_reply_to` in the edge context and in
the run diagnostics, so no single edge is presented as the only parent.

Transport-header variants are grouped as copies when their single Message-ID,
From identity, Date, subject, To/Cc recipients and reply headers agree, plus either the
decoded content digest matches or the only differences are recognised
link-protection rewrites. For that comparison the parser records a fingerprint of
the full decoded content of every part, including HTML markup, attributes,
comments, hidden form fields, and attachment bytes, filenames and dispositions,
with each URL masked and
whitespace collapsed, together with the URLs in order. Two files match only when
the fingerprints are identical and their URLs decode to the same destinations in
the same order. Any other difference, such as a changed account number in the
visible text, a hidden HTML field or a renamed attachment with the same bytes,
keeps the files apart, and a reply to their
shared Message-ID stays an ambiguous parent. A gateway that changes markup as
well as links (for example by adding a warning banner) also leaves its copies
ambiguous.

RFC 6854 permits named groups in From, Sender, Resent-From and Resent-Sender,
including an empty group with no mailbox. E-Trace preserves the group labels and
members separately from the original header. From members remain claimed authors;
Sender is shown separately as the claimed transmitting agent. An empty From group
is displayed without inventing an address or domain. Copies using named From
groups must agree on the group structure and any Sender field. For an empty From
group, the decoded content digest must also match before copies are grouped.

Recognised wrappers are HTTPS links on the provider's own domains only:
Microsoft Defender Safe Links on `safelinks.protection.outlook.com` and
`safelinks.protection.office365.us` (and their subdomains), and Proofpoint URL
Defense v2 (`urldefense.proofpoint.com`) and v3 (`urldefense.com`). A look-alike
host such as `login.safelinks.attacker.example` is never trusted.
`--trusted-wrapper-host` adds a host that uses the Safe Links `url=` format, for
example a test corpus or another gateway; it is recorded with the run and should
normally stay empty. Unwrapping is used only for this comparison; every observed
URL is preserved exactly. Groups whose raw content differs are marked
`copy_content_variation`. Every raw file and SHA-256 remains separate evidence.
Inline MIME resources are recorded as `inline_resource_sha256`, reported as
inline image reuse, and never used as coordination signals.

Two rules keep routine traffic out of coordination without hiding focused or
recurring campaigns:

- Links to the investigated organisation's own domain are ignored once the
  investigator confirms that domain with `--organisation-domain` (repeatable) or
  in the analysis form. E-Trace suggests a domain only when it is, without a tie,
  both the most common recipient domain and the most common sender domain,
  receives at least half of all recipient addresses and sends at least a quarter
  of the messages. It never applies the suggestion on its own, and the form does
  not pre-fill it: who the organisation is depends on how the evidence was
  collected (mail to or from a supplier can otherwise make the supplier look
  internal). An unconfirmed suggestion is reported as an
  `organisation_domain_not_confirmed` diagnostic. `--exclude-url-domain` ignores
  further domains, for example a second company domain.
- A shared value is routine background for a given pair when at least
  `--background-min-outside` occurrences (default 10) fall outside the pair's
  window extended by one window each side, and they outnumber the occurrences
  inside it by `--background-ratio` (default 5). A burst, including each wave of a
  campaign repeated over several days, keeps its signal; a link that appears all
  month does not.

Every link excluded by domain is listed as a `coordination_signal_suppressed`
diagnostic, and every value treated as background is listed as a
`coordination_background_signal` diagnostic with the number of pair comparisons
it affected and its source files. Neither rule changes URL, attachment or
subject observations or the reuse events. A cluster containing files with
List-Unsubscribe, List-Id, Auto-Submitted or Precedence bulk/list/junk headers is
labelled `bulk_mail_indicators` as a review-priority hint. Bulk mail sent on a
single day without those headers, such as payslip notices or an authorised
phishing simulation, is indistinguishable from a burst campaign by these rules and
remains in the results.
Overlapping qualifying pairs are shown as one cluster with each pair's signals
and source observations retained. Cluster membership alone does not imply a
direct relationship between every member.

Subject matching removes leading Re/Fw/Fwd prefixes, folds case and collapses
whitespace. URL matching lowercases scheme/host, converts international hostnames
to IDNA, removes default ports and normalizes an empty path to `/`. Query order,
values, percent encoding, path case and fragments are preserved. IP matching uses
one X-Originating-IP claim or the `from` clause of the oldest Received header;
shared relay addresses are not automatically treated as senders.

Use `--minimum-signals 3` for a stricter coordination hypothesis,
`--background-min-outside 10 --background-ratio 5` to tune the routine-background
test, `--exclude-url-domain company.example` to ignore one more domain and its
subdomains for coordination, or `--timestamp-source received` to use
the top Received header instead of Date.
There is no silent time-source fallback. Parameters are saved with every run.
Unknown times exclude messages only from temporal coordination. Repeating a run
with the same parsed evidence and parameters produces the same identifier.
Each source record includes its Python and, for MSG, extract-msg parser version;
changing parser runtimes can change extraction and therefore run identifiers. New evidence
requires a new analysis; old runs remain available in the export.
For cases ingested with an older parser, analysis and the investigator view
reparse preserved raw bytes in memory. The originally stored parse and its audit
hash remain unchanged and are included in the case export. For those items the
export also contains the derived `analysis_record` used by analysis, and every
run lists the `parser_versions` of the records it analysed.

Resource limits abort analysis without saving partial results. Defaults allow
250,000 distinct coordination candidates, 2,000,000 candidate comparisons and
50,000 events. CLI options `--max-candidates` and `--max-events` change those
limits; the comparison limit is eight times the candidate limit.

## Reproducible evaluation

The primary evaluation question is whether E-Trace correctly reconstructs the
four explicitly defined relationships in the rule table above, with traceable
supporting evidence. Use the simple, medium and complex controlled tiers for
rule-conformance metrics, and the public/mixed workloads for processing coverage
and scoped planted-relationship recovery. The CMU adjacency benchmark and the
intent-labelled challenge ask broader questions and belong in a separate
limitations analysis. Do not pool their scores with the primary rule-conformance
scores or describe rule conformance as proven campaign attribution.

Older packaged corpora were labelled for rule version 1.0.0, which counted inline
logos and routine links in coordination and treated copies as separate messages.
Rule version 1.2.0 replaced the share-based common-artifact filter with the
organisation-domain and routine-background rules; 1.3.0 made the organisation
domain an investigator-confirmed setting and limited link-wrapper recognition to
provider domains; 1.4.0 required the full decoded content, markup included, to
match before files are grouped as copies; 1.4.1 added attachment filenames and
dispositions to that comparison; 1.4.2 adds RFC 6854 From-group identity to copy
matching. Precision and recall from older labels
are not a valid benchmark for the current rules. The evaluator reports
`rule_definition_compatible`; generate fresh controlled tiers for version 1.4.2 and
review any external corpus labels against the new rule table. Corpora that use a
fictional link-protection host need `--trusted-wrapper-host` to reproduce copy
grouping.

The evaluator scores logical messages. Labels and predictions are mapped onto the
run's copy groups, pairs between copies of one message are dropped, and the
result lists each copy group by filename. `file_level_per_rule` repeats the
scoring per preserved file for comparison. If grouping maps a positive and a
negative label onto the same pair, the labels contradict each other and the
evaluator stops with exit status 2, naming the conflicting files, instead of
scoring. The options `--background-min-outside`, `--background-ratio`,
`--organisation-domain`, `--exclude-url-domain` and `--trusted-wrapper-host` are
available for
separately reported sensitivity experiments. Fix parameters before a final run and
report any tuning separately; the defaults were chosen on fictional corpora and
have not been validated on real mailbox collections.

After installing the package, run these commands from the repository root. The
generator and evaluator refuse to write generated data inside the repository.

```powershell
python evaluation/generate.py --output ..\etrace-evaluation\simple --tier simple --seed 47
python evaluation/evaluate.py ..\etrace-evaluation\simple --output ..\etrace-evaluation\simple-results.json
python evaluation/generate.py --output ..\etrace-evaluation\medium --tier medium --seed 47
python evaluation/evaluate.py ..\etrace-evaluation\medium --output ..\etrace-evaluation\medium-results.json
python evaluation/generate.py --output ..\etrace-evaluation\complex --tier complex --seed 47
python evaluation/evaluate.py ..\etrace-evaluation\complex --output ..\etrace-evaluation\complex-results.json
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

### Fictional Halcyon Freight corpora (41 and 355 labelled files)

Two scripts write fictional mail for an invented Singapore freight company. Every
domain ends in `.example`, every public IP is in a documentation range and every
attachment is inert:

| Script | Collection |
| --- | --- |
| `evaluation/build_realistic_corpus.py` | 41 messages: a look-alike-supplier invoice phishing campaign (14-15 Oct 2026) among ordinary mail from several employees' Inbox, Sent Items and Drafts |
| `evaluation/build_complex_corpus.py` | 355 labelled files plus one duplicate acquisition file (174 logical messages) over 2-23 Oct 2026: credential phishing, a stolen-password internal blast, a supplier thread hijack and per-recipient QR-code payroll PDFs, mixed with copies from every mailbox, Safe Links-style rewriting on a fictional host, newsletters, a sanctioned phishing simulation, NDRs, out-of-office replies, ISO-2022-JP and GB2312 mail and scanners without time zones |

Each build writes `conformance/` and `intent/`, each with a `ground_truth.json`.
Labels come from what each scenario writes into each message, never from E-Trace's
parser or rules, and the answer key lists the SHA-256 of every file.

```powershell
python -m pip install -r evaluation\corpus-requirements.txt
python evaluation\build_realistic_corpus.py --output ..\etrace-corpora\realistic
python evaluation\build_complex_corpus.py --output ..\etrace-corpora\complex
```

With Python 3.13 and the pinned libraries, the generated evidence and answer keys
match those inside `samples/realistic-41.zip` and `samples/complex-355.zip` byte for byte. Because
every file hash is in the answer key, comparing the answer keys checks the whole
build (`Get-FileHash` on Windows, `sha256sum` elsewhere):

| Answer key | SHA-256 |
| --- | --- |
| `realistic\conformance\ground_truth.json` | `3d6dec939718b1e01d57e75c3cf4c949241698aa53227ac20adf5b7829829ee5` |
| `realistic\intent\ground_truth.json` | `86dd3000b5de46696533d9128e788eef86906a3d7d680f5b6db6b6147195dab8` |
| `complex\conformance\ground_truth.json` | `15dcfd736ac1987d190d9b7f3a6c57a93626fa635adcbe364ec56f06599cdd05` |
| `complex\intent\ground_truth.json` | `4220fd0bf9bb57f635c1fe51e08519ff2fbdae0db225783431972d6e23c4e2db` |

Python 3.12 folds a few long headers with different whitespace, so 4 of 41 and 6
of 355 messages (and therefore the answer keys) differ in bytes, not in content.
The complex corpus uses a fictional link-protection host; evaluate it with
`--trusted-wrapper-host safelinks.mailprotect.example` and confirm the organisation
with `--organisation-domain halcyon-freight.example`. Both corpora are labelled for
rule version 1.0.0 (see above), and they were written by the same author as the
1.2-1.5 rule refinements, so treat their scores as development checks rather than
independent validation.

### Public email and mixed workloads

The following commands download three pinned February 2003 archives from the
[Apache SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/readme.html).
They contain 3,250 unique messages in total. Archive SHA-256 values are pinned
in `evaluation/corpora.py`. Downloads and generated evidence stay outside Git.
The script reads regular archive members without extracting archive paths or
executing the included `cmds` files. A mismatched cached/downloaded archive fails
verification; it is never silently accepted.

```powershell
python evaluation/corpora.py --cache ..\etrace-evaluation\downloads --output ..\etrace-evaluation\public-1000 --count 1000 --seed 47
python evaluation/evaluate.py ..\etrace-evaluation\public-1000 --output ..\etrace-evaluation\public-results.json
python evaluation/mix.py ..\etrace-evaluation\public-1000 --output ..\etrace-evaluation\mixed-1000 --seed 97
python evaluation/evaluate.py ..\etrace-evaluation\mixed-1000 --output ..\etrace-evaluation\mixed-results.json
```

Selection is a seeded contiguous window of messages sorted by their aware Date
and SHA-256, with unknown dates last. It is independent of E-Trace output and
retains temporal neighbours, but does not guarantee complete conversations.
Use `--count 3250` for the complete pinned population. Evidence gets a `.eml`
filename; its bytes remain identical to the archive member. The manifest records
original member names, archive hashes, selection settings, date coverage and
upstream modifications. This historical collection contains obfuscated addresses
and other edits described by Apache; it is not representative of every modern
email environment. Its spam/ham classes are not E-Trace relationship labels.

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
python evaluation/evaluate.py ..\etrace-evaluation\mixed-1000 --reviews ..\etrace-evaluation\reviewed-results.json --output ..\etrace-evaluation\assessed-results.json
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
related-message retrieval task, not an all-rule E-Trace forensic benchmark.

```powershell
python evaluation/cmu_threads.py --cache ..\etrace-evaluation\downloads --output ..\etrace-evaluation\cmu-test --split test
```

The script evaluates all published test queries against their complete mailbox
subsets. It maps directed reply edges to undirected adjacency for this one task.
It preserves the pinned source archives and writes separately hashed derivatives
with the release's leading blank lines removed. It never invents missing headers.
Results include every query, expected answer, original/derived hash and header
coverage count. The supplied 5,293 files lack Message-ID, In-Reply-To and References;
E-Trace consequently recovers none of the 161 test query-answer relationships
(152 queries). Precision is undefined because it proposes no reply edges.
Keep this result: header-linked reconstruction cannot recover conversations when
those headers are unavailable. This does not implement or reproduce the paper's
ranking algorithm and does not evaluate URL, attachment or campaign detection.

### Challenge cases and claim boundaries

```powershell
python evaluation/generate.py --output ..\etrace-evaluation\challenge --tier challenge --seed 47
python evaluation/evaluate.py ..\etrace-evaluation\challenge --output ..\etrace-evaluation\challenge-results.json
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
tool behaviour to be checked. E-Trace is not NIST certified, and these scenarios
are not NIST datasets. No single dataset here supplies authenticated real-incident
ground truth for all four rules. Observable reuse, header-linked replies and
possible-coordination hypotheses must remain distinct in any presentation.

For additional acquisition validation, the group can record send/reply/forward
and independent-reuse actions through actual mail clients in a controlled mailbox,
export EML/MSG, and retain a separate action log before running E-Trace. Record
client versions, export method, original hashes and missing messages. Such a lab
remains a simulation. No client study or human time-saving result is implied by
the automated evaluations above.


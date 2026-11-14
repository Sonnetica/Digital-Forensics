# E-Trace

E-Trace is a local email investigation prototype. It imports individual EML and MSG files, preserves their bytes and SHA-256 hashes, and shows replies, reused URLs, shared attachments and possible coordination with links back to the original messages. It does not require an email account, API key or cloud service.

## Get started from GitHub

Install **Python 3.12 or later** and Git. In Windows PowerShell, run:

```powershell
git clone https://github.com/Sonnetica/Digital-Forensics.git
cd Digital-Forensics
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m etrace init .\work\demo.db --name "Demo case"
.\.venv\Scripts\python.exe -m etrace ingest .\work\demo.db .\samples\quick-demo
.\.venv\Scripts\python.exe -m etrace analyze .\work\demo.db
.\.venv\Scripts\python.exe -m etrace serve .\work\demo.db
```

Open <http://127.0.0.1:8765> in a browser. Use **Timeline**, **Relationship graph**, **Evidence** and **Diagnostics** to inspect the result. Stop the server with `Ctrl+C`. On later visits, run only the `serve` command for the existing case. Case creation refuses to overwrite an existing database.

If the repository was downloaded as a ZIP from GitHub, extract it and run the commands from the extracted `Digital-Forensics` folder, starting at `python -m venv .venv`.

On macOS or Linux, use `python3 -m venv .venv`, then replace `.\.venv\Scripts\python.exe` with `./.venv/bin/python` in the commands above. Use forward slashes in paths.

## Sample email collections

| Location | Purpose | Size |
| --- | --- | --- |
| [`samples/quick-demo/`](samples/quick-demo/README.md) | Ready-to-run fictional office email walkthrough | 14 EML files |
| [`samples/realistic-41.zip`](samples/realistic-41.zip) | Fictional freight company mail with an invoice phishing scenario and ordinary messages | 41 EML files per labelled set |
| [`samples/complex-355.zip`](samples/complex-355.zip) | Larger overlapping mailboxes with several attack scenarios and routine traffic | 355 labelled files plus one duplicate acquisition file per set, representing 174 logical messages |

The two archives must be extracted before ingestion. They contain `conformance/` and `intent/` copies of the same mail, answer keys and older evaluation results. Ingest **one** email folder, not the archive root. Their answer keys were written for an earlier rule definition, so they are useful for demonstration but are not the source of current accuracy figures. [The sample guide](samples/README.md) gives exact extraction and run commands.

The separate `evaluation/` generators create the 14-, 77- and 269-message **controlled test tiers** used for rule-conformance measurements. Those are distinct from the three demonstration collections above. [Rules and evaluation details](docs/rules-and-evaluation.md) explain the labels and their limits.

## Use E-Trace with your own files

Start a fresh case and ingest an exported `.eml` or `.msg` file, or a directory containing those files:

```powershell
.\.venv\Scripts\python.exe -m etrace init .\work\my-case.db --name "My case"
.\.venv\Scripts\python.exe -m etrace ingest .\work\my-case.db C:\path\to\exported-mail
.\.venv\Scripts\python.exe -m etrace analyze .\work\my-case.db
.\.venv\Scripts\python.exe -m etrace verify .\work\my-case.db
.\.venv\Scripts\python.exe -m etrace serve .\work\my-case.db
```

Replace `C:\path\to\exported-mail` with your actual folder. E-Trace recursively reads EML and MSG files from a directory. Keep real evidence and shared case databases outside the clone. The local `work/` folder is ignored by Git and is intended only for trials.

To hand off a case, export JSON or a bundle. The bundle contains the original files and a manifest, and the importer checks its internal consistency:

```powershell
.\.venv\Scripts\python.exe -m etrace export .\work\demo.db --output .\work\demo.json
.\.venv\Scripts\python.exe -m etrace export .\work\demo.db --bundle --output .\work\demo-bundle.zip
.\.venv\Scripts\python.exe -m etrace import-bundle .\work\demo-bundle.zip --case .\work\demo-rebuilt.db
```

The [user manual](docs/user-manual.md) explains the settings, web interface, exports, verification and common errors. Equal hashes and rule matches are observations for an investigator to review. They do not establish sender identity or malicious intent by themselves.

## Run the tests

After installation, from the repository root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The automated tests create their own temporary EML data and use the MSG fixtures in `tests/fixtures/msg/`. Generated evaluation corpora are created separately and must be written outside the repository. See [rules and evaluation](docs/rules-and-evaluation.md) for reproduction commands. `requirements.txt` pins the submitted runtime dependency set. The package definition and command entry point are in `pyproject.toml`.

## Repository layout

| Folder | Contents |
| --- | --- |
| `src/etrace/` | Application, CLI, parser, correlation rules, case storage and local web interface |
| `samples/` | Fictional email collections for trying the interface |
| `tests/` | Automated regression tests and MSG test fixtures |
| `evaluation/` | Corpus generators, evaluator and public-data preparation scripts |
| `docs/` | Detailed user manual, rules and evaluation notes |
| `archive/patches/` | Historical development patches, not needed to run E-Trace |

Local environments, case databases, generated data, reports and build products are excluded from Git by `.gitignore`.

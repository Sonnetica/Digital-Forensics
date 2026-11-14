# Fictional email case

For setup instructions and larger samples, see the [sample guide](../README.md).

These 14 EML files form a fictional office email collection from 2 October 2026.
Names, domains, IP addresses, and attachments are invented. The `.example`
domains and documentation IP ranges do not identify real infrastructure.

| Files | What to inspect |
| --- | --- |
| `01`–`03` | Three supplier payment messages share a decoded attachment, normalized URL, subject, and claimed origin IP. The third uses a different sender domain; inspect that context before interpreting the possible-coordination hypotheses. The second has the URL in an HTML link, and the third varies URL capitalization and the default HTTPS port. |
| `04` | A question reuses the supplier URL but lacks a Date header. It contributes to URL reuse, while Date-based coordination cannot use its time. |
| `05`–`07` | An access-review reply chain quotes the same URL. Message `07` has References but no In-Reply-To, so its parent is a qualified fallback. Resolved replies are excluded from ordinary coordination hypotheses. |
| `08`–`09` | Two unrelated messages share only a browser advisory URL. |
| `10`–`11` | Two visitor messages reuse the same attachment but have different subjects and claimed origin IPs. |
| `12` | A reply points to a message absent from the collection. Check the missing-parent diagnostic. |
| `13`–`14` | Ordinary background messages with no planted relationship. |

With the default analysis settings, this collection produces 2 attachment-reuse
groups, 3 URL-reuse groups, 2 reply edges, and 3 possible-coordination pair
hypotheses. The latter are review prompts, not proof of a shared plan or malicious
intent.

Use a new case database when trying this revised demo. Ingesting into an existing
case retains all previously acquired evidence, including older demo files.
The messages can be regenerated into an empty folder with
`python evaluation/demo.py --output <empty-folder>` from the project root.

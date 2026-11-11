# Outlook MSG fixtures

`other.msg` and `outer.msg` are real Outlook items copied unchanged from the test
suite of [msg_parser](https://pypi.org/project/msg-parser/) 1.2.0
(`tests/files/`), BSD-licensed; see `LICENSE-msg_parser.txt`.

| File | Code page | HTML stream | Body source |
| --- | --- | --- | --- |
| `other.msg` | 936 (GBK) | none | HTML encapsulated in compressed RTF; Chinese text |
| `outer.msg` | 20127 (ASCII) | none | HTML encapsulated in compressed RTF; transport headers absent |

Both contain an embedded Outlook item as an attachment.

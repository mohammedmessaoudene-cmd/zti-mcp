# Third-party material and exclusions

This inventory records the boundaries of the prepared public package. It is not a claim that the project owns external standards, dependencies or referenced research.

| Material | Treatment in this package |
| --- | --- |
| IETF Trust notices and standard boilerplate in the formatted candidate | Preserved in the specification artifacts. Their applicable terms remain in force. See the [corrected IETF TLP 5.0](https://trustee.ietf.org/documents/trust-legal-provisions/tlp-5/) and [RFC 5378](https://www.rfc-editor.org/rfc/rfc5378.html). The project grants Apache-2.0 only for its author's original contributions. |
| Bibliographic entries, standard names, cited identifiers and links | Retain their attribution and context. The upstream RFCs, specifications and papers are not relicensed by this project. The published draft may contain rendered reference information; separate upstream BibXML and grammar files are not bundled. |
| Apache-2.0 legal text | The unmodified official English text is in `LICENSE`, obtained from [Apache](https://www.apache.org/licenses/LICENSE-2.0.txt). Do not replace its appendix placeholders with a claim of ownership over the license text. The project's attribution appears in `NOTICE` and `LICENSE_SCOPE.md`. |
| CC BY 4.0 legal text | The unmodified official English text is in `LICENSES/CC-BY-4.0.txt`, obtained from [Creative Commons](https://creativecommons.org/licenses/by/4.0/legalcode.txt). Its own license-text notice remains intact. |
| Python, SQLite, `cryptography` and separately retrieved GitHub Actions | These are runtime or workflow dependencies, not vendored source code in this package. They retain their own licenses. `requirements.txt` and workflow references do not replace upstream terms. A future redistribution of those components must inventory and preserve the licenses and notices of the components actually included. |
| Original reference software, schemas and laboratory vectors | Licensed as mapped in `LICENSE_SCOPE.md`. The public P-256 test key and fictional JWTs have the provenance and limitations described in the examples; they are not production credentials. |

No upstream formatting grammar, virtual environment, dependency wheel, toolchain cache, full third-party article, private inbox export or unrelated project repository is included in this package. The downloaded upstream formatting resources used during preparation remain outside the public subset.

Organization names, project names and standards identifiers are descriptive references. No affiliation or endorsement is claimed, and no general trademark license is granted.

Future additions must be checked on their own provenance. An existing repository-level license is not a grant over newly copied third-party material.

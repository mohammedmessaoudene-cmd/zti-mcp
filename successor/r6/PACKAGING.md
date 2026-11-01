# R6 intentional public packaging snapshot

The root public manifest is intentionally regenerated for the separately named
R6 successor. This adds the installed provider/consumer/client sources, frozen
contract, locked dependencies, collector, separate data reader, bootstrap,
allowlist exporter and hosted workflow. README and license/dependency notices
describe this added scope; the root verifier recognizes its text formats.

This packaging change does not replace earlier evidence. The 101 files listed
in PRESERVED_BASELINE.json must remain byte-identical, including the entire
historical integration tree and its manifest. Only the five existing paths
listed as permitted in that baseline record may change. Verification checks
the 14 sealed R6 files separately. R4 and R5 release tags remain historical.

The manifest records the new source snapshot after review; it is not evidence
of execution or authenticity. CI verifies it and never regenerates it. Generated
campaigns, private keys/settings, correspondence, browser/director instructions,
toolchain caches and review workspaces stay outside the public source tree.
Release evidence and review receipts identify the exact qualified commits.

The frozen npm lock originally uses CRLF. A local .gitattributes rule preserves
its exact bytes on both platforms; its frozen hash is unchanged. Other new text
files use LF. The staged Git blobs are compared with the verified file bytes
before the candidate is committed.

# R6 implementation corrections before qualification

Development collections are retained separately from clean-commit qualification.
The original complete development collection was rejected for packaging and
injected-witness defects; later code does not relabel its files as passing.
The reader corrections and code seal are in
[ORACLE_IMPLEMENTATION_ERRATA.json](ORACLE_IMPLEMENTATION_ERRATA.json) and
[oracle-implementation-seal.json](oracle-implementation-seal.json).

| Boundary | Correction and bounded evidence |
| --- | --- |
| Configured tenant for lookup/cancellation | The operation helper refuses another tenant before its SELECT. A retained local SDK development diagnostic established the original gap. A fresh installed corrected provider passed a unit regression requiring refusal with zero database calls. The frozen campaign uses one configured laboratory tenant; it does not establish general multi-tenant deployment security. |
| Received permit verification | A TypeScript verification failure could retain a result alongside a local error. Corrected bridges remove that result. A controlled SDK diagnostic retains the old TypeScript failure and corrected Python/TypeScript responses. Python cleanup is symmetric hardening. |
| SQLite capture lifetime | Readers and backup handles close explicitly. Closed snapshots and stopped-writer data use immutable reads. Quiescence preserves tables and avoids volatile sidecars in stable inventories. A fresh nominal plus six data-only copies passed semantic and portable-component readback. |
| Injected callback mutation | M02 changes alpha to the frozen bravo witness. The earlier alpha! result remains a failed witness. New targeted data contains the actual bravo business row and is rejected by the ordinary binding check. |
| Distributions before execution | Wheels and npm archives are inspected against verified source before own-package installation/import or client execution. Altered-source, path-control, notice and entry-point probes are rejected. Runtime observations link the actual inspection, build and distribution hashes. |
| Upstream entry identities | Selected SDK entry hashes derive from locked, hash-verified upstream archives. DEPENDENCY_ENTRY_POINTS.json covers three Python entries and the TypeScript client entry. It does not hash every dependency file or attest to an outside runner. |
| POSIX virtual-environment launcher | Keep the executable's absolute invocation path. Resolving its symlink starts the base interpreter and loses the installed wheels. The first Ubuntu head run stopped at client identity before any scenario; its failure is retained and the corrected head requires fresh qualification. |
| Hosted checkout ancestry | Both R6 workflow checkouts fetch full history. A shallow build recorded no parent while the native checkout recorded the real parent, so the unchanged attribution gate rejected the second head despite passing semantic cases. That failed run is retained. A new exact head and distribution set require all three qualifications; no old result is relabeled. |

These finite checks and team reviews are AI-assisted. Release evidence must
identify the actual clean head, merge commit, installed artifacts, native/hosted
runs and completed handoffs before claiming qualification. Application plugins,
launch configuration and the OS context remain trusted.

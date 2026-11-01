# Frozen R6 distribution procedure

Original technical execution specification, Apache-2.0.

The provider and the distinct consumer are built as two Python wheels from
byte-verified source staging. They are installed without editable mode or
PYTHONPATH in a fresh Python 3.12 virtual environment **outside the checkout**.
The consumer imports the installed public ToolSpec API. Its own table and
effect are observed. Source copies or a patched authority core do not satisfy
this requirement.

The TypeScript distribution is a real npm-created `.tgz` application archive,
with original `.ts` sources and its frozen runtime lock. It is not a compiled
JavaScript distribution. Node 24.22.2 executes supported erasable TypeScript
syntax without static type checking. No type-checking result is claimed.

The exact qualification procedure is:

1. Build the `.tgz` with `npm pack --ignore-scripts` from verified staged source.
2. Safely extract it into a fresh directory outside both the checkout and every
   `node_modules` directory. Reject links, traversal and duplicate members.
3. Copy `runtime-lock.json` to `package-lock.json` unchanged. Hash the source,
   extracted lock and copied lock and require byte equality.
4. Run `npm ci --ignore-scripts --no-audit --no-fund` there, using a fresh local
   cache. Retain exact dependency versions, registry integrity and exit status.
5. Launch that extracted `client.ts` with exactly Node 24.22.2, not a source
   entry from the checkout. Record the actual loaded entry/module paths and
   hashes as private provenance; publish portable source identities.
6. Exercise the real MCP SDK, explicit active discovery, custom extension and
   guarded tool calls. Apply the same procedure on Windows and Ubuntu.

The launcher allocates retained fresh runtime directories outside the checkout
even when evidence output is `work/r6-new`. An explicit fresh `--runtime-dir`
can name that outside directory. Failure evidence and runtime directories are
retained. No global runtime or dependency upgrade is performed.

On the actual merged commit M, build the distributions once. BUILD.json records
M, its tree, source identities and artifact hashes. The Windows/Ubuntu hosted
jobs and native Windows campaign install those same bytes. Prebuilt
distributions from a different commit are rejected even if its tree happens
to equal M's tree. The final prerelease publishes these qualified bytes.

The data-only audit mode runs the trusted checkout's audit reader, rather than
scripts or executables from an evidence archive. A real SQLite backup is the
checkpoint source; JSON exports are independently compared auxiliary data.

## Packaging notice erratum before qualification

FREEZE-003 adds NOTICE to the npm archive file list. The original Apache-2.0
LICENSE and project NOTICE must be included byte-identically to verified source.
This corrects an observed npm packaging omission; no action, golden, expected
state, diagnostic, dependency version or runtime-lock byte changes. npm pack
creates the final archive directly; no archive is rewritten after packing.
Both Python wheels and the client archive are inspected against the verified
source manifest before own package installation, imports or client execution.

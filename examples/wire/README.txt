ZTI-MCP 0.1 — OFFLINE DOCUMENTARY MCP MESSAGE BODIES

STATUS AND PROVENANCE
Every request and response in this directory was assembled offline. No MCP peer,
SDK, server or transport exchanged these messages. These files are examples of
the proposed binding, not network traces, interoperability results, authenticated
receipts or evidence of deployment. org.example/zti-mcp is reserved documentation
space only; a production deployment must agree on its own controlled EXT_ID.

The root mandate, child mandate and ICT strings are copied literally from the
three existing public laboratory .jwt files in the parent directory. They have
real ES256 signatures from the C02 fixture; no signature was regenerated here.
Their deliberately public laboratory key is not deployment material. Fixed JWT
times belong to that fixture and do not assert current validity at wall-clock time.

The tools/call result, lookup result and consumed-cancellation result embed the
unchanged parent receipt.json. That receipt is an OFFLINE DOCUMENTARY PROJECTION
of the persisted C02 SQLite effect and COMMITTED audit row. It was not delivered
by an authenticated MCP endpoint. The wire wrappers do not strengthen its evidence.

Register/reserve responses, discovery, cancellation, lookup, revocation and denial
wrappers are illustrative. In particular, register revision 0, reserve revision 1,
and revoke epoch 1 / revision 3 are chosen values illustrating the contract;
they are not captured control API events. The copied receipt revision 2 comes
from the C02 audit projection. No event ordering or network trace is claimed by
the numbered filenames. MANIFEST.json describes provenance for each pair.

CONTENTS
01: server/discover request/result with protocol version, extensions, tools,
    supportedVersions and required cache metadata (ttlMs 0, cacheScope private).
02: root registration with the literal signed root mandate.
03: attenuated child registration with the literal signed child mandate.
04: reserve the exact exported action; return the literal exported ICT.
05: protected tools/call with final arguments and ICT in params._meta[EXT_ID].
    The result carries the copied receipt in result._meta[EXT_ID]. content is an
    empty array: no unavailable business output has been invented.
06: authorized lookup with the unchanged COMMITTED receipt.
07: cancel after consumption; returns COMMITTED unchanged and does not release
    authority. ALREADY_CONSUMED is the alternative allowed by the draft.
08: illustrative root revocation acknowledgement; it does not undo C02's effect.
09: independent illustrative -31001 NOT_AUTHORIZED refusal of revocation.

AUTHENTICATION AND TRANSPORT
The assumed authenticated actor for each pair is stated in MANIFEST.json.
clientInfo/serverInfo identify fictional software only. They are not proof of
the actor's identity or authority. Public possession of a signed mandate is not
permission to register, look up, cancel or revoke it.

These are JSON-RPC message bodies, not complete HTTP captures. Streamable HTTP
would additionally require the separate Authorization credential and the matching
MCP-Protocol-Version, Mcp-Method, and Mcp-Name for tools/call headers. No credential
or successful authentication exchange is fabricated. A stdio integration would
need its own authenticated local invocation identity and protected authority path.

SCHEMA AND CHECK LIMITS
../../schema/zti-control-0.1.schema.json provides method-specific $defs for control
params/results, receipt, -31001 error data/object, action metadata and capability.
Use the matching definition for the selected method. The top-level anyOf does not
perform dispatch and deliberately tolerates overlapping structural shapes.

The schema keeps standard MCP metadata open. Its configured EXT_ID cannot be
hardcoded to org.example for production: an implementation must separately check
that exact configured capability entry against $defs/extensionCapability.
JSON Schema cannot establish authenticated rights, actual token usability, signature
validity, live state, cross-field equality, clock order or AtomicEffect coupling.
Returning usable RESERVED authority requires its ICT; an unconsumed stored state
alone is not a promise that a token can still be used. No token refresh is defined.

The performed checks cover JSON syntax without duplicate members, local $ref
resolution, exact required field sets for these examples, per-request metadata,
matching JSON-RPC IDs, literal JWT copies and consistency with the exported action,
decoded claims and receipt. No complete JSON Schema engine was installed or run.
No engine, concurrency or provider-effect experiment was added.

See ../../review/WIRE_EXAMPLES_REVIEW_R4.json for the machine-readable check record.
The original draft, executable core, signed examples and existing schemas were
not modified by this assembly.

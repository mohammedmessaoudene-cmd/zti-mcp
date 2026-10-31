# R5 provider database mapping

This mapping is fixed before the first integration campaign. The exact DDL is
`SCHEMA` in `core.py`. These are SQLite base tables, not provider summary views.
The independent reader uses a read-only connection and imports no provider code.

| Table | Key | Relevant columns |
| --- | --- | --- |
| `roots` | `(tenant_id, root_mandate_id)` | `policy_json`, `active` (0/1), `authority_epoch`, `state_revision` |
| `mandates` | `(tenant_id, mandate_id)` | `root_mandate_id`, `parent_id`, `parent_hash`, `delegatee_id`, `body_json`, `mandate_hash`, `jws`, `revoked` (0/1) |
| `reservations` | `(tenant_id, root_mandate_id, operation_id)` | `reservation_id`, `mandate_id`, `subject`, `audience`, `action_json`, `action_hash`, `cost_json`, `facts_json`, `state`, `ict_claims_json`, `ict_jws` |
| `business_effects` | `(tenant_id, root_mandate_id, operation_id)` | `reservation_id`, `mandate_id`, `action_json`, `arguments_json`, `action_hash`, `cost_json`, `facts_json`, `provider_pid` |
| `receipts` | `(tenant_id, root_mandate_id, operation_id)` | `reservation_id`, exact `receipt_json`, consumption `state_revision` |
| `transitions` | `(tenant_id, root_mandate_id, state_revision)` | `event`, nullable `operation_id`, nullable `reservation_id`, `provider_pid`, `detail_json` |

`reservations`, `business_effects` and `receipts` also enforce uniqueness of
`(tenant_id, root_mandate_id, reservation_id)`. Identity fields are SQLite TEXT;
root counters are canonical uint64 decimal TEXT. JSON columns contain the
documented canonical subset as UTF-8 text. Process IDs are INTEGER. No separate
cached totals are used: reservations in COMMITTED/COMPLETED/UNKNOWN contribute
to D, RESERVED contributes to R, and the remaining declared states contribute
to neither. The reader must reject an unrecognized state.

The reader's base-table query surface is deliberately plain:

```sql
SELECT * FROM roots;
SELECT * FROM mandates;
SELECT * FROM reservations;
SELECT * FROM business_effects;
SELECT * FROM receipts;
SELECT * FROM transitions;
```

Readers sort numeric counter values after parsing canonical decimal strings,
rather than lexicographically ordering TEXT. Each root has a contiguous revision
sequence starting at 1. Event names are ROOT_REGISTERED, CHILD_REGISTERED,
RESERVED, COMMITTED, CANCELLED and REVOKED. REVOKED detail_json contains the
specific mandate_id. A root revocation also changes roots.active to 0; a child
revocation leaves that root-active flag unchanged. Every new revocation advances
authority_epoch once; ordinary transitions never do. Idempotent retries and
refusals produce no transition or revision increment.

For a normal effect, one BEGIN IMMEDIATE transaction reloads authority/time,
verifies final action, consumes RESERVED, inserts the actual business row,
advances the root revision, persists the exact full receipt and transition,
then commits before success is written to stdio. The receipt is immutable.
Subsequent lookup may report a later outer root revision without changing it.
The effect row stores the same final action and its exact arguments, with the
PID of the provider process which inserted it.

Each connection uses `busy_timeout=30000` and `synchronous=FULL`; initialization
sets `journal_mode=WAL`. Startup uses CREATE TABLE IF NOT EXISTS and preserves
an existing database for restart scenarios. The launcher starts the admin
endpoint first. This is a local process-crash demonstration, not a power-loss or
corruption proof. Test clock input is a trusted startup-configured path whose
UTF-8 content is a canonical decimal integer, read inside authorization
transactions. It is not a public MCP clock-control method.

M01 and M02 are explicit startup-only deliberately broken fixtures, never
selected by arguments. M01 retrieves the caller's stored token when ICT was
omitted. M02 validates and closes an earlier transaction, pauses outside the
write lock, then stages an effect from the cached authorization in a later
transaction without current revalidation. The independent reader must observe
their violations and the unchanged normal oracle must reject them.

## Source provenance

`core.py` is a separate successor implementation. Its transaction/gate concepts
derive from the preserved R4 reference, but its signed import, schema, revisions,
durable receipts and retry/cancellation mapping are new R5 code. `crypto.py`
adapts the small canonical-subset, uint64 and ES256 helper pattern from
`reference/authority.py` at commit
`fc350b219f4f8ed452a6e59784ea69ea68fbaf07` (source SHA-256
`0489bf76fc482558051e65ac3517aab9189109bc3d1647724e54211b623aa11f`).
Its constants are the R5 fixture identities, errors are the proposed wire
vocabulary, and signature verification may be separated from present-time
validation solely for immutable history access. The original R4 source and its
oracles remain unchanged. The scalar-1 private key is intentionally public
laboratory material, unsuitable for deployment.

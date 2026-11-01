# R6 public integration and wire API

Original technical execution specification, Apache-2.0.

## Public integration API

```python
@dataclass(frozen=True)
class TableSpec:
    name: str
    columns: Mapping[str, str]  # ordered column names -> 'TEXT' or 'INTEGER'; NOT NULL
    # core adds row_id INTEGER PRIMARY KEY AUTOINCREMENT; no UNIQUE operation_id

@dataclass(frozen=True)
class Footprint:
    costs: Mapping[str, Mapping[str, str]]
    facts: Sequence[str]

@dataclass(frozen=True)
class ExecutionContext:
    tenant_id: str
    root_mandate_id: str
    mandate_id: str
    operation_id: str
    reservation_id: str
    action_hash: str
    provider_pid: int

@dataclass(frozen=True)
class ToolSpec:
    name: str
    revision: str
    input_schema: Mapping
    tables: Sequence[TableSpec]
    validate: Callable[[Mapping], None]  # no coercion; throws ValueError on invalid args
    footprint: Callable[[Mapping], Footprint]  # deterministic trusted footprint
    apply: Callable[[Writer, ExecutionContext, Mapping], Mapping]

class Writer:
    def insert(self, table: str, values: Mapping[str, str | int]) -> int: ...
```

`Writer` owns no public connection/control method; insert accepts only this tool's declared table and exact columns with validated types, parameterized SQL, and returns row_id. Tools are loaded from a trusted startup module:function returning ToolSpec objects. No plugin import/name is selected by request. Schema initialization is provider-owned, before calls, from the bounded TableSpec definitions. Names use `[a-z][a-z0-9_]{0,62}` and must not collide with any authority/audit table. Callback receives deep read-only arguments (dict->MappingProxyType,list->tuple), frozen context, and cannot mutate shared authorization inputs. Result canonicalization must finish before commit. Python plugin remains trusted code, not a hostile-code sandbox.

Demo supplied by B: name `demo.add_record`, revision `1`, args exactly `quantity` canonical uint64 string, `label` valid Unicode UTF8<=256 bytes, `tags` list <=8 unique strings in red/blue/neutral; facts sorted tags. Costs retain existing vector shape: `{'ops':{'unit':'operation','amount':quantity},'bytes':{'unit':'byte','amount':str(len(label.encode('utf-8')))}}`. Here ops amount is requested quantity, not a constant 1. Suggested `demo_records` columns: tenant_id,root_mandate_id,mandate_id,operation_id,reservation_id,quantity,label,tags_json,action_hash TEXT and provider_pid INTEGER; row_id generated, operation_id deliberately NOT UNIQUE.

## Wire and keys

The official Python SDK's public MCPServer.list_tools method is overridden by
a small subclass to return Tool objects from configured ToolSpec input schemas.
The extension's public intercept_tool_call hook owns the actual guarded effect
path. No SDK private field, monkeypatch or generated signature is used. I01
checks tools/list over the real SDK and verifies the external tool schema before
calling it.

Profile `zti-mcp/0.1`, extension `org.example/zti-mcp`, MCP2026-07-28. Capability exactly `{'revision':'0.1','profile':'zti-mcp/0.1','mode':'current-online','effect_coupling':'required'}`. Methods `.register{mandate}`, `.reserve{action}`, `.lookup{tenant_id,root_mandate_id,operation_id}`, `.cancel{same + reservation_id}`, `.revoke{tenant_id,root_mandate_id,mandate_id}`. tools/call `_meta[EXT_ID]` exactly `{revision:'0.1',operation_id,ict}`. Closed action fields: profile,tenant_id,root_mandate_id,mandate_id,operation_id,executor_id,resource_id,method,tool_name,tool_revision,arguments. All identifiers checked as nonempty strings before membership/use; no unknown-field fallthrough. Action hash SHA256 of ASCII-key, valid-Unicode, safe-int, no-float canonical JSON UTF8.

Root/child signed body fields unchanged from R5: profile,tenant_id,principal_id,root_mandate_id,mandate_id,parent_id,parent_hash,correlation_id,delegatee_id,valid_from,valid_until,constraints,root_policy,policy_hash. Constraints closed allowed_executors/resources/methods/tools plus action_caps; policy budgets+forbidden_sets. Dates type int (never bool), safe range0<=from<until<=2^53-1. Common JWS exact claims iss,sub,aud,iat,nbf,exp,jti plus zti_mandate or zti. Header exactly alg ES256,typ role-specific,kid configured role-specific. Mandate nbf/exp equal body dates; sub=delegatee_id; aud=registry_id; iss=mandate_issuer. ICT sub=fixed launch principal,aud=executor_id,iss=permit_issuer, lifetime<=60 and bounded by lineage. ICT zti fields exactly existing R5 profile/mode/tenant/root/mandate/hash/correlation/op/reservation/actionhash/policyhash/epoch/cost_bounds/facts.

Launch JSON required keys: db_path,principal,role(admin|agent|intruder),tenant_id,admin_principal,registry_id,executor_id,resource_id,mandate_issuer,mandate_kid,mandate_public_key_path,permit_issuer,permit_kid,permit_private_key_path,clock_path,tools(list module:function),control_dir(optional),mutant(optional M02..M06). Provider loads only KI.public and KP.private; derive KP.public. Reject same public key material or same kid/issuer role combination at startup. No import of issuer signer. PEM P256 public SPKI and private PKCS8 accepted. Keys generated externally. Private paths never emitted in protocol or public evidence. B/root may request compact defaults before freeze, but explicit fixture values preferred.

Custom domain refusal wire exactly code-31001,message 'ZTI-MCP authorization refused',data{profile,reason,status}; status REFUSED or SUSPENDED, no private details. Reason vocabulary retains R5 INVALID_TOKEN,PROFILE_UNSUPPORTED,BINDING_MISMATCH,CONSTRAINT_VIOLATION,CUMULATIVE_VIOLATION,OPERATION_CONFLICT,NOT_AUTHORIZED,NOT_FOUND,REVOKED,EXPIRED,AUTHORITY_UNAVAILABLE. Callback exception maps EXECUTION_FAILED/REFUSED after rollback. SDK model-shape errors remain standard SDK -32602 and are separately classified, never successful semantic policy refusals.

## Database schema

All existing names below are new R6 tables created by this package, not reuse of an R5 DB. PK tuple convention unchanged:

```
roots(tenant_id,root_mandate_id,policy_json,active INTEGER,authority_epoch,state_revision)
  PK(tenant_id,root_mandate_id)
mandates(tenant_id,mandate_id,root_mandate_id,parent_id NULL,parent_hash NULL,
 delegatee_id,body_json,mandate_hash,jws,revoked INTEGER)
  PK(tenant_id,mandate_id)
reservations(tenant_id,root_mandate_id,operation_id,reservation_id,mandate_id,
 subject,audience,action_json,action_hash,cost_json,facts_json,state,ict_claims_json,ict_jws)
  PK(tenant_id,root_mandate_id,operation_id), UNIQUE(tenant_id,root_mandate_id,reservation_id)
business_effects(tenant_id,root_mandate_id,operation_id,reservation_id,mandate_id,
 action_json,arguments_json,action_hash,cost_json,facts_json,provider_pid INTEGER,result_json)
  PK(tenant_id,root_mandate_id,operation_id), UNIQUE(tenant_id,root_mandate_id,reservation_id)
receipts(tenant_id,root_mandate_id,operation_id,reservation_id,receipt_json,state_revision)
  PK(tenant_id,root_mandate_id,operation_id), UNIQUE(tenant_id,root_mandate_id,reservation_id)
transitions(tenant_id,root_mandate_id,state_revision,event,operation_id NULL,
 reservation_id NULL,provider_pid INTEGER,detail_json)
  PK(tenant_id,root_mandate_id,state_revision)
```

All unspecified columns TEXT NOT NULL. active/revoked INTEGER NOT NULL. Epoch/revision uint64 canonical strings. Events ROOT_REGISTERED(root revision1),CHILD_REGISTERED,RESERVED,COMMITTED,CANCELLED,REVOKED. Revocation increments epoch exactly once, detail_json includes mandate_id. Every state-changing transition increments contiguous revision once. No-op/retry/lookup leave revision unchanged. Receipt same R5 closed shape: profile,tenant_id,root_mandate_id,mandate_id,operation_id,reservation_id,action_hash,effect_boundary='resource-mutation',status='COMMITTED',state_revision. Business callback result is retained in audit result_json. tools/call structuredContent contains receipt and result; profile metadata carries the unchanged receipt. No receipt fields are added.

## Transactions, fault hooks and mutants

Normal execute: `call:before_transaction` -> BEGIN IMMEDIATE -> current signature/lineage/time/epoch/binding/state/accounting -> `call:validated` -> callback -> `call:business_inserted` -> consumption+audit+receipt+revision -> `call:staged_before_commit` -> COMMIT -> `call:commit` -> `call:after_commit` -> response. Hooks synchronous `hook(event,detail)` detail includes operation_id/reservation_id/provider_pid as available. Barrier/pause/crash selected only in startup-controlled rule file. BEFORE_TRANSACTION permits cross-process starting barrier; no sleeping establishes order. Event emission after actual INSERT is provider responsibility, including rowid evidence when possible. Callback is invoked once only for unused valid reservation.

M02: after validation, before apply, transform label deterministically; emit mutant:M02 with original/final hashes. I01 reaches it and consumer-row oracle must detect mutation.
M03: actual business INSERT committed on a separate intentionally broken path before charge/receipt, then call:business_inserted fault raises/crashes -> orphan durable. Emit mutant:M03 before faulty durable commit and exact after-commit event. Never treat operational error alone as witness.
M04: existing consumed retry re-invokes callback and commits second consumer row; no uniqueness on consumer operation_id; emit mutant:M04 only on actual branch.
M05: completed authority validation in earlier transaction -> call:validation_transaction_finished -> call:pause_after_validation (blocking) -> revoke commits -> release -> separate effect tx uses cached validation deliberately; emit mutant:M05. Must not hold authority transaction across pause.
M06: gate omits other RESERVED facts while retaining consumed facts; emit mutant:M06 with omitted reservations. Admission checkpoint, not effects, is the required witness.

Historical consumed retry verifies token signature/context and exact action but need not require current time/lineage to retrieve its immutable receipt; it never creates new effect. Unused stale/expired/revoked permits cannot execute; cancellation may safely release RESERVED state. No timeout/socket-close refund. SQLite writer serialization is not a claim that requests cannot be concurrent.

## Preexecution resolutions

FREEZE-002 adds discriminating announced-key role tests, isolated JWS context
faults, raw duplicated-iss verification, execution-channel identity and
historical tools/call after revocation. C01-C04/I12 use the trusted
reserve:before_transaction barrier on two actual provider processes before any
release. These are fixture and evidence obligations; no business parameter
selects a hook. DISTRIBUTION.md defines the native TypeScript archive adaptation.

All JWS integer dates satisfy 0 <= iat <= nbf < exp <= 9007199254740991.
Default mandate iat equals valid_from (1999999940), not the later fixture clock.
Date diagnostics override iat/nbf/exp with their explicitly specified integers.

MANDATE_CONFLICT is retained for a duplicate mandate identifier with a different
signed body. A signed root imported by the configured admin establishes its
nonempty principal_id; child lineage preserves that value. The fixture owner
identity is urn:r6:owner, distinct from the configured admin/executor principals.

Initial authority epoch is 0, root revision is 1. Bootstrap root plus A and B is revision3. Callback exceptions are EXECUTION_FAILED/REFUSED after rollback. Tool result metadata contains the unchanged receipt; structuredContent is {receipt,result}. Malformed bound identifier types are BINDING_MISMATCH. Invalid canonical-domain values are rejected before tool validation; valid JSON with invalid demo schema/quantity is CONSTRAINT_VIOLATION. The authoritative hook after the consumer INSERT is call:business_inserted. Consumed reserve returns COMMITTED and the same receipt without issuing a new ICT.

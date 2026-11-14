# R7 bounded execution and evidence contract

Original technical specification, Apache-2.0. Prepared with AI assistance. This contract describes the finite R7 laboratory; it does not extend the guarantees of MCP or requalify historical R6 results.

## Experimental unit and authority

The complete comparison contains exactly 12 authored templates, two variants each, giving 24 paired cases and 48 controller executions. The paired arms receive identical public setup, structured permissions, task obligations, permitted proposals/continuations and observation restrictions. Variants remain clustered by template. The six instrument-control categories and positive witnesses are separate from these pairs.

There is one local provider authority, one tenant, trusted Python application code, trusted launch configuration and clock, and SQLite-local effects. The pilot is a deterministic adaptive process, not an LLM. Recovery creates a new process under the **same service principal**, not delegated authority to another principal. No HTTP/OAuth, new SDK/wire conformance, real mailbox or remote atomicity is exercised.

The Z arm uses an explicitly attributed R7 copy of the R6 core with localized read/refusal additions. The C arm is an independently written flat durable ACL with its own canonical binding, budget accounting, current-policy checks and idempotency state. Sharing a neutral effect engine does not permit sharing the authorization checker or evaluator's expected labels. Neither arm is deprived of current observations, lookup, durable journal, cancellation, revocation or `UNKNOWN` to create a performance gap.

## Complete bounded business semantics

The immutable seed declares self identity, messages and versions, thread/sender/`to`/`cc`/`bcc`, read state, and a versioned directory. Synthetic aliases expand one level to one known identity; groups name explicit known members. Unknown identities, unsupported shapes and ambiguous recipient overlap are refused rather than ignored. Environment changes are separately attributed append-only events, with ordering relative to execution recorded by the harness.

One trusted `message.mutate` ToolSpec owns `mail_events`. `reply` resolves each declared recipient field; an empty `to` means the source sender. `reply_all` has empty explicit selectors and resolves source sender, `to` and `cc`, excluding self, into sorted `to`; `cc` and `bcc` are empty. Hidden source BCC recipients are not recovered. This is a deliberately closed simulation profile, not general mail syntax.

Every non-`mark_read` action creates one local outbox occurrence, one delivery event per resolved recipient/field, and the declared read event when the previously unread source is to become read. Source message version increases once when the call creates an outbox or changes read state. Standalone `mark_read` needs its own explicit structured permission. An already-read `mark_read` is an accepted no-op: it consumes the accepted-operation cost but creates no useful extra mutation or version increment.

The bound action includes obligation identity, message identity, kind, selectors, expected resolved recipient fields, expected message/directory versions, body, `set_read` and expected actual read-change bit. Client declarations are not authority. Within the effect transaction each backend independently verifies the recomputed current plan against these declarations, and independently checks all effective recipients, allowed message/mode/body and explicit read permission before the first business insert.

The shared engine resolves and applies effects, without ACL decisions. The independent evaluator uses separate expectations and SQL/event interpretation, not the engine's normalizer as its sole definition of truth.

## Reads, costs and transactions

The R7 writer's `read_rows(table)` uses the already-open effect transaction and only a table declared by the active ToolSpec. Results are immutable copied rows ordered by `row_id`. No connection, cursor, free SQL, projection or transaction control is returned. The fixed maximum is 1,024 rows per table; reading a 1,025th row triggers the typed `READ_LIMIT` refusal. Truncation is forbidden. Access outside the writer lifetime or to another table is an error.

The pure declared footprint charges `ops=1` per accepted call and `bytes=len(body.encode('utf-8'))` for `reply`/`reply_all`, zero bytes for `mark_read`. Facts include each declared effective recipient and `read:<message_id>` only when an actual read change is declared. The complete current plan must agree with that footprint-bearing action before insertion. Quantity and integer domains are bounded explicitly by the implementation; the profile does not assert general JSON/JCS conformance.

Consumed costs plus all active held reservations count against the same root budget. A failed execution does not erase its preexisting reservation; a continuation with changed action must resolve or cancel the old hold before making a new operation. Lost responses do not refund charge. Each arm owns its transaction and couples current authority/epoch, state preconditions, business events, consumption, result and receipt. An exception before commit rolls back this execution's changes together.

Revocation committed before the effect transaction's authority check blocks an unused permit. Revocation after an effect preserves history. The selected schedule is established by actual semantic barrier events, not assumed from sleep durations. Harness fault boundaries are before the effect transaction, after the first business insert before commit, and after commit before response; injection configuration is not passed to the pilot.

## Identity, replay and proof

`obligation_id`, `operation_id` and effect occurrence identities are distinct. Identical retry of a committed operation returns its exact historical receipt/result without another callback, charge or revision. Reusing that operation with different bound action is a conflict. The core does not guarantee semantic deduplication under new operations and there is no `UNIQUE(obligation_id)` business constraint hiding duplicates. Two distinct obligations with identical content remain two legitimate occurrences.

Before every dispatch the pilot durably records exact arguments/action hash, operation and obligation, any reservation, phase and cumulative call counters. A resumed operation reuses these exact bytes and identifiers; it does not refresh versions under the old operation. Changed plans require resolved cancellation and a new operation. At most 16 provider calls, including at most four lookups, are allowed across all process IDs. `observe`, `reserve`, `execute`, `lookup` and `cancel` count; pure local preparation and separately logged administrator injections do not.

Both lookups expose status and receipt, not full stored business result or secret outbox access. A delivered `COMMITTED` receipt must bind to the journal's exact operation/action and obligation before it supports completion. A historical receipt does not authorize another effect, prove all task obligations done, or establish an external delivery. An optional bounded prior report is opaque context, never evidence of completion. Where the available bounded lookup/observation budget cannot settle an outcome, `UNKNOWN` remains distinct from completion.

## Refusals, faults and evaluation

Intentional domain refusals use a closed vocabulary including `STALE_STATE`, `POLICY_DENIED`, `UNSUPPORTED_TARGET`, `READ_LIMIT`, `REVOKED` and `OPERATION_CONFLICT`. Unexpected exceptions, parser/import failures, unexpected process exits and timeouts are operational failures; they cannot count as successful security refusals. Expected process exit 86 requires the actual announced hook and durable pre/postcommit witness.

The evaluator runs separately after controller processes end, from committed-state backups. It reads expected effects, raw requests and delivered observations, reservation/commit records, journal and claims. Controllers receive neither expected labels nor schedules. An import/process guard detects accidental leakage in this trusted laboratory; it is not a hostile-administrator sandbox.

The six separate red controls must exercise actual witnesses for omitted effective recipients, uncounted implicit effects, duplicate obligation under different operations, factually false `DONE`, unsupported `DONE` despite a real effect, and oracle information leakage. Positive witnesses include correctly supported completion and distinct obligations with identical content. Instrument failure invalidates qualification until corrected within the fixed budget, preserving the failed output.

Per-case results keep unauthorized effects, missing useful effects, duplicates, false refusals, factual false `DONE`, unsupported `DONE`, justified/unnecessary `UNKNOWN`, completion and costs separate. No aggregate security score hides a utility/safety tradeoff. Equality, an attributable difference, an invalid instrument or insufficient evidence are legitimate finite conclusions. Selected zero-incident results do not establish population rates, production fitness or universal equivalence.

## Qualification and publication attribution

Development checks remain development. The manifest freezes the candidate inputs before the separate S1-cleared full qualification. R1 and R2 use authors distinct from the components they approve and remain same-team AI reviews. Windows qualification identifies candidate H; Ubuntu CI identifies its actual checked-out source. An authorized merge uses expected H; the resulting real M and tree are read back, with M CI and an installed final-package smoke attributed to M.

Public export contains a closed reviewed data set and manifest; private keys/configuration/runtime directories are excluded. Hashes check internal consistency, not independent provenance. A fresh audit uses trusted installed source and executes no captured code. Actual anonymous release downloads, byte matching, downloaded-package audit/smoke and the final matching director decision are separate publication/closure gates. No new external contact, general standard, certification or adoption is implied.

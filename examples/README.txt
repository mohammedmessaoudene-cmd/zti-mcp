PUBLIC LABORATORY EXAMPLES — NOT LIVE CREDENTIALS

The root mandate, narrowed child mandate, ICT and action are exported from the
successful C02 scenario of experiment/runs/initial. All three JWS signatures are
real ES256/P-256/SHA-256 signatures and verify with public_jwk.json. The private
key is deliberately PUBLIC laboratory material (P-256 scalar 1). Never deploy it.
The fixed NumericDate values belong to the deterministic fixture clock.

action.json is the exact final command bound by the ICT. root_mandate_claims.json,
child_mandate_claims.json and ict_claims.json are decoded views of their .jwt files.
Hashes cover the declared canonical subset; signatures cover received JWS segments.

receipt.json is an OFFLINE DOCUMENTARY VIEW of the persisted C02 local SQLite
effect and COMMITTED audit entry. Its state_revision is the audit sequence. It is
not an authenticated network response and was not emitted by a real MCP server.
The local executable API uses simpler Python results. EXAMPLE_METADATA.json and
VERIFICATION.json preserve provenance, checks and this distinction.

To repeat the signature and binding verification:
  python3 -I ../experiment/verify_examples.py

Any MCP/control envelopes added by the coordinator around these values remain
illustrative wire documents unless separately executed against actual peers.

# Selected R6 SDK clients

The Python client is distributed in the separately installed zti-r6-demo wheel.
The TypeScript source in this archive runs with Node 24.22.2 native type stripping;
it does not require a compiler or a source checkout at runtime.

The launcher builds the archive from verified staging and extracts it into a
fresh directory outside the checkout and node_modules. It copies the shipped
runtime-lock.json byte-for-byte to package-lock.json, then runs npm ci. The
direct official SDK2.4.0 and zod4.6.7 dependencies are pinned. Dependencies and
source files are never installed into the published source tree.

Both bridges delegate actual protocol I/O to public SDK APIs. The transparent
public Transport composition keeps TypeScript discovery on the active stdio
channel; raw bytes, process identities and exits are independently recorded.
The local command input/output is a harness interface, not an invented MCP peer.

Code is Apache-2.0, with LICENSE and NOTICE included. This explanatory prose
uses [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/) under the
[repository allocation](https://github.com/mohammedmessaoudene-cmd/zti-mcp/blob/main/LICENSE_SCOPE.md).
No static type-checking result is claimed. The demonstration uses trusted local
identities, keys and plugins.

## Project notice

ZTI-MCP: Constraint-Preserving Delegation and Cumulative Effect Authorization
Copyright 2026 Mohammed Messaoudene

This notice concerns the original project contributions identified in
LICENSE_SCOPE.md. Original software, schemas, fixtures and specification
contributions are licensed under the Apache License, Version 2.0. Original
non-specification documentation is licensed under CC BY 4.0 as identified
in that file.

The IETF-formatted specification retains its existing IETF Trust notices
and third-party references. No rights in third-party material are granted
by this project notice. See THIRD_PARTY_NOTICES.md.

Project and organization names are used descriptively. No affiliation,
adoption, certification or endorsement by the IETF, MCP maintainers, the
Apache Software Foundation or Creative Commons is asserted.

This NOTICE provides attribution and information. It does not amend or
add conditions to either license.

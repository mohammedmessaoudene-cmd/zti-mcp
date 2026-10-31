"""Public, harmless R5 laboratory inputs; no expected oracle enters the provider.

The signing key is the deliberately public P-256 scalar 1 implemented in
crypto.py. These identities and symbolic tools are not deployment credentials.
"""
from __future__ import annotations

import copy
import secrets
from typing import Any

from crypto import digest, sign

EXT_ID = "org.example/zti-mcp"
PROFILE = "zti-mcp/0.1"
CAPABILITY = {
    "revision": "0.1",
    "profile": PROFILE,
    "mode": "current-online",
    "effect_coupling": "required",
}


def identifier(prefix: str) -> str:
    return prefix + secrets.token_hex(16)


def build_fixture(contract: dict[str, Any], variant: dict[str, Any]) -> dict[str, Any]:
    """Resolve aliases once per fresh database, retaining them over restart."""
    c = copy.deepcopy(contract["fixture_contract"])
    overrides = copy.deepcopy(variant.get("fixture_overrides", {}))
    for key, value in overrides.items():
        if key not in {"actions", "additional_actions", "additional_endpoints"}:
            c[key] = value
    endpoints = list(c["default_endpoints"])
    endpoints += [x for x in overrides.get("additional_endpoints", []) if x not in endpoints]
    leaves = c.get("registered_leaves", c["default_registered_leaves"])
    policy = {"budgets": c["root_budget"], "forbidden_sets": c["root_forbidden_sets"]}
    constraints = {
        "allowed_executors": [c["executor_id"]],
        "allowed_resources": [c["resource_id"]],
        "allowed_methods": ["tools/call"],
        "allowed_tools": list(c["catalog"]["facts_by_tool"]),
        "action_caps": c["action_caps"],
    }
    root_id = identifier("root-")
    root = {
        "profile": PROFILE,
        "tenant_id": c["tenant_id"],
        "principal_id": c["principal_id"],
        "root_mandate_id": root_id,
        "mandate_id": root_id,
        "parent_id": None,
        "parent_hash": None,
        "correlation_id": identifier("corr-"),
        "delegatee_id": c["endpoint_principals"]["admin"],
        "valid_from": c["mandate_valid_from"],
        "valid_until": c["mandate_valid_until"],
        "constraints": constraints,
        "root_policy": policy,
        "policy_hash": digest(policy),
    }
    mandates = {"root": root}
    for leaf in leaves:
        body = copy.deepcopy(root)
        body.update({
            "mandate_id": identifier("child-"),
            "parent_id": root_id,
            "parent_hash": digest(root),
            "delegatee_id": c["endpoint_principals"][leaf],
            "root_policy": None,
        })
        mandates[leaf] = body
    tokens = {}
    claims = {}
    for alias, body in mandates.items():
        claims[alias] = {
            "iss": c["issuer"],
            "sub": body["delegatee_id"],
            "aud": c["registry_id"],
            "iat": c["initial_test_clock"],
            "nbf": body["valid_from"],
            "exp": body["valid_until"],
            "jti": identifier("m-"),
            "zti_mandate": body,
        }
        tokens[alias] = sign(claims[alias], "zti-mandate+jwt")
    definitions = copy.deepcopy(overrides.get("actions", c["default_actions"]))
    definitions.update(overrides.get("additional_actions", {}))
    actions = {}
    for alias, definition in definitions.items():
        body = mandates[definition["delegatee"]]
        actions[alias] = {
            "profile": PROFILE,
            "tenant_id": c["tenant_id"],
            "root_mandate_id": root_id,
            "mandate_id": body["mandate_id"],
            "operation_id": identifier("op-"),
            "executor_id": c["executor_id"],
            "resource_id": c["resource_id"],
            "method": definition.get("method", "tools/call"),
            "tool_name": definition["tool_name"],
            "tool_revision": definition.get("tool_revision", "1"),
            "arguments": definition["arguments"],
        }
    return {
        "fixture_type": "PUBLIC_LABORATORY_MATERIAL_NOT_DEPLOYMENT_AUTHENTICATION",
        "tenant_id": c["tenant_id"],
        "root_mandate_id": root_id,
        "mandates": mandates,
        "mandate_claims": claims,
        "signed_mandates": tokens,
        "actions": actions,
        "operation_ids": {k: v["operation_id"] for k, v in actions.items()},
        "action_definitions": definitions,
        "endpoint_principals": c["endpoint_principals"],
        "endpoint_aliases": endpoints,
        "registered_leaves": list(leaves),
        "initial_clock": c["initial_test_clock"],
        "agent_a_server_advertises_extension": c.get("agent_a_server_advertises_extension", True),
    }

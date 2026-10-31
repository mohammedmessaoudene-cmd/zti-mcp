"""Closed method-specific request models for the experimental R4 wire binding.

The SDK owns standard MCP metadata. Explicit snake_case aliases preserve the
existing ZTI schema rather than inheriting the SDK's camelCase generator.
"""
from typing import Any
from mcp.types import RequestParams, Result
from pydantic import ConfigDict, Field

EXT_ID = 'org.example/zti-mcp'
CAPABILITY = {'revision':'0.1','profile':'zti-mcp/0.1','mode':'current-online','effect_coupling':'required'}
PROTOCOL = '2026-07-28'

class ClosedParams(RequestParams):
    model_config = ConfigDict(extra='forbid', populate_by_name=True, alias_generator=None, strict=True)
    meta: dict[str, Any] | None = Field(default=None,alias='_meta')

class RegisterParams(ClosedParams):
    mandate: str = Field(alias='mandate')

class ReserveParams(ClosedParams):
    action: dict[str, Any] = Field(alias='action')

class LookupParams(ClosedParams):
    tenant_id: str = Field(alias='tenant_id')
    root_mandate_id: str = Field(alias='root_mandate_id')
    operation_id: str = Field(alias='operation_id')

class CancelParams(LookupParams):
    reservation_id: str = Field(alias='reservation_id')

class RevokeParams(ClosedParams):
    tenant_id: str = Field(alias='tenant_id')
    root_mandate_id: str = Field(alias='root_mandate_id')
    mandate_id: str = Field(alias='mandate_id')

PARAM_TYPES = {'register':RegisterParams,'reserve':ReserveParams,'lookup':LookupParams,'cancel':CancelParams,'revoke':RevokeParams}

class ControlResult(Result):
    """Preserve custom result keys; each wire result is separately schema checked."""
    model_config = ConfigDict(extra='allow', populate_by_name=True, alias_generator=None)

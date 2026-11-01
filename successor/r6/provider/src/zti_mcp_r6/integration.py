"""Bounded public application interface, not a malicious-Python sandbox.

The provider owns table creation, connection, transaction and writer lifetime.
Application code receives no public SQL or commit/rollback interface.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import importlib
import re
from types import MappingProxyType
from typing import Any

from .crypto import SAFE, canonical

INTERNAL_TABLES = frozenset({'roots', 'mandates', 'reservations', 'business_effects',
                             'receipts', 'transitions', 'sqlite_sequence'})


def identifier(value):
    return type(value) is str and re.fullmatch(r'[a-z][a-z0-9_]{0,62}', value) is not None


def freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: freeze(child) for key, child in value.items()})
    if type(value) is list:
        return tuple(freeze(child) for child in value)
    return value


def thaw(value):
    if isinstance(value, Mapping):
        return {key: thaw(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [thaw(child) for child in value]
    return value


@dataclass(frozen=True)
class TableSpec:
    name: str
    columns: Mapping[str, str]

    def __post_init__(self):
        if not identifier(self.name) or self.name in INTERNAL_TABLES or self.name.startswith('sqlite_'):
            raise ValueError('Invalid application table name')
        if not isinstance(self.columns, Mapping) or not self.columns:
            raise ValueError('Application columns required')
        columns = dict(self.columns)
        if any(not identifier(key) or key == 'row_id' or value not in ('TEXT', 'INTEGER')
               for key, value in columns.items()):
            raise ValueError('Invalid application column definition')
        object.__setattr__(self, 'columns', MappingProxyType(columns))


@dataclass(frozen=True)
class Footprint:
    costs: Mapping[str, Mapping[str, str]]
    facts: Sequence[str]

    def __post_init__(self):
        if not isinstance(self.costs, Mapping) or not isinstance(self.facts, Sequence) or isinstance(self.facts, (str, bytes)):
            raise ValueError('Typed footprint mappings and fact sequence required')
        object.__setattr__(self, 'costs', freeze(thaw(self.costs)))
        object.__setattr__(self, 'facts', tuple(self.facts))


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
    input_schema: Mapping[str, Any]
    tables: Sequence[TableSpec]
    validate: Callable
    footprint: Callable
    apply: Callable

    def __post_init__(self):
        if (type(self.name) is not str or not re.fullmatch(r'[a-z][a-zA-Z0-9_.-]{0,127}', self.name)
                or type(self.revision) is not str or not self.revision):
            raise ValueError('Invalid tool identity')
        schema = thaw(self.input_schema)
        canonical(schema)
        if type(schema) is not dict or schema.get('type') != 'object':
            raise ValueError('Object input schema required')
        tables = tuple(self.tables)
        if not tables or any(not isinstance(table, TableSpec) for table in tables):
            raise ValueError('Declared application tables required')
        if len({table.name for table in tables}) != len(tables):
            raise ValueError('Duplicate table declaration')
        if not all(callable(fn) for fn in (self.validate, self.footprint, self.apply)):
            raise ValueError('Tool callbacks required')
        object.__setattr__(self, 'input_schema', freeze(schema))
        object.__setattr__(self, 'tables', tables)


class Writer:
    """A short-lived INSERT-only handle restricted to this trusted tool's tables."""

    __slots__ = ('__connection', '__tables', '__active', '__on_insert')

    def __init__(self, connection, tables, on_insert):
        self.__connection = connection
        self.__tables = {table.name: table for table in tables}
        self.__active = True
        self.__on_insert = on_insert

    def insert(self, table: str, values: Mapping[str, str | int]) -> int:
        if not self.__active or not self.__connection.in_transaction:
            raise ValueError('Writer lifetime ended')
        if type(table) is not str or table not in self.__tables or not isinstance(values, Mapping):
            raise ValueError('Undeclared application table')
        values = dict(values)
        columns = self.__tables[table].columns
        if set(values) != set(columns):
            raise ValueError('Application column mismatch')
        for key, column_type in columns.items():
            value = values[key]
            if column_type == 'TEXT':
                if type(value) is not str:
                    raise ValueError('TEXT value required')
                value.encode('utf-8')
            elif type(value) is not int or not -SAFE <= value <= SAFE:
                raise ValueError('Safe INTEGER value required')
        names = ','.join('"' + name + '"' for name in columns)
        query = f'INSERT INTO "{table}" ({names}) VALUES ({",".join("?" for _ in columns)})'
        cursor = self.__connection.execute(query, tuple(values[name] for name in columns))
        row_id = cursor.lastrowid
        if type(row_id) is not int or not 0 < row_id <= SAFE:
            raise ValueError('Application row identifier overflow')
        self.__on_insert(table, row_id)
        return row_id

    def _finish(self):
        self.__active = False


def load_tools(entries):
    """Load only the trusted launch configuration's installed module factories."""
    if type(entries) is not list or not entries or any(type(item) is not str for item in entries):
        raise ValueError('Installed tool factories required')
    result = []
    for entry in entries:
        module, separator, name = entry.partition(':')
        if not separator or not module or not name or not name.isidentifier():
            raise ValueError('Expected module:factory')
        factory = getattr(importlib.import_module(module), name)
        tools = factory()
        result.extend((tools,) if isinstance(tools, ToolSpec) else tuple(tools))
    if any(not isinstance(tool, ToolSpec) for tool in result):
        raise ValueError('Factory must return ToolSpec objects')
    if len({tool.name for tool in result}) != len(result):
        raise ValueError('Duplicate tool name')
    tables = [table.name for tool in result for table in tool.tables]
    if len(set(tables)) != len(tables):
        raise ValueError('Application tables must have one tool owner')
    return tuple(result)

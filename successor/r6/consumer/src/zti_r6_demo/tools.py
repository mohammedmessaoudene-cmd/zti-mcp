"""An external ToolSpec, without an authority-core patch or transaction control.

The provider owns the transaction. This in-process plugin is trusted code,
not a sandbox. It inserts fictional data only through the bounded Writer API.
"""
import json
import re
from zti_mcp_r6 import Footprint, TableSpec, ToolSpec

U64 = 18446744073709551615
TAGS = frozenset(("red", "blue", "neutral"))
SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["quantity", "label", "tags"],
    "properties": {
        "quantity": {"type": "string", "pattern": "^(0|[1-9][0-9]*)$", "maxLength": 20},
        "label": {"type": "string", "maxLength": 256, "description": "At most 256 UTF-8 bytes; semantic validation enforces byte length."},
        "tags": {"type": "array", "maxItems": 8, "uniqueItems": True,
                 "items": {"type": "string", "enum": ["red", "blue", "neutral"]}},
    },
}
COLUMNS = {
    "tenant_id": "TEXT", "root_mandate_id": "TEXT", "mandate_id": "TEXT",
    "operation_id": "TEXT", "reservation_id": "TEXT", "quantity": "TEXT",
    "label": "TEXT", "tags_json": "TEXT", "action_hash": "TEXT", "provider_pid": "INTEGER",
}


def validate(args):
    if type(args) is not dict or set(args) != {"quantity", "label", "tags"}:
        raise ValueError("Expected the three declared argument fields")
    value = args["quantity"]
    if type(value) is not str or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value) or int(value) > U64:
        raise ValueError("Expected canonical uint64 quantity")
    label = args["label"]
    if type(label) is not str:
        raise ValueError("Expected Unicode label")
    try:
        size = len(label.encode("utf-8"))
    except UnicodeError as exc:
        raise ValueError("Invalid Unicode") from exc
    if size > 256:
        raise ValueError("Label exceeds byte limit")
    tags = args["tags"]
    if (type(tags) is not list or len(tags) > 8 or
            any(type(tag) is not str or tag not in TAGS for tag in tags) or len(tags) != len(set(tags))):
        raise ValueError("Expected unique declared tags")


def footprint(args):
    return Footprint(costs={
        "ops": {"unit": "operation", "amount": args["quantity"]},
        "bytes": {"unit": "byte", "amount": str(len(args["label"].encode("utf-8")))},
    }, facts=tuple(sorted(args["tags"])))


def apply(writer, context, args):
    values = {key: getattr(context, key) for key in (
        "tenant_id", "root_mandate_id", "mandate_id", "operation_id",
        "reservation_id", "action_hash", "provider_pid")}
    values.update(quantity=args["quantity"], label=args["label"],
                  tags_json=json.dumps(list(args["tags"]), ensure_ascii=False, separators=(",", ":")))
    row_id = writer.insert("demo_records", values)
    return {"row_id": row_id, "operation_id": context.operation_id,
            "quantity": args["quantity"], "label": args["label"], "tags": list(args["tags"])}


def tools():
    return (ToolSpec(name="demo.add_record", revision="1", input_schema=SCHEMA,
                     tables=(TableSpec(name="demo_records", columns=COLUMNS),),
                     validate=validate, footprint=footprint, apply=apply),)

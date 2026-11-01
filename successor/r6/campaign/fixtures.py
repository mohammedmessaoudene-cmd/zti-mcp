"""Resolve frozen input templates and use the separate local issuer role.

No provider or oracle helper is imported. Expected values never enter provider
configuration, callback arguments or signatures.
"""
import base64
import copy
import importlib.util
from pathlib import Path
from common import R6, digest

spec = importlib.util.spec_from_file_location("r6_separate_issuer", R6 / "issuer" / "issuer.py")
issuer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(issuer)


def claims_of(token):
    payload = token.split(".")[1]
    return __import__("json").loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def resolve(corpus, keys, overrides=None):
    overrides = overrides or {}
    bodies = copy.deepcopy(corpus["mandate_templates"])
    root = bodies["root"]
    if "root_budget" in overrides:
        root["root_policy"]["budgets"] = copy.deepcopy(overrides["root_budget"])
    root["policy_hash"] = digest(root["root_policy"])
    for name, body in bodies.items():
        if name != "root":
            body["parent_hash"] = digest(root)
            body["policy_hash"] = root["policy_hash"]
    signed = {}
    for name, body in bodies.items():
        token = issuer.sign_mandate(body, keys["KI"]["private"])
        signed[name] = {"body": body, "jws": token, "claims": claims_of(token)}
    return {"mandates": signed, "actions": copy.deepcopy(corpus["action_templates"]),
            "operation_ids": copy.deepcopy(corpus["operation_ids"]),
            "request_mandates": {}, "negative_icts": {}}


def signed_variant(fixture, alias, args, keys):
    body = copy.deepcopy(fixture["mandates"][alias]["body"])
    if "constraint_override" in args:
        body["constraints"].update(copy.deepcopy(args["constraint_override"]))
    signer = args.get("sign_with", "KI")
    kid_role = args.get("kid_role", "KI")
    header = {"alg": "ES256", "typ": args.get("typ", "zti-mandate+jwt"),
              "kid": issuer.CONTEXT["mandate_kid" if kid_role == "KI" else "permit_kid"]}
    header.update(args.get("header", {}))
    token = issuer.sign_mandate(body, keys[signer]["private"], header=header,
                                claims_overrides=args.get("claims_overrides"))
    original = token
    if args.get("signature_xor"):
        h, p, s = token.split(".")
        raw = bytearray(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
        mutation = args["signature_xor"]
        raw[mutation["byte_offset"]] ^= mutation["mask"]
        token = h + "." + p + "." + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    record = {"body": body, "jws": token, "claims": claims_of(token), "signer_role": signer}
    if args.get("signature_xor"):
        record.update(original_jws=original, signature_xor=args["signature_xor"])
    return record

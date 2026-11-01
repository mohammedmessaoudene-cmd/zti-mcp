"""Execute the twelve frozen causal plans with observable handoffs."""
import asyncio
import copy
from common import EXT
from fixtures import claims_of, issuer


def reserve(name, action, channel="A"):
    return {"id": name, "kind": "rpc", "channel": channel, "method": EXT + ".reserve", "args": {"action_ref": action}}


def call(name, action, channel="A"):
    return {"id": name, "kind": "rpc", "channel": channel, "method": "tools/call", "args": {"action_ref": action}}


def control(name, method, args):
    return {"id": name, "kind": "rpc", "channel": "admin", "method": EXT + "." + method, "args": args}


async def causal(case):
    code = case.spec["id"]
    try:
        await case.bootstrap()
        if code in ("C01", "C02"):
            first, second = (("o1", "A"), ("o2", "B")) if code == "C01" else (("o2", "B"), ("o1", "A"))
            rules = [await case.arm(alias, "reserve:before_transaction", action) for action, alias in (first, second)]
            tasks = [asyncio.create_task(case.request(reserve(name, *item))) for name, item in (("rFirst", first), ("rSecond", second))]
            for rule in rules:
                await case.await_rule(rule)
            for index in (0, 1):
                case.release(rules[index])
                await tasks[index]
                if index == 0:
                    await case.observe_commit("rFirst", "reserve:commit")
            case.observation["groups"]["admissions"] = ["rFirst", "rSecond"]
            case.checkpoint("after_admission")
            await case.request(call("cFirst", *first))
        elif code in ("C03", "C04"):
            first, second = (("red", "A"), ("blue", "B")) if code == "C03" else (("blue", "B"), ("red", "A"))
            rules = [await case.arm(alias, "reserve:before_transaction", action) for action, alias in (first, second)]
            tasks = [asyncio.create_task(case.request(reserve(name, *item))) for name, item in (("rFirst", first), ("rSecond", second))]
            for rule in rules:
                await case.await_rule(rule)
            for index in (0, 1):
                case.release(rules[index])
                await tasks[index]
                if index == 0:
                    await case.observe_commit("rFirst", "reserve:commit")
            case.observation["groups"]["admissions"] = ["rFirst", "rSecond"]
            case.checkpoint("after_admission")
        elif code in ("C05", "C06"):
            await case.request(reserve("r1", "o1"))
            rules = [await case.arm(alias, "call:before_transaction", "o1") for alias in ("A", "A2")]
            tasks = [asyncio.create_task(case.request(call("c1" if alias == "A" else "c2", "o1", alias))) for alias in ("A", "A2")]
            for rule in rules:
                await case.await_rule(rule)
            order = (0, 1) if code == "C05" else (1, 0)
            for index in order:
                case.release(rules[index])
                await tasks[index]
                if index == order[0]:
                    await case.observe_commit("c1" if index == 0 else "c2", "call:commit")
            case.observation["groups"]["same_operation"] = ["c1", "c2"]
        elif code in ("C07", "C09"):
            await case.request(reserve("r1", "o1"))
            event = "call:pause_after_validation" if case.mutant == "M05" else "call:before_transaction"
            rule = await case.arm("A", event, "o1")
            pending = asyncio.create_task(case.request(call("c1", "o1")))
            await case.await_rule(rule)
            if code == "C07":
                await case.request(control("revoke", "revoke", {"mandate_ref": "leafA"}))
                case.checkpoint("after_revocation_before_release")
            else:
                await case.request(control("cancel", "cancel", {"operation_ref": "o1"}))
                case.checkpoint("after_cancellation_before_release")
            case.release(rule)
            await pending
        elif code in ("C08", "C10"):
            await case.request(reserve("r1", "o1"))
            await case.request(call("c1", "o1"))
            if code == "C08":
                await case.request(control("revoke", "revoke", {"mandate_ref": "leafA"}))
                await case.request(control("lookup", "lookup", {"operation_ref": "o1"}))
            else:
                await case.request(control("cancel", "cancel", {"operation_ref": "o1"}))
        elif code in ("C11", "C12"):
            await case.request(reserve("r1", "o1"))
            await case.arm("A", "call:staged_before_commit" if code == "C11" else "call:after_commit", "o1", "crash")
            await case.request(call("crash", "o1"))
            await case.stop_all()
            case.checkpoint("after_crash")
            await case.launch("A", case.pair[1])
            if code == "C12":
                await case.request({"id": "lookup", "method": EXT + ".lookup", "channel": "A", "args": {"operation_ref": "o1"}})
            await case.request(call("retry", "o1"))
        else:
            raise ValueError("Unknown causal plan " + code)
    except Exception as exc:
        case.observation["infrastructure_errors"].append({"type": type(exc).__name__, "message": str(exc)})
        raise
    finally:
        try:
            await case.finish()
        finally:
            case.persist()


async def date_case(case):
    spec = case.spec
    try:
        from common import atomic, digest
        atomic(case.clock, str(spec["clock"]))
        case.manifest["initial_clock"] = spec["clock"]
        valid_root = copy.deepcopy(case.corpus["mandate_templates"]["root"])
        valid_root.update(valid_from=0, valid_until=1000)
        root_token = issuer.sign_mandate(valid_root, case.keys["KI"]["private"], issued_at=0)
        case.fixture["mandates"]["root"] = {"body": valid_root, "jws": root_token, "claims": claims_of(root_token)}
        target = copy.deepcopy(valid_root if spec["target"] == "root" else case.corpus["mandate_templates"]["leafA"])
        if spec["target"] == "child":
            target["parent_hash"] = digest(valid_root)
        target.update(valid_from=spec["body_valid_from"], valid_until=spec["body_valid_until"])
        jwt = spec["jwt"]
        token = issuer.sign_mandate(target, case.keys["KI"]["private"], issued_at=jwt["iat"],
            claims_overrides={"nbf": jwt["nbf"], "exp": jwt["exp"]})
        case.fixture["mandates"]["date_target"] = {"body": target, "jws": token, "claims": claims_of(token)}
        case.fixture["date_diagnostic"] = spec
        case.persist()
        await case.launch("admin")
        if spec["target"] == "child":
            await case.request(control("date.valid_root", "register", {"mandate_ref": "root"}))
        case.checkpoint("before_target")
        await case.request(control("date.target", "register", {"mandate_ref": "date_target"}))
        case.checkpoint("after_target")
    except Exception as exc:
        case.observation["infrastructure_errors"].append({"type": type(exc).__name__, "message": str(exc)})
        raise
    finally:
        try:
            await case.finish()
        finally:
            case.persist()


async def regression(case):
    try:
        await case.bootstrap()
        bad = reserve("bad", "o1")
        bad["args"]["action_override"] = copy.deepcopy(case.spec["override"])
        await case.request(bad)
        case.checkpoint("after_bad")
        await case.request(reserve("good.reserve", "o1"))
        await case.request(call("good.call", "o1"))
    except Exception as exc:
        case.observation["infrastructure_errors"].append({"type": type(exc).__name__, "message": str(exc)})
        raise
    finally:
        try:
            await case.finish()
        finally:
            case.persist()

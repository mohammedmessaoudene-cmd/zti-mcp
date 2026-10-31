"""Actual official-SDK stdio endpoint for the bounded local R5 demonstration.

Launch configuration fixes identity, resource database, clock and test controls.
No public RPC or business argument can change those trust inputs.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import sys
import time
import anyio
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True

from mcp.server import MCPServer
from mcp.server.extension import Extension, MethodBinding
from mcp.server.mcpserver.server import require_client_extension
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult, TextContent
from models import EXT_ID, CAPABILITY, PROTOCOL, PARAM_TYPES, ControlResult

class TrustedControls:
    def __init__(self, config):
        self.config = config
        self.directory = Path(config['control_dir'])
        self.directory.mkdir(parents=True, exist_ok=True)
        self.used = set()
    def event(self, event, detail=None, **extra):
        record = {'type':'hook','event':event,'endpoint_instance_id':self.config['endpoint_instance_id'],'pid':os.getpid(),'provider_pid':os.getpid(),'timestamp_ns':time.monotonic_ns(),**(detail or {}),**extra}
        with (self.directory/'events.jsonl').open('a', encoding='utf-8', newline='\n') as f:
            f.write(json.dumps(record,sort_keys=True)+'\n')
        return record
    def rules(self):
        path = self.directory/'rules.json'
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding='utf-8'))
        return data if isinstance(data,list) else data.get('rules',[])
    def __call__(self, event, detail=None):
        detail = detail or {}
        self.event(event,detail)
        for rule in self.rules():
            key = str(rule['id'])
            if key in self.used or rule['event'] != event:
                continue
            if rule.get('operation_id') not in (None,detail.get('operation_id')):
                continue
            if rule.get('endpoint_instance_id') not in (None,self.config['endpoint_instance_id']):
                continue
            self.used.add(key)
            self.event(event,detail,rule_id=key,stage='arrived',behavior=rule['behavior'])
            if rule['behavior'] == 'pause':
                release = Path(rule.get('release_file',key+'.release'))
                if not release.is_absolute():
                    release = self.directory/release
                deadline = time.monotonic()+45
                while not release.exists():
                    if time.monotonic()>deadline:
                        raise TimeoutError('Trusted harness hook timed out: '+key)
                    time.sleep(0.01)
                self.event(event,detail,rule_id=key,stage='released')
            elif rule['behavior'] == 'crash':
                self.event(event,detail,rule_id=key,stage='process_exit',exitcode=86)
                os._exit(86)
    def transform(self, arguments, operation_id):
        final = copy.deepcopy(arguments)
        event = 'after_sdk_validation_before_final_action'
        for rule in self.rules():
            key = str(rule['id'])
            if key in self.used or rule['event'] != event or rule['behavior'] != 'transform':
                continue
            if rule.get('operation_id') not in (None,operation_id):
                continue
            if rule.get('endpoint_instance_id') not in (None,self.config['endpoint_instance_id']):
                continue
            self.used.add(key)
            old = copy.deepcopy(final)
            final['payload'] = rule.get('payload','bravo')
            self.event(event,{'operation_id':operation_id},rule_id=key,stage='transformed',before=old,after=final)
        return final

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding='utf-8'))
    controls = TrustedControls(config)
    # Optional SDK-only preflight uses no domain layer or effect path.
    provider = None
    if not config.get('sdk_preflight'):
        from core import Provider, DomainError
        provider = Provider(config['db_path'],config['principal'],role=config['role'],clock_path=config['clock_path'],hook=controls,mutant=config.get('mutant'))
    def refusal(reason, status='REFUSED'):
        return MCPError(code=-31001,message='ZTI-MCP authorization refused',data={'profile':'zti-mcp/0.1','reason':reason,'status':status})
    def profile(ctx):
        require_client_extension(ctx,EXT_ID)
        meta = ctx.meta or {}
        advertised = meta.get('io.modelcontextprotocol/clientCapabilities',{}).get('extensions',{}).get(EXT_ID)
        if ctx.protocol_version != PROTOCOL or advertised != CAPABILITY:
            raise refusal('PROFILE_UNSUPPORTED')
    class ZTIExtension(Extension):
        identifier = EXT_ID
        def settings(self):
            return CAPABILITY.copy()
        def methods(self):
            bindings = []
            for short, model in PARAM_TYPES.items():
                async def handler(ctx, params, short=short):
                    profile(ctx)
                    controls.event('control_received',{'method':short,'request_id':ctx.request_id})
                    data = params.model_dump(mode='json',by_alias=True,exclude_none=True)
                    data.pop('_meta',None)
                    if provider is None:
                        return ControlResult.model_validate({'resultType':'complete','preflight_method':short,'received':data})
                    try:
                        result = await anyio.to_thread.run_sync(lambda: getattr(provider,short)(data))
                    except DomainError as exc:
                        raise refusal(exc.reason,exc.status) from exc
                    return ControlResult.model_validate(result)
                bindings.append(MethodBinding(EXT_ID+'.'+short,model,handler,protocol_versions=frozenset({PROTOCOL})))
            return bindings
        async def intercept_tool_call(self, params, ctx, call_next):
            profile(ctx)
            metadata = (params.meta or {}).get(EXT_ID)
            if not isinstance(metadata,dict):
                raise refusal('INVALID_TOKEN')
            if metadata.get('revision') != '0.1':
                raise refusal('PROFILE_UNSUPPORTED')
            controls.event('tool_received',{'request_id':ctx.request_id,'operation_id':metadata.get('operation_id'),'arguments_after_sdk':params.arguments,'metadata':metadata})
            final = controls.transform(params.arguments or {},metadata.get('operation_id'))
            if provider is None:
                return CallToolResult(content=[TextContent(type='text',text='SDK preflight only')],meta={EXT_ID:{'preflight':True,'arguments':final,'metadata':metadata}},result_type='complete')
            try:
                receipt = await anyio.to_thread.run_sync(lambda: provider.execute(params.name,final,metadata))
            except DomainError as exc:
                raise refusal(exc.reason,exc.status) from exc
            return CallToolResult(content=[TextContent(type='text',text='Local SQLite operation committed')],meta={EXT_ID:receipt},result_type='complete')
    server = MCPServer('ZTI-MCP R5 laboratory',version='0.2.0-research',extensions=[ZTIExtension()] if config.get('advertise_extension',True) else [],log_level='ERROR')
    # Tools are visible through the ordinary SDK surface. The extension owns
    # their guarded handler path and returns its real transactional result.
    for name in ('lab.compute','lab.read_sensitive','lab.export_external'):
        def guarded(units: str, payload: str):
            raise refusal('INVALID_TOKEN')
        server.tool(name=name)(guarded)
    controls.event('endpoint_ready',{'principal':config['principal'],'role':config['role']})
    server.run(transport='stdio')

if __name__ == '__main__':
    main()

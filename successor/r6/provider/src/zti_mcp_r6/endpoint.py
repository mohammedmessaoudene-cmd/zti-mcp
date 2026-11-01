"""Official SDK endpoint, adapting R5 endpoint.py at baseline 3b5b696 (Apache-2.0).

Public list_tools advertises installed schemas. The public extension interceptor
owns the guarded effect path. No private SDK fields or generated signatures.
"""
from __future__ import annotations
import argparse
import contextvars
import copy
import json
import os
from pathlib import Path
import threading
import time
import anyio
from mcp.server import MCPServer
from mcp.server.extension import Extension, MethodBinding
from mcp.server.mcpserver.server import require_client_extension
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult, TextContent, Tool
from .core import Provider
from .crypto import DomainError
from .integration import load_tools, thaw
from .models import EXT_ID, CAPABILITY, PROTOCOL, PARAM_TYPES, ControlResult

REQUEST_ID = contextvars.ContextVar('r6_sdk_request_id', default=None)


class TrustedControls:
    """Lab-only startup files. Polling observes explicit releases, not causality."""
    def __init__(self, config):
        self.instance = config.get('endpoint_instance_id', 'configured-endpoint')
        self.directory = Path(config['control_dir']) if config.get('control_dir') else None
        if self.directory is not None:
            self.directory.mkdir(parents=True, exist_ok=True)
        self.used, self.lock, self.sequence = set(), threading.Lock(), 0

    def event(self, event, detail=None, **extra):
        with self.lock:
            self.sequence += 1
            record = {**(detail or {}), **extra, 'type': 'hook', 'event': event,
                      'endpoint_instance_id': self.instance, 'pid': os.getpid(),
                      'provider_pid': os.getpid(), 'request_id': REQUEST_ID.get(),
                      'sequence': self.sequence, 'timestamp_ns': time.monotonic_ns()}
            if self.directory is not None:
                with (self.directory/'events.jsonl').open('a', encoding='utf-8', newline='\n') as stream:
                    stream.write(json.dumps(record, sort_keys=True, ensure_ascii=True)+'\n')
            return record

    def rules(self):
        if self.directory is None or not (self.directory/'rules.json').exists():
            return []
        value = json.loads((self.directory/'rules.json').read_text(encoding='utf-8'))
        return value if type(value) is list else value['rules']

    def claim(self, rule, event, detail):
        if rule['event'] != event or rule.get('operation_id') not in (None, detail.get('operation_id')):
            return False
        if rule.get('endpoint_instance_id') not in (None, self.instance):
            return False
        with self.lock:
            if str(rule['id']) in self.used:
                return False
            self.used.add(str(rule['id']))
            return True

    def __call__(self, event, detail=None):
        detail = detail or {}
        self.event(event, detail)
        for rule in self.rules():
            if not self.claim(rule, event, detail):
                continue
            key, behavior = str(rule['id']), rule['behavior']
            self.event(event, detail, rule_id=key, stage='arrived', behavior=behavior)
            if behavior == 'pause':
                release = Path(rule.get('release_file', key+'.release'))
                if not release.is_absolute():
                    release = self.directory/release
                deadline = time.monotonic()+45
                while not release.exists():
                    if time.monotonic()>deadline:
                        raise TimeoutError('Trusted test control timed out')
                    time.sleep(0.01)
                self.event(event, detail, rule_id=key, stage='released')
            elif behavior == 'crash':
                self.event(event, detail, rule_id=key, stage='process_exit', exitcode=86)
                os._exit(86)
            elif behavior == 'raise':
                self.event(event, detail, rule_id=key, stage='raised')
                raise DomainError('EXECUTION_FAILED')
            else:
                raise ValueError('Unknown trusted test-control behavior')

    def transform(self, arguments, operation_id):
        final = copy.deepcopy(arguments)
        event = 'after_sdk_validation_before_final_action'
        for rule in self.rules():
            if rule.get('behavior') != 'transform' or not self.claim(rule, event, {'operation_id': operation_id}):
                continue
            before = copy.deepcopy(final)
            if type(rule.get('arguments')) is dict:
                final = copy.deepcopy(rule['arguments'])
            else:
                final['label'] = rule.get('label', 'altered')
            self.event(event, {'operation_id': operation_id}, rule_id=str(rule['id']),
                       stage='transformed', before=before, after=final)
        return final


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding='utf-8'))
    controls = TrustedControls(config)
    tools = load_tools(config['tools'])
    provider = Provider(config, tools, hook=controls)

    def refusal(reason, status='REFUSED'):
        return MCPError(code=-31001, message='ZTI-MCP authorization refused',
                        data={'profile': 'zti-mcp/0.1', 'reason': reason, 'status': status})

    def profile(ctx):
        metadata = ctx.meta or {}
        capabilities = metadata.get('io.modelcontextprotocol/clientCapabilities', {})
        extensions = capabilities.get('extensions') if type(capabilities) is dict else None
        advertised = extensions.get(EXT_ID) if type(extensions) is dict else None
        if ctx.protocol_version != PROTOCOL or advertised != CAPABILITY:
            raise refusal('PROFILE_UNSUPPORTED')
        require_client_extension(ctx, EXT_ID)

    class ZTIExtension(Extension):
        identifier = EXT_ID

        def settings(self):
            return CAPABILITY.copy()

        def methods(self):
            bindings = []
            for short, model in PARAM_TYPES.items():
                async def handler(ctx, params, short=short):
                    token = REQUEST_ID.set(ctx.request_id)
                    try:
                        profile(ctx)
                        controls.event('control_received', {'method': short})
                        data = params.model_dump(mode='json', by_alias=True, exclude_none=True)
                        data.pop('_meta', None)
                        try:
                            result = await anyio.to_thread.run_sync(lambda: getattr(provider, short)(data))
                        except DomainError as error:
                            raise refusal(error.reason, error.status) from error
                        return ControlResult.model_validate(result)
                    finally:
                        REQUEST_ID.reset(token)
                bindings.append(MethodBinding(EXT_ID+'.'+short, model, handler,
                                              protocol_versions=frozenset({PROTOCOL})))
            return bindings

        async def intercept_tool_call(self, params, ctx, call_next):
            token = REQUEST_ID.set(ctx.request_id)
            try:
                profile(ctx)
                metadata = (params.meta or {}).get(EXT_ID)
                if type(metadata) is not dict:
                    raise refusal('INVALID_TOKEN')
                if metadata.get('revision') != '0.1':
                    raise refusal('PROFILE_UNSUPPORTED')
                controls.event('tool_received', {'operation_id': metadata.get('operation_id'),
                               'arguments_after_sdk': params.arguments, 'metadata': metadata})
                final = controls.transform(params.arguments if params.arguments is not None else {}, metadata.get('operation_id'))
                try:
                    result = await anyio.to_thread.run_sync(lambda: provider.execute(params.name, final, metadata))
                except DomainError as error:
                    raise refusal(error.reason, error.status) from error
                return CallToolResult(content=[TextContent(type='text', text='Local SQLite operation committed')],
                                      structured_content=result, meta={EXT_ID: result['receipt']}, result_type='complete')
            finally:
                REQUEST_ID.reset(token)

    class ToolServer(MCPServer):
        async def list_tools(self):
            return [Tool(name=tool.name, description='Trusted local SQLite application tool',
                         input_schema=thaw(tool.input_schema)) for tool in tools]

    server = ToolServer('ZTI-MCP R6 laboratory', version='0.3.0',
                        extensions=[ZTIExtension()] if config.get('advertise_extension', True) else [], log_level='ERROR')
    controls.event('endpoint_ready', {'principal': config['principal'], 'role': config['role']})
    server.run(transport='stdio')


if __name__ == '__main__':
    main()

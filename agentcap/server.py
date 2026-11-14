"""MCP server mode: the audit and compile engine over stdio JSON-RPC.

A thin transport layer only. Every tool call runs the same core functions
the CLI runs and returns the same output the CLI would print for the same
input. No network calls, no telemetry, no configured process execution.
"""
import json
import sys

from . import __version__
from .core import InputError, audit, compile_policy, markdown, parse

SERVER_NAME = 'agentcap-auditor'
SUPPORTED_PROTOCOL_VERSIONS = ('2024-11-05', '2025-03-26', '2025-06-18')
DEFAULT_PROTOCOL_VERSION = '2025-03-26'

TOOLS = [
    {
        'name': 'audit',
        'description': (
            'Audit an agent tool manifest or an MCP mcpServers configuration '
            'for over-privilege. Returns the same report the agentcap audit '
            'CLI command prints: per-tool authority tiers plus findings with '
            'severity, evidence and remediation.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'config': {
                    'type': 'object',
                    'description': (
                        'The configuration to audit, as a JSON object: either '
                        'an agent tool manifest or an object with an '
                        'mcpServers key.'
                    ),
                },
                'format': {
                    'type': 'string',
                    'enum': ['json', 'markdown'],
                    'default': 'json',
                    'description': 'Report format, identical to the CLI --format option.',
                },
            },
            'required': ['config'],
        },
    },
    {
        'name': 'compile',
        'description': (
            'Compile explicit task requirements into a default-deny '
            'capability policy. Returns the same policy document the '
            'agentcap compile CLI command prints.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'config': {
                    'type': 'object',
                    'description': (
                        'The agent tool manifest or mcpServers configuration, '
                        'as a JSON object.'
                    ),
                },
                'tasks': {
                    'type': 'object',
                    'description': (
                        'Task requirements document: an object with a tasks '
                        'array of {name, requires} entries, exactly as the CLI '
                        '--tasks file.'
                    ),
                },
            },
            'required': ['config', 'tasks'],
        },
    },
]


def _tool_result(text, is_error=False):
    return {'content': [{'type': 'text', 'text': text}], 'isError': is_error}


def call_tool(tool_name, arguments):
    """Run one tool and return its MCP result dict. Mirrors the CLI paths."""
    arguments = arguments or {}
    try:
        if tool_name == 'audit':
            config = arguments.get('config')
            if not isinstance(config, dict):
                raise InputError('audit requires a config object')
            result = audit(parse(config))
            if arguments.get('format', 'json') == 'markdown':
                return _tool_result(markdown(result))
            return _tool_result(json.dumps(result, indent=2) + '\n')
        if tool_name == 'compile':
            config = arguments.get('config')
            tasks = arguments.get('tasks')
            if not isinstance(config, dict):
                raise InputError('compile requires a config object')
            if not isinstance(tasks, dict):
                raise InputError('compile requires a tasks object')
            result = compile_policy(parse(config), tasks)
            return _tool_result(json.dumps(result, indent=2) + '\n')
        return _tool_result(f'agentcap: unknown tool: {tool_name}', is_error=True)
    except (InputError, KeyError, TypeError) as exc:
        return _tool_result(f'agentcap: {exc}', is_error=True)


def handle(message):
    """Handle one JSON-RPC message dict; return a response dict or None."""
    method = message.get('method')
    request_id = message.get('id')
    if method == 'initialize':
        requested = (message.get('params') or {}).get('protocolVersion')
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
        result = {
            'protocolVersion': version,
            'capabilities': {'tools': {'listChanged': False}},
            'serverInfo': {'name': SERVER_NAME, 'version': __version__},
        }
        return {'jsonrpc': '2.0', 'id': request_id, 'result': result}
    if request_id is None:
        return None  # Any notification, including notifications/initialized.
    if method == 'ping':
        result = {}
    elif method == 'tools/list':
        result = {'tools': TOOLS}
    elif method == 'tools/call':
        params = message.get('params') or {}
        result = call_tool(params.get('name'), params.get('arguments'))
    else:
        return {
            'jsonrpc': '2.0',
            'id': request_id,
            'error': {'code': -32601, 'message': f'method not found: {method}'},
        }
    return {'jsonrpc': '2.0', 'id': request_id, 'result': result}


def main(argv=None):
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict):
            continue
        response = handle(message)
        if response is not None:
            sys.stdout.write(json.dumps(response) + '\n')
            sys.stdout.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

"""MCP server mode tests: handshake, tool listing, CLI parity over stdio."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / 'examples'


def run_session(messages):
    payload = ''.join(json.dumps(m) + '\n' for m in messages)
    proc = subprocess.run(
        [sys.executable, '-m', 'agentcap.server'],
        input=payload, capture_output=True, text=True, cwd=ROOT, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def run_cli(*args):
    proc = subprocess.run(
        [sys.executable, '-m', 'agentcap', *args],
        capture_output=True, text=True, cwd=ROOT, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def by_id(responses, request_id):
    matches = [r for r in responses if r.get('id') == request_id]
    assert len(matches) == 1
    return matches[0]


def handshake_messages(extra):
    return [
        {
            'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
            'params': {
                'protocolVersion': '2025-03-26',
                'capabilities': {},
                'clientInfo': {'name': 'pytest', 'version': '0'},
            },
        },
        {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
        *extra,
    ]


def test_initialize_handshake():
    import agentcap
    responses = run_session(handshake_messages([]))
    response = by_id(responses, 1)
    result = response['result']
    assert result['protocolVersion'] == '2025-03-26'
    assert result['serverInfo']['name'] == 'agentcap-auditor'
    assert result['serverInfo']['version'] == agentcap.__version__
    assert 'tools' in result['capabilities']
    # The notification must not produce a response.
    assert len(responses) == 1


def test_tools_list():
    responses = run_session(handshake_messages([
        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
    ]))
    tools = by_id(responses, 2)['result']['tools']
    names = [t['name'] for t in tools]
    assert names == ['audit', 'compile']
    for tool in tools:
        assert tool['inputSchema']['type'] == 'object'
        assert 'config' in tool['inputSchema']['properties']


def test_tools_call_audit_matches_cli_json():
    config = json.loads((EXAMPLES / 'manifest.json').read_text(encoding='utf-8'))
    responses = run_session(handshake_messages([
        {
            'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
            'params': {'name': 'audit', 'arguments': {'config': config}},
        },
    ]))
    result = by_id(responses, 3)['result']
    assert result['isError'] is False
    server_report = json.loads(result['content'][0]['text'])
    cli_report = json.loads(run_cli('audit', str(EXAMPLES / 'manifest.json')))
    assert server_report == cli_report


def test_tools_call_audit_mcp_config_markdown_matches_cli():
    config = json.loads((EXAMPLES / 'mcp.json').read_text(encoding='utf-8'))
    responses = run_session(handshake_messages([
        {
            'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call',
            'params': {
                'name': 'audit',
                'arguments': {'config': config, 'format': 'markdown'},
            },
        },
    ]))
    result = by_id(responses, 4)['result']
    assert result['isError'] is False
    cli_text = run_cli('audit', str(EXAMPLES / 'mcp.json'), '--format', 'markdown')
    assert result['content'][0]['text'] == cli_text


def test_tools_call_compile_matches_cli():
    config = json.loads((EXAMPLES / 'manifest.json').read_text(encoding='utf-8'))
    tasks = json.loads((EXAMPLES / 'tasks.json').read_text(encoding='utf-8'))
    responses = run_session(handshake_messages([
        {
            'jsonrpc': '2.0', 'id': 5, 'method': 'tools/call',
            'params': {'name': 'compile', 'arguments': {'config': config, 'tasks': tasks}},
        },
    ]))
    result = by_id(responses, 5)['result']
    assert result['isError'] is False
    server_policy = json.loads(result['content'][0]['text'])
    cli_policy = json.loads(run_cli(
        'compile', str(EXAMPLES / 'manifest.json'),
        '--tasks', str(EXAMPLES / 'tasks.json'),
    ))
    assert server_policy == cli_policy


def test_tools_call_errors_are_tool_errors():
    responses = run_session(handshake_messages([
        {
            'jsonrpc': '2.0', 'id': 6, 'method': 'tools/call',
            'params': {'name': 'audit', 'arguments': {'config': {'bogus': 1}}},
        },
        {
            'jsonrpc': '2.0', 'id': 7, 'method': 'tools/call',
            'params': {'name': 'nope', 'arguments': {}},
        },
    ]))
    bad_input = by_id(responses, 6)['result']
    assert bad_input['isError'] is True
    assert bad_input['content'][0]['text'].startswith('agentcap:')
    unknown = by_id(responses, 7)['result']
    assert unknown['isError'] is True
    assert 'unknown tool' in unknown['content'][0]['text']

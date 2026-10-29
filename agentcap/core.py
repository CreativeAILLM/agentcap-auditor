"""Validated inputs, conservative classification, auditing and policy compilation."""
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

# All matching rules contribute; declarations cannot erase inferred authority.
RULES = {
    'read': ('read', 'list', 'get', 'search', 'query', 'inspect'),
    'write': ('write', 'create', 'update', 'delete', 'send', 'publish', 'insert'),
    'network_egress': ('http', 'fetch', 'request', 'browse', 'network', 'url'),
    'shell_execution': ('shell', 'exec', 'execute', 'bash', 'sh', 'terminal', 'subprocess'),
    'filesystem_write': ('write_file', 'delete_file', 'mkdir', 'filesystem'),
    'secrets_access': ('secret', 'credential', 'token', 'password', 'vault', 'api_key'),
    'payments': ('pay', 'payment', 'charge', 'purchase', 'refund', 'transfer'),
}
SECRET = re.compile(r'(?i)(secret|token|password|credential|private.?key|api.?key|access.?key)')


class InputError(ValueError):
    """Invalid or unsupported input; never silently broaden permissions."""


def obj(value, label):
    if not isinstance(value, dict):
        raise InputError(f'{label} must be an object')
    return value


def strings(value, label):
    if not isinstance(value, list) or any(not isinstance(x, str) or not x.strip() for x in value):
        raise InputError(f'{label} must be a list of nonempty strings')
    return tuple(sorted(set(value)))


def name(value):
    if not isinstance(value, str) or not value.strip():
        raise InputError('name must be a nonempty string')
    return value


def classify(tool_name, declared=()):
    text = re.sub(r'([a-z])([A-Z])', r'\1_\2', tool_name).lower()
    hits = set(declared)
    if hits - RULES.keys():
        raise InputError('unknown risk tier')
    for tier, words in RULES.items():
        if any(re.search(r'(?<![a-z0-9])' + re.escape(w) + r'(?![a-z0-9])', text) for w in words):
            hits.add(tier)
    # Unknown tools are never treated as harmless reads.
    return tuple(sorted(hits or {'unknown'}))


@dataclass(frozen=True)
class Capability:
    name: str
    tiers: tuple
    scopes: tuple = ()
    paths: tuple = ()
    hosts: tuple = ()
    env_keys: tuple = ()


def capability(raw, prefix=''):
    raw = obj(raw, 'tool')
    n = prefix + name(raw.get('name'))
    env = obj(raw.get('env', {}), 'env')
    return Capability(n, classify(n, strings(raw.get('tiers', []), 'tiers')),
                      strings(raw.get('scopes', []), 'scopes'),
                      strings(raw.get('paths', []), 'paths'),
                      strings(raw.get('hosts', []), 'hosts'), tuple(sorted(env)))


def parse(data):
    data = obj(data, 'config')
    caps = []
    if 'mcpServers' in data:
        if 'tools' in data:
            raise InputError('ambiguous input: tools and mcpServers')
        for server, raw in obj(data['mcpServers'], 'mcpServers').items():
            name(server)
            raw = obj(raw, 'server')
            if bool(raw.get('command')) == bool(raw.get('url')):
                raise InputError('server requires exactly one command or URL')
            tiers = []
            hosts = []
            if raw.get('command'):
                name(raw['command'])
                strings(raw.get('args', []), 'args')
                tiers.append('shell_execution')
            else:
                url = urlsplit(name(raw['url']))
                if url.scheme not in ('http', 'https') or not url.hostname:
                    raise InputError('server URL must be HTTP(S)')
                tiers.append('network_egress')
                hosts = [url.hostname]
            # Transport is an independent grant, never the server's tool inventory.
            caps.append(capability({'name': server + ':transport', 'tiers': tiers,
                                    'hosts': hosts, 'env': raw.get('env', {})}))
            if 'tools' not in raw:
                caps.append(Capability(server + ':undiscovered', ('unknown',)))
            else:
                if not isinstance(raw['tools'], list):
                    raise InputError('server tools must be a list')
                caps.extend(capability(t, server + ':') for t in raw['tools'])
    else:
        if data.get('version') != 1 or not isinstance(data.get('tools'), list):
            raise InputError('manifest requires version 1 and tools list')
        caps = [capability(t) for t in data['tools']]
    if len({c.name for c in caps}) != len(caps):
        raise InputError('duplicate capability name')
    return sorted(caps, key=lambda c: c.name)


def load(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise InputError(f'cannot read JSON: {path}') from exc


def wildcard(value):
    return any(c in value for c in '*?[')


def unrestricted_path(value):
    return (wildcard(value) or value in ('/', '~', '.', '..', '\\')
            or bool(re.fullmatch(r'[A-Za-z]:[\\/]?', value)))


def audit(caps):
    findings = []
    def add(c, code, severity, evidence, remediation):
        findings.append(dict(capability=c.name, code=code, severity=severity,
                             evidence=evidence, remediation=remediation))
    for c in caps:
        if 'unknown' in c.tiers:
            add(c, 'unknown_authority', 'high', 'Tool authority is not declared or recognized.',
                'Provide an explicit reviewed tool inventory and risk tiers.')
        if any(wildcard(s) for s in c.scopes):
            add(c, 'wildcard_scope', 'high', 'Scope contains a wildcard.', 'Enumerate exact resource scopes.')
        if 'shell_execution' in c.tiers:
            add(c, 'shell_execution', 'critical', 'Process execution authority is present.',
                'Remove execution or isolate it with a reviewed command allowlist.')
        if any(unrestricted_path(p) for p in c.paths):
            add(c, 'unrestricted_filesystem', 'high', 'Filesystem roots or glob paths are granted.',
                'Allow exact files or narrowly scoped directories.')
        if 'network_egress' in c.tiers and (not c.hosts or any(wildcard(h) for h in c.hosts)):
            add(c, 'unscoped_network', 'high', 'No finite destination host allowlist.',
                'List exact destination hosts and enforce outbound filtering.')
        keys = [k for k in c.env_keys if SECRET.search(k)]
        if keys:
            add(c, 'secret_environment', 'high', {'environment_keys': keys},
                'Use short-lived scoped credentials; avoid secrets in config files.')
        required = {'filesystem_write': c.paths, 'network_egress': c.hosts,
                    'read': c.scopes or c.paths, 'write': c.scopes or c.paths,
                    'shell_execution': c.scopes, 'payments': c.scopes, 'secrets_access': c.scopes}
        missing = sorted(t for t in c.tiers if t in required and not required[t])
        if missing:
            add(c, 'missing_allowlist', 'high', {'tiers': missing},
                'Declare explicit scopes, paths or destination hosts for each grant.')
    return {'version': '0.1.0', 'capability_count': len(caps),
            'classifications': [{'name': c.name, 'tiers': list(c.tiers)} for c in caps],
            'findings': findings}


def compile_policy(caps, tasks):
    tasks = obj(tasks, 'task document')
    if not isinstance(tasks.get('tasks'), list):
        raise InputError('tasks must be a list')
    available = {c.name: c for c in caps}
    selected = {}
    names = set()
    for task in tasks['tasks']:
        task = obj(task, 'task')
        task_name = name(task.get('name'))
        if task_name in names:
            raise InputError('duplicate task name')
        names.add(task_name)
        if not isinstance(task.get('requires'), list):
            raise InputError('task requires must be a list')
        for req in task['requires']:
            req = obj(req, 'requirement')
            n = name(req.get('name'))
            if n not in available or 'unknown' in available[n].tiers:
                raise InputError(f'unknown or unclassified capability: {n}')
            source = available[n]
            target = selected.setdefault(n, {'name': n, 'tiers': list(source.tiers),
                                             'scopes': [], 'paths': [], 'hosts': []})
            for field in ('scopes', 'paths', 'hosts'):
                values = strings(req.get(field, []), field)
                grants = getattr(source, field)
                for value in values:
                    if wildcard(value) or (field == 'paths' and unrestricted_path(value)):
                        raise InputError('task requirements must be finite and explicit')
                    # Only exact grants or the explicit universal grant are supported.
                    if value not in grants and '*' not in grants:
                        raise InputError(f'request exceeds granted {field}: {n}')
                target[field] = sorted(set(target[field]) | set(values))
            needed = {'read': 'scopes', 'write': 'scopes', 'shell_execution': 'scopes',
                      'filesystem_write': 'paths', 'network_egress': 'hosts',
                      'secrets_access': 'scopes', 'payments': 'scopes'}
            for tier in source.tiers:
                if not target[needed[tier]]:
                    raise InputError(f'{n} requires explicit {needed[tier]}')
    for n in selected:
        if ':' in n:
            transport = n.split(':', 1)[0] + ':transport'
            if transport in available and transport not in selected:
                raise InputError(f'MCP tool requires an explicit transport requirement: {transport}')
    return {'version': 1, 'default': 'deny', 'tasks': sorted(names),
            'tools': [selected[n] for n in sorted(selected)]}


def authority_count(caps):
    """Count unique (capability identity, risk tier) grants; no scope weighting."""
    return len({(c.name, t) for c in caps for t in c.tiers})


def reduction(before, after):
    if before < 0 or after < 0 or after > before:
        raise InputError('authority counts require 0 <= after <= before')
    return 100.0 * (before - after) / before if before else 0.0


def benchmark(directory):
    rows = []
    for path in sorted(Path(directory).glob('*.json')):
        fixture = obj(load(path), 'fixture')
        caps = parse(fixture['manifest'])
        policy = compile_policy(caps, {'tasks': [fixture['task']]})
        before, after = authority_count(caps), authority_count(parse(policy))
        rows.append({'task': fixture['task']['name'], 'granted': before,
                     'compiled': after, 'reduction_percent': reduction(before, after)})
    if not rows:
        raise InputError('no benchmark fixtures found')
    return {'tasks': rows, 'mean_reduction_percent': sum(r['reduction_percent'] for r in rows) / len(rows)}


def markdown(report):
    lines = ['# AgentCap audit', '', f"Capabilities: {report['capability_count']}",
             f"Findings: {len(report['findings'])}", '']
    for f in report['findings']:
        # Escape untrusted text so Markdown cannot create links or HTML.
        def safe(value):
            return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('[', '&#91;').replace(']', '&#93;').replace('`', '&#96;').replace('\n', ' ')
        lines.extend([f"- **{f['severity'].upper()} {f['code']}** — {safe(f['capability'])}",
                      f"  Evidence: {safe(json.dumps(f['evidence']))}",
                      f"  Remediation: {f['remediation']}"])
    return '\n'.join(lines) + '\n'

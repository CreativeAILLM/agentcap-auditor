"""Offline command line interface; never launches configured tools."""
import argparse
import json
import sys
from importlib.resources import files
from pathlib import Path
from . import __version__
from .core import InputError, audit, benchmark, compile_policy, load, markdown, parse


def main(argv=None):
    parser = argparse.ArgumentParser(prog='agentcap')
    parser.add_argument('--version', action='version', version=__version__)
    commands = parser.add_subparsers(dest='command', required=True)
    audit_cmd = commands.add_parser('audit')
    audit_cmd.add_argument('config')
    audit_cmd.add_argument('--format', choices=('json', 'markdown'), default='json')
    audit_cmd.add_argument('--fail-on', choices=('high', 'critical'))
    compiler = commands.add_parser('compile')
    compiler.add_argument('config')
    compiler.add_argument('--tasks', required=True)
    bench = commands.add_parser('benchmark')
    bench.add_argument('--fixtures', default=str(files('agentcap').joinpath('fixtures')))
    bench.add_argument('--format', choices=('text', 'json'), default='text')
    for cmd in (audit_cmd, compiler, bench):
        cmd.add_argument('-o', '--output')
    args = parser.parse_args(argv)
    try:
        code = 0
        if args.command == 'audit':
            result = audit(parse(load(args.config)))
            output = markdown(result) if args.format == 'markdown' else json.dumps(result, indent=2) + '\n'
            levels = {'high': {'high', 'critical'}, 'critical': {'critical'}}
            if args.fail_on and any(f['severity'] in levels[args.fail_on] for f in result['findings']):
                code = 1
        elif args.command == 'compile':
            result = compile_policy(parse(load(args.config)), load(args.tasks))
            output = json.dumps(result, indent=2) + '\n'
        else:
            result = benchmark(args.fixtures)
            if args.format == 'json':
                output = json.dumps(result, indent=2) + '\n'
            else:
                output = 'Task                     Granted Compiled Reduction\n'
                for row in result['tasks']:
                    output += f"{row['task']:<24} {row['granted']:>7} {row['compiled']:>8} {row['reduction_percent']:>8.2f}%\n"
                output += f"Mean reduction: {result['mean_reduction_percent']:.2f}%\n"
        if args.output:
            Path(args.output).write_text(output, encoding='utf-8')
        else:
            sys.stdout.write(output)
        return code
    except (InputError, OSError, KeyError, TypeError) as exc:
        print(f'agentcap: {exc}', file=sys.stderr)
        return 2

import json
from pathlib import Path
import pytest
from agentcap.core import (InputError, RULES, audit, authority_count, benchmark,
                           classify, compile_policy, load, markdown, parse, reduction)

FIXTURES = Path(__file__).parents[1] / 'agentcap' / 'fixtures'


def manifest(**tool):
    return {'version': 1, 'tools': [{'name': 'read_docs', **tool}]}


@pytest.mark.parametrize('tier,term', [(tier, words[0]) for tier, words in RULES.items()])
def test_rule_table(tier, term):
    assert tier in classify(term)


def test_classifier_multilabel_unknown_and_boundaries():
    assert classify('read_secret') == ('read', 'secrets_access')
    assert classify('shellfish') == ('unknown',)
    assert 'filesystem_write' in classify('writeFile')
    assert 'shell_execution' in classify('execute', ['read'])
    with pytest.raises(InputError):
        classify('read', ['invalid'])


@pytest.mark.parametrize('bad', [None, [], {}, {'version': 2, 'tools': []},
    manifest(scopes='*'), manifest(tiers=['wrong']), manifest(name=''),
    {'version':1,'tools':[{'name':'read'},{'name':'read'}]},
    {'mcpServers':{'x':{}}}, {'mcpServers':{'x':{'url':'file:///tmp'}}},
    {'mcpServers':{'x':{'command':'python','url':'https://example.org'}}},
    {'mcpServers':{},'tools':[]}])
def test_invalid_inputs(bad):
    with pytest.raises(InputError):
        parse(bad)


def test_manifest_deterministic():
    caps = parse(manifest(scopes=['b','a','a']))
    assert caps[0].scopes == ('a','b')


def test_mcp_transport_does_not_invent_inventory():
    caps = parse({'mcpServers':{'docs':{'url':'https://docs.example.org/mcp'}}})
    assert len(caps) == 2
    assert caps[0].hosts == ('docs.example.org',)
    assert caps[1].tiers == ('unknown',)


def test_mcp_declared_inventory():
    caps = parse({'mcpServers':{'local':{'command':'python','args':['server.py'],
                                     'tools':[{'name':'read_docs','scopes':['doc:1']}]}}})
    assert {c.name for c in caps} == {'local:transport','local:read_docs'}
    assert 'shell_execution' in next(c for c in caps if c.name.endswith('transport')).tiers


def test_findings_and_secret_redaction():
    data={'version':1,'tools':[{'name':'shell_write_file_fetch_url','scopes':['*'],
          'paths':['/'],'hosts':['*'],'env':{'API_TOKEN':'do-not-disclose'}}]}
    report=audit(parse(data))
    codes={f['code'] for f in report['findings']}
    assert {'shell_execution','wildcard_scope','unrestricted_filesystem',
            'unscoped_network','secret_environment'} <= codes
    for f in report['findings']:
        assert f['severity'] and f['evidence'] and f['remediation']
    assert 'do-not-disclose' not in json.dumps(report) + markdown(report)
    assert 'API_TOKEN' in json.dumps(report)


def test_missing_allowlists_and_unknown():
    report=audit(parse(manifest(name='fetch')))
    assert {f['code'] for f in report['findings']} == {'unscoped_network','missing_allowlist'}
    assert audit(parse(manifest(name='mystery')))['findings'][0]['code']=='unknown_authority'


@pytest.mark.parametrize('path', ['/', '*', '/tmp/*', 'C:\\', '~', '.', '..'])
def test_unrestricted_paths(path):
    assert any(f['code']=='unrestricted_filesystem' for f in audit(parse(manifest(paths=[path])))['findings'])


def test_scoped_read_is_clean():
    assert audit(parse(manifest(scopes=['doc:1'])))['findings'] == []


def test_compile_narrows_and_omits_env():
    caps=parse(manifest(scopes=['*'],env={'API_TOKEN':'value'}))
    policy=compile_policy(caps,{'tasks':[{'name':'summary','requires':[{'name':'read_docs','scopes':['doc:1']}]}]})
    assert policy['default']=='deny'
    assert policy['tools']==[{'name':'read_docs','tiers':['read'],'scopes':['doc:1'],'paths':[],'hosts':[]}]
    assert 'value' not in json.dumps(policy)


@pytest.mark.parametrize('requirement', [
    {'name':'missing'}, {'name':'read_docs'}, {'name':'read_docs','scopes':['*']},
    {'name':'read_docs','scopes':['doc:2']}])
def test_compile_rejects_unsafe_requirements(requirement):
    with pytest.raises(InputError):
        compile_policy(parse(manifest(scopes=['doc:1'])),{'tasks':[{'name':'t','requires':[requirement]}]})


def test_compile_unknown_empty_and_duplicate_tasks():
    caps=parse(manifest(name='opaque'))
    with pytest.raises(InputError):
        compile_policy(caps,{'tasks':[{'name':'t','requires':[{'name':'opaque'}]}]})
    assert compile_policy(caps,{'tasks':[]})['tools']==[]
    with pytest.raises(InputError):
        compile_policy(caps,{'tasks':[{'name':'t','requires':[]},{'name':'t','requires':[]}]})


def test_compile_union_does_not_duplicate_grants():
    caps=parse(manifest(scopes=['*']))
    policy=compile_policy(caps,{'tasks':[{'name':n,'requires':[{'name':'read_docs','scopes':[n]}]} for n in ('a','b')]})
    assert policy['tools'][0]['scopes']==['a','b']
    assert authority_count(parse(policy))==1


def test_math():
    assert reduction(8,2)==75
    assert reduction(0,0)==0
    assert reduction(7,7)==0
    for args in [(0,1),(-1,0),(2,-1)]:
        with pytest.raises(InputError):
            reduction(*args)


def test_fixture_benchmark_computed_and_mutation(tmp_path):
    result=benchmark(FIXTURES)
    assert len(result['tasks'])==10
    percentages=[]
    for path,row in zip(sorted(FIXTURES.glob('*.json')),result['tasks']):
        data=load(path)
        caps=parse(data['manifest'])
        after=parse(compile_policy(caps,{'tasks':[data['task']]}))
        expected=100*(authority_count(caps)-authority_count(after))/authority_count(caps)
        assert row['reduction_percent']==pytest.approx(expected)
        percentages.append(expected)
    assert result['mean_reduction_percent']==pytest.approx(sum(percentages)/len(percentages))
    data=load(next(FIXTURES.glob('*.json')))
    (tmp_path/'one.json').write_text(json.dumps(data))
    original=benchmark(tmp_path)
    data['manifest']['tools'].append({'name':'read_extra','scopes':['*']})
    (tmp_path/'one.json').write_text(json.dumps(data))
    assert benchmark(tmp_path)['mean_reduction_percent'] > original['mean_reduction_percent']


def test_empty_benchmark_and_bad_json(tmp_path):
    with pytest.raises(InputError):
        benchmark(tmp_path)
    p=tmp_path/'bad.json'
    p.write_text('{')
    with pytest.raises(InputError):
        load(p)


def test_mcp_compiler_requires_transport():
    caps = parse({'mcpServers': {'docs': {'url':'https://docs.example.org/mcp',
                  'tools':[{'name':'read_page','scopes':['page:42']}]}}})
    tasks = {'tasks':[{'name':'read','requires':[{'name':'docs:read_page','scopes':['page:42']}]}]}
    with pytest.raises(InputError, match='transport requirement'):
        compile_policy(caps, tasks)
    tasks['tasks'][0]['requires'].append({'name':'docs:transport','hosts':['docs.example.org']})
    assert len(compile_policy(caps,tasks)['tools']) == 2


def test_markdown_escapes_untrusted_names():
    report = audit(parse(manifest(name='<script>[link](url)')))
    result = markdown(report)
    assert '<script>' not in result
    assert '[link]' not in result

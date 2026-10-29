import json
from agentcap.cli import main


def test_cli_roundtrip(tmp_path,capsys):
    config=tmp_path/'config.json'
    config.write_text(json.dumps({'version':1,'tools':[{'name':'read_docs','scopes':['*']}]}))
    assert main(['audit',str(config),'--fail-on','high'])==1
    report=json.loads(capsys.readouterr().out)
    assert report['capability_count']==1
    output=tmp_path/'audit.md'
    assert main(['audit',str(config),'--format','markdown','-o',str(output)])==0
    assert output.read_text().startswith('# AgentCap audit')
    tasks=tmp_path/'tasks.json'
    tasks.write_text(json.dumps({'tasks':[{'name':'summary','requires':[{'name':'read_docs','scopes':['doc:1']}]}]}))
    assert main(['compile',str(config),'--tasks',str(tasks)])==0
    assert json.loads(capsys.readouterr().out)['default']=='deny'


def test_cli_benchmark_and_errors(capsys):
    assert main(['benchmark','--format','json'])==0
    assert len(json.loads(capsys.readouterr().out)['tasks'])==10
    assert main(['audit','nonexistent.json'])==2
    assert 'cannot read JSON' in capsys.readouterr().err

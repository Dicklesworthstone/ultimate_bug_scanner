import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'modules/helpers'))
from ubs_core.analyzers import taint_py
from ubs_core.registry import RunContext

CASES=[
    ('text','import sys\neval(next(filter(None,sys.stdin)))\n',['input\n'],1),
    ('binary','import sys\neval(next(filter(None,sys.stdin.buffer)))\n',['input\n'],1),
    ('raw','import sys\neval(next(filter(None,sys.stdin.buffer.raw)))\n',['input\n'],1),
    ('saved_factory','import sys\nmake=filter\neval(next(make(None,sys.stdin)))\n',['input\n'],1),
    ('imported_factory','import sys\nfrom builtins import filter as select\neval(next(select(None,sys.stdin)))\n',['input\n'],1),
    ('aliased_cursor','import sys\nit=filter(None,sys.stdin)\nalias=it\nnext(it)\neval(next(alias))\n',['second\n'],1),
    ('helper_factory','import sys\ndef select(stream):\n return filter(None,stream)\neval(next(select(sys.stdin)))\n',['input\n'],1),
    ('loop','import sys\nfor line in filter(None,sys.stdin):\n eval(line)\n',['input\n','second\n'],1),
    ('joined','import sys\neval("".join(filter(None,sys.stdin)))\n',['input\nsecond\n'],1),
    ('materialized','import sys\nlines=list(filter(None,sys.stdin))\neval(lines[0])\n',['input\n'],1),
    ('unused_cursor','import sys\nit=filter(None,sys.stdin)\neval("safe")\n',['safe'],0),
    ('empty_vector','eval(next(filter(None,[]),"safe"))\n',['safe'],0),
    ('clean_vector','eval(next(filter(None,["safe"])))\n',['safe'],0),
    ('zero_read','import sys\neval(next(filter(None,[sys.stdin.read(0)]),"safe"))\n',['safe'],0),
    ('shadow','import sys\ndef filter(*args):\n return iter(["safe"])\neval(next(filter(None,sys.stdin)))\n',['safe'],0),
    ('predicate_does_not_replace','import sys\neval(next(filter(lambda line: "safe",sys.stdin)))\n',['input\n'],1),
    ('capture_before_rebind','import sys\nmake=filter\nfilter=None\neval(next(make(None,sys.stdin)))\n',['input\n'],1),
]

directory=Path(tempfile.mkdtemp(prefix='independent-filter-',dir=ROOT/'test-suite/artifacts'))
wrong=exact=partial=0
for name,source,expected_values,expected in CASES:
    native=('import json\nseen=[]\n'
            'def record(value):\n seen.append(value.decode() if isinstance(value,bytes) else value)\n'
            'exec('+repr(source)+',{"eval":record})\nprint(json.dumps(seen))\n')
    run=subprocess.run([sys.executable,'-c',native],input='input\nsecond\n',capture_output=True,text=True,timeout=10)
    assert run.returncode==0,(name,run.stderr)
    assert json.loads(run.stdout)==expected_values,(name,run.stdout,expected_values)
    path=directory/(name+'.py')
    path.write_text(source)
    found=[]
    try:
        for finding in taint_py.run(RunContext(lang='python',files=[path])):
            found.append(finding)
    except Exception as exc:
        partial+=1
        print(json.dumps({'case':name,'status':'partial','reason':str(exc),'retained':len(found)}),flush=True)
    else:
        count=sum(f['rule']=='python.taint.eval' for f in found)
        ok=count==expected
        exact+=int(ok)
        wrong+=int(not ok)
        print(json.dumps({'case':name,'status':'exact' if ok else 'incorrect-complete','expected':expected,'actual':count}),flush=True)
print(json.dumps({'exact':exact,'partial':partial,'incorrect_complete':wrong,'cases':len(CASES),'fixtures':str(directory)}))
sys.exit(bool(wrong))

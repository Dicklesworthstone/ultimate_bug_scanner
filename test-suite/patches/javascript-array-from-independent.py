import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules/helpers'))
from ubs_core.analyzers import taint_js
from ubs_core.registry import RunContext

# Native output labels are fixed before looking at candidate analysis results.
CASES = [
    ('mapped_source', 'const out=Array.from([1], v=>req.query.html); res.send(out[0]);', ['input'], 1),
    ('mapped_clean', 'const out=Array.from([req.query.html], v=>"safe"); res.send(out[0]);', ['safe'], 0),
    ('callback_effect', 'const box={html:"safe"}; Array.from([1], v=>{box.html=req.query.html; return v;}); res.send(box.html);', ['input'], 1),
    ('hole_callback', 'const out=Array.from([,], v=>req.query.html); res.send(out[0]);', ['input'], 1),
    ('live_growth', 'const src=["safe"]; const out=Array.from(src,(v,i)=>{if(i===0)src.push(req.query.html);return v;}); res.send(out[1]);', ['input'], 1),
    ('live_shrink', 'const src=["safe",req.query.html]; const out=Array.from(src,(v,i)=>{src.length=0;return v;}); res.send(out[1]);', [None], 0),
    ('mapper_arity', 'const out=Array.from([req.query.html],function(v,i,third){return third===undefined ? "safe" : v;}); res.send(out[0]);', ['safe'], 0),
    ('this_argument', 'const out=Array.from(["safe"],function(v){return this.html;},{html:req.query.html}); res.send(out[0]);', ['input'], 1),
    ('saved_native', 'const from=Array.from; const out=from([1],v=>req.query.html); res.send(out[0]);', ['input'], 1),
    ('shadowed_factory', 'const Array={from(values,fn){return ["safe"];}}; res.send(Array.from([req.query.html],v=>v)[0]);', ['safe'], 0),
    ('mapper_argument_effect', 'const src=["safe"]; function mapper(){src.push(req.query.html);return v=>v;} const out=Array.from(src,mapper()); res.send(out[1]);', ['input'], 1),
    ('borrowed_object', 'const box={html:"safe"}; const out=Array.from([box]); box.html=req.query.html; res.send(out[0].html);', ['input'], 1),
    ('fresh_outer', 'const src=[req.query.html]; const out=Array.from(src); out[0]="safe"; res.send(src[0]); res.send(out[0]);', ['input','safe'], 1),
    ('iterator_override', 'const src=[]; src[Symbol.iterator]=function*(){yield req.query.html;}; const out=Array.from(src); res.send(out[0]);', ['input'], 1),
    ('empty_no_callback', 'const box={html:"safe"}; Array.from([],v=>{box.html=req.query.html;}); res.send(box.html);', ['safe'], 0),
    ('selected_helper', 'function clone(src,fn){return Array.from(src,fn);} const out=clone(["safe"],v=>req.query.html); res.send(out[0]);', ['input'], 1),
    ('safe_index', 'const out=Array.from([req.query.html],(v,i)=>i); res.send(out[0]);', [0], 0),
    ('array_like_source', 'const out=Array.from({0:req.query.html,length:1}); res.send(out[0]);', ['input'], 1),
]

directory = Path(tempfile.mkdtemp(prefix='independent-array-from-', dir=ROOT/'test-suite/artifacts'))
wrong = 0
exact = 0
partial = 0
for name, source, native_expected, finding_expected in CASES:
    fixture = ('const vm=require("node:vm"); const out=[]; vm.runInNewContext(' + json.dumps(source)
               + ',{req:{query:{html:"input"}},res:{send(v){out.push(v)}}},{timeout:3000}); process.stdout.write(JSON.stringify(out));')
    native = subprocess.run(['node','-e',fixture], capture_output=True, text=True, timeout=10)
    assert native.returncode == 0, (name,native.stderr)
    assert json.loads(native.stdout) == native_expected, (name,native.stdout,native_expected)
    path = directory/(name+'.js')
    path.write_text(source+'\n')
    found=[]
    try:
        found=list(taint_js.run(RunContext(lang='javascript',files=[path])))
    except Exception as exc:
        partial += 1
        print(json.dumps({'case':name,'status':'partial','reason':str(exc)}), flush=True)
    else:
        count=sum(f['rule']=='javascript.taint.xss' for f in found)
        ok=count==finding_expected
        exact+=int(ok)
        wrong+=int(not ok)
        print(json.dumps({'case':name,'status':'exact' if ok else 'incorrect-complete','expected':finding_expected,'actual':count}),flush=True)
print(json.dumps({'exact':exact,'partial':partial,'incorrect_complete':wrong,'cases':len(CASES),'fixtures':str(directory)}))
sys.exit(bool(wrong))

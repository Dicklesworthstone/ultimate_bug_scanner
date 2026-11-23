import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'modules/helpers'))
from ubs_core.analyzers import taint_go
from ubs_core.registry import RunContext

CASES = [
    ('request_full','buf:=make([]byte,8)\nio.ReadFull(r.Body,buf)\ndb.Query(string(buf))',1),
    ('request_at_least','buf:=make([]byte,8)\nio.ReadAtLeast(r.Body,buf,1)\ndb.Query(string(buf))',1),
    ('buffer_alias','buf:=make([]byte,8)\nalias:=buf\nio.ReadFull(r.Body,alias)\ndb.Query(string(buf))',1),
    ('rebound_alias','buf:=make([]byte,8)\nalias:=buf\nalias=make([]byte,8)\nio.ReadFull(r.Body,alias)\ndb.Query(string(buf))\ndb.Query(string(alias))',1),
    ('literal_input','buf:=make([]byte,8)\nio.ReadFull(strings.NewReader("constant"),buf)\ndb.Query(string(buf))',0),
    ('empty_buffer','buf:=make([]byte,0)\nio.ReadFull(r.Body,buf)\ndb.Query(string(buf))',0),
    ('zero_minimum','buf:=make([]byte,8)\nio.ReadAtLeast(r.Body,buf,0)\ndb.Query(string(buf))',0),
    ('negative_minimum','buf:=make([]byte,8)\nio.ReadAtLeast(r.Body,buf,-1)\ndb.Query(string(buf))',0),
    ('too_large_minimum','buf:=make([]byte,8)\nio.ReadAtLeast(r.Body,buf,9)\ndb.Query(string(buf))',0),
    ('read_result_metadata','buf:=make([]byte,8)\nn,err:=io.ReadFull(r.Body,buf)\ndb.Query(fmt.Sprint(n))\ndb.Query(fmt.Sprint(err))',0),
    ('bound_query','buf:=make([]byte,8)\nio.ReadFull(r.Body,buf)\ndb.Query("SELECT $1",string(buf))',0),
    ('overwritten_binding','buf:=make([]byte,8)\nio.ReadFull(r.Body,buf)\nbuf=[]byte("safe")\ndb.Query(string(buf))',0),
    ('sliced_alias','buf:=make([]byte,8)\nalias:=buf[1:]\nio.ReadFull(r.Body,alias)\ndb.Query(string(buf))',1),
    ('saved_native','buf:=make([]byte,8)\nread:=io.ReadFull\nread(r.Body,buf)\ndb.Query(string(buf))',1),
    ('stdin_source','buf:=make([]byte,8)\nio.ReadFull(os.Stdin,buf)\ndb.Query(string(buf))',1),
    ('short_read_retains_source','buf:=make([]byte,8)\nif n,err:=io.ReadFull(r.Body,buf);err!=nil {db.Query(string(buf[:n]))}',1),
    ('separate_allocation','buf:=make([]byte,8)\nother:=make([]byte,8)\nio.ReadFull(r.Body,buf)\ndb.Query(string(other))',0),
    ('dirty_buffer_no_read','buf:=[]byte(r.FormValue("q"))\nio.ReadAtLeast(r.Body,buf,0)\ndb.Query(string(buf))',1),
]
directory=Path(tempfile.mkdtemp(prefix='independent-read-into-',dir=ROOT/'test-suite/artifacts'))
wrong=exact=partial=0
for name,body,expected in CASES:
    path=directory/(name+'.go')
    path.write_text('package app\nimport ("io"; "os"; "fmt"; "strings")\nfunc handler(){\n'+body+'\n}\n')
    found=[]
    try:
        for finding in taint_go.run(RunContext(lang='go',files=[path])):
            found.append(finding)
    except Exception as exc:
        partial+=1
        print(json.dumps({'case':name,'status':'partial','reason':str(exc),'retained':len(found)}),flush=True)
    else:
        count=sum(f['rule']=='go.taint.sql' for f in found)
        ok=count==expected
        exact+=int(ok)
        wrong+=int(not ok)
        print(json.dumps({'case':name,'status':'exact' if ok else 'incorrect-complete','expected':expected,'actual':count}),flush=True)
print(json.dumps({'exact':exact,'partial':partial,'incorrect_complete':wrong,'cases':len(CASES),'fixtures':str(directory)}))
sys.exit(bool(wrong))

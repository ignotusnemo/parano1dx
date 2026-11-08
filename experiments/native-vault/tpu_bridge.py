"""Local bridge to the official Agave TPU sender. Keys stay in the signer."""
from pathlib import Path
import base64,json,os,queue,subprocess,threading,urllib.parse

class DirectTpu:
    def __init__(self,binary,profile):
        access=json.loads(Path(profile).read_text())
        secrets=[access.get('http_url',''),access.get('websocket_url','')]
        secrets += [v for _,v in urllib.parse.parse_qsl(urllib.parse.urlsplit(access.get('http_url','')).query)]
        def clean(value):
            text=str(value)
            for secret in secrets:
                if secret:text=text.replace(secret,'[private RPC]')
            return text
        self.clean=clean;self.lock=threading.Lock();self.messages=queue.Queue();self.ident=0
        self.errors=[]
        self.process=subprocess.Popen([str(binary),str(profile)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,text=True,bufsize=1,env={**os.environ,'RUST_LOG':'off','RUST_BACKTRACE':'0'})
        def stdout():
            for line in self.process.stdout:
                try:self.messages.put(json.loads(clean(line)))
                except json.JSONDecodeError:self.errors.append(clean(line))
            self.messages.put({'error':'TPU sender closed'})
        def stderr():
            for line in self.process.stderr:self.errors.append(clean(line))
        threading.Thread(target=stdout,daemon=True).start();threading.Thread(target=stderr,daemon=True).start()
        try:ready=self.messages.get(timeout=90)
        except queue.Empty:self.close();raise TimeoutError('TPU initialization deadline')
        if not ready.get('ready'):
            self.close();raise RuntimeError(clean(ready.get('error','TPU initialization failed')))
        self.ready=ready
    def send(self,wire):
        return self.send_many([wire])
    def send_many(self,wires):
        if not 1<=len(wires)<=64:raise ValueError('One to 64 public transaction wires required')
        with self.lock:
            self.ident+=1
            self.process.stdin.write(json.dumps({'id':self.ident,'transactions':[base64.b64encode(wire).decode() for wire in wires]})+'\n')
            self.process.stdin.flush()
            try:result=self.messages.get(timeout=30)
            except queue.Empty:raise TimeoutError('TPU transport deadline')
            if result.get('id')!=self.ident or result.get('submitted')!=len(wires):
                raise RuntimeError(self.clean(result.get('error','TPU submission failed')))
            return result
    def close(self):
        process=getattr(self,'process',None)
        if process and process.poll() is None:
            try:process.stdin.write('{"op":"close"}\n');process.stdin.flush();process.wait(timeout=5)
            except (OSError,subprocess.TimeoutExpired):process.terminate()

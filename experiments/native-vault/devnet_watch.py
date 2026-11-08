"""Public progress notifications over a private WebSocket connection."""
from pathlib import Path
import base64,json,threading

class DevnetWatch:
    def __init__(self,profile):
        from websockets.sync.client import connect
        access=json.loads(Path(profile).read_text())
        self.condition=threading.Condition();self.send_lock=threading.Lock()
        self.values={};self.requests={};self.subscriptions={};self.ident=0
        self.events=0;self.ready=False;self.closed=False
        self.socket=connect(access['websocket_url'],open_timeout=8,close_timeout=2,proxy=None)
        self.ready=True
        def read():
            try:
                for payload in self.socket:
                    body=json.loads(payload)
                    with self.condition:
                        if 'id' in body:
                            command=self.requests.pop(body['id'],None)
                            if command and 'result' in body:self.subscriptions[body['result']]=command
                            elif command:self.values[command['tag']]={'event':'subscription_error','code':body.get('error',{}).get('code')}
                            self.condition.notify_all();continue
                        params=body.get('params',{});command=self.subscriptions.get(params.get('subscription'))
                        if not command:continue
                        result=params['result'];value=result['value'];self.events+=1
                        if command['op']=='account':
                            data=value.get('data') if value else None
                            header=base64.b64encode(base64.b64decode(data[0])[:256]).decode() if data else None
                            event={'event':'account','tag':command['tag'],'slot':result['context']['slot'],'header_base64':header}
                        else:
                            event={'event':'signature','tag':command['tag'],'slot':result['context']['slot'],'error':value.get('err')}
                            self.subscriptions.pop(params['subscription'],None)
                        self.values[command['tag']]=event;self.condition.notify_all()
            except Exception:
                with self.condition:self.ready=False;self.condition.notify_all()
        self.reader=threading.Thread(target=read,daemon=True);self.reader.start()
    def subscribe(self,command):
        with self.send_lock:
            if not self.ready:return
            self.ident+=1
            with self.condition:self.requests[self.ident]=command
            account=command['op']=='account'
            params=[command['pubkey'],{'encoding':'base64','commitment':command.get('level','confirmed')}] if account else [command['signature'],{'commitment':command.get('level','confirmed'),'enableReceivedNotification':False}]
            try:self.socket.send(json.dumps({'jsonrpc':'2.0','id':self.ident,'method':'accountSubscribe' if account else 'signatureSubscribe','params':params}))
            except Exception:self.ready=False
    def wait(self,tag,timeout=.4):
        with self.condition:
            self.condition.wait_for(lambda:tag in self.values,timeout=timeout)
            return self.values.get(tag)
    def close(self):
        self.closed=True;self.socket.close();self.reader.join(timeout=2)

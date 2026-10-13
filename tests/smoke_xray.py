"""Real VLESS -> TCP fixture, in an ephemeral CI runner. No Internet traffic."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer

binary=str(Path(sys.argv[1]).resolve())
payload=b'Rasad measured payload\n'*8192
class PayloadHandler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        self.send_response(200);self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)

target=ThreadingHTTPServer(('127.0.0.1',15502),PayloadHandler)
threading.Thread(target=target.serve_forever,daemon=True).start()
uuid='550e8400-e29b-41d4-a716-446655440000'
with tempfile.TemporaryDirectory(prefix='rasad-xray-smoke-') as directory:
    root=Path(directory);policy=root/'policy.json';metrics=root/'domains.json'
    policy.write_text(json.dumps({'enabled':True,'expires':int(time.time())+300,'users':{'smoke-user':123}}))
    server={'log':{'loglevel':'debug'},'inbounds':[{'listen':'127.0.0.1','port':15500,'protocol':'vless','settings':{'clients':[{'id':uuid,'email':'smoke-user'}],'decryption':'none'}}],'outbounds':[{'protocol':'freedom','settings':{'redirect':'127.0.0.1:15502','finalRules':[{'action':'allow','network':'tcp','ip':['127.0.0.1/32'],'port':15502}]}}]}
    client={'log':{'loglevel':'error'},'inbounds':[{'listen':'127.0.0.1','port':15501,'protocol':'http','settings':{}}],'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':15500,'users':[{'id':uuid,'encryption':'none'}]}]}}]}
    (root/'server.json').write_text(json.dumps(server));(root/'client.json').write_text(json.dumps(client))
    env=dict(os.environ,RASAD_POLICY=str(policy),RASAD_METRICS=str(metrics))
    running=[]
    for file in ('server.json','client.json'):
        subprocess.run([binary,'run','-test','-config',str(root/file)],check=True)
    def request_payload():
        with socket.create_connection(('127.0.0.1',15501),timeout=5) as conn:
            conn.sendall(b'GET http://localhost:15502/payload HTTP/1.1\r\nHost: localhost:15502\r\nConnection: close\r\n\r\n')
            response=b''
            while True:
                part=conn.recv(65536)
                if not part:break
                response+=part
                # HTTP proxy transports may remain open after a complete response.
                if b'\r\n\r\n' in response and len(response.split(b'\r\n\r\n',1)[1])>=len(payload):
                    break
            assert response.split(b'\r\n\r\n',1)[1]==payload,'proxy path failed to deliver expected payload'
    try:
        running.append(subprocess.Popen([binary,'run','-config',str(root/'server.json')],env=env))
        running.append(subprocess.Popen([binary,'run','-config',str(root/'client.json')],env={k:v for k,v in os.environ.items() if k not in ('RASAD_POLICY','RASAD_METRICS')}))
        # Wait for policy load and listeners, then send the fixture through VLESS.
        time.sleep(6)
        request_payload()
        for attempt in range(20):
            if metrics.exists():
                snapshot=json.loads(metrics.read_text())
                rows=[r for r in snapshot['rows'] if r['email']=='smoke-user' and r['domain']=='localhost']
                if rows and rows[0]['down']>=len(payload):break
            time.sleep(1)
        assert rows and rows[0]['up']>0 and rows[0]['down']>=len(payload),'dispatch measurement was not exported'
        before=rows[0]['down']
        policy.write_text(json.dumps({'enabled':False,'expires':int(time.time())+300,'users':{'smoke-user':123}}))
        time.sleep(6)
        request_payload()
        time.sleep(16)
        after=[r for r in json.loads(metrics.read_text())['rows'] if r['email']=='smoke-user' and r['domain']=='localhost'][0]['down']
        assert after==before,'disabled telemetry continued counting'
        print('Actual VLESS forwarding, destination payload counters and policy disable: PASS')
    finally:
        for process in running:
            process.terminate();process.wait(timeout=10)
        target.shutdown();target.server_close()

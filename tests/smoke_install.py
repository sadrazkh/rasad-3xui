"""Ubuntu CI only: install the real service with a local mock 3x-ui."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
from urllib.request import Request,urlopen
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from server import password_hash

class MockPanel(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        obj=[{'id':1,'remark':'smoke','protocol':'vless','settings':{'clients':[{'email':'smoke-user','enable':True}]},'clientStats':[{'email':'smoke-user','up':100,'down':200,'total':10000}]}]
        self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers()
        self.wfile.write(json.dumps({'success':True,'obj':obj}).encode())
    def do_POST(self):
        self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers()
        self.wfile.write(b'{"success":true,"obj":["smoke-user"]}')

if sys.platform!='linux':raise SystemExit('This smoke test runs only on an ephemeral Ubuntu CI runner')
mock=ThreadingHTTPServer(('127.0.0.1',2053),MockPanel)
threading.Thread(target=mock.serve_forever,daemon=True).start()
config={'panel_url':'http://127.0.0.1:2053','panel_token':'ci-fixture-token','admin_username':'admin',
        'admin_password_hash':password_hash('ci fixture long password'),'public_origin':'http://localhost:8787',
        'listen':'127.0.0.1','port':8787,'database':'/var/lib/rasad/rasad.db','timezone':'Asia/Tehran','access_log':'',
        'domain_policy':'/run/rasad/policy.json','domain_metrics':'/run/rasad/domains.json'}
temp=Path('/tmp/rasad-ci-config.json');temp.write_text(json.dumps(config));temp.chmod(0o600)
try:
    subprocess.run(['sudo','install','-d','-m','0750','/etc/rasad'],check=True)
    subprocess.run(['sudo','install','-m','0600',str(temp),'/etc/rasad/config.json'],check=True)
    subprocess.run(['sudo','bash','install.sh'],check=True)
    # Plain dashboard installation must leave core byte metering disabled.
    status=subprocess.check_output(['sudo','rasad','sites','status'],text=True)
    assert 'disabled' in status
    assert not Path('/etc/systemd/system/x-ui.service.d/90-rasad-sites.conf').exists()
    response=urlopen(Request('http://127.0.0.1:8787/api/login',data=json.dumps({'username':'admin','password':'ci fixture long password'}).encode(),headers={'Content-Type':'application/json','Origin':'http://localhost:8787'}))
    cookie=response.headers['Set-Cookie'].split(';')[0];response.close()
    for attempt in range(15):
        data=json.load(urlopen(Request('http://127.0.0.1:8787/api/report',headers={'Cookie':cookie})))
        if len(data['users'])==1:break
        time.sleep(1)
    assert data['users'][0]['email']=='smoke-user'
    assert data['users'][0]['up']==100 and data['users'][0]['down']==200
    assert data['users'][0]['period_up']==0 and data['users'][0]['period_down']==0
    assert not data['settings']['domains_enabled']
    assert data['mode']=='live'
    print('Ubuntu installation, systemd health, admin login and real collector API: PASS')
finally:
    mock.shutdown();mock.server_close()
    subprocess.run(['sudo','systemctl','stop','rasad'],check=False)

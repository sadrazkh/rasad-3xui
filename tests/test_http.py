import json
import io
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch
from urllib import request,error
from http.server import ThreadingHTTPServer
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"backend"))
from server import App, handler_for, password_hash
from core import Store


class LoginLimitTests(unittest.TestCase):
    def test_parallel_login_attempts_share_one_budget(self):
        store = Store(":memory:")
        self.addCleanup(store.db.close)
        app = App({"admin_username": "admin", "admin_password_hash": "unused", "public_origin": "http://localhost"}, store)
        Handler = handler_for(app)
        hashing = threading.Barrier(8)
        def wrong_password(*_):
            hashing.wait(timeout=5)
            return False
        def attempt(_):
            body = b'{"username":"admin","password":"wrong"}'
            handler = Handler.__new__(Handler)
            handler.path = "/api/login"
            handler.client_address = ("127.0.0.1", 1234)
            handler.headers = {"Origin": "http://localhost", "Content-Length": str(len(body))}
            handler.rfile = io.BytesIO(body)
            statuses = []
            handler.respond = lambda status, *args, **kwargs: statuses.append(status)
            handler.do_POST()
            return statuses[0]
        with patch("server.password_ok", side_effect=wrong_password), ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(list(pool.map(attempt, range(8))), [401] * 8)
            self.assertEqual(list(pool.map(attempt, range(8))), [429] * 8)
        self.assertEqual(app.failures["127.0.0.1"][0], 8)


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store=Store(":memory:")
        cls.app=App({"admin_username":"admin","admin_password_hash":password_hash("correct long password"),"public_origin":"http://localhost"},cls.store)
        cls.server=ThreadingHTTPServer(("127.0.0.1",0),handler_for(cls.app))
        cls.base=f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever,daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.store.db.close()

    def send(self,path,data=None,headers=None):
        headers=headers or {}
        if data is not None: headers=dict(headers,**{"Content-Type":"application/json"});data=json.dumps(data).encode()
        req=request.Request(self.base+path,data=data,headers=headers)
        try:response=request.urlopen(req)
        except error.HTTPError as e:response=e
        with response:return response.status,response.headers,response.read()

    def test_auth_csrf_and_headers(self):
        self.assertEqual(self.send("/api/report")[0],401)
        credentials={"username":"admin","password":"correct long password"}
        self.assertEqual(self.send("/api/login",credentials,{"Origin":"https://evil.example"})[0],403)
        status,headers,body=self.send("/api/login",credentials,{"Origin":"http://localhost"})
        self.assertEqual(status,200)
        self.assertIn("HttpOnly",headers["Set-Cookie"])
        self.assertIn("SameSite=Strict",headers["Set-Cookie"])
        cookie=headers["Set-Cookie"].split(";")[0];csrf=json.loads(body)["csrf"]
        self.assertEqual(self.send("/api/report",headers={"Cookie":cookie})[0],200)
        settings={"scope":"selected","interval":120,"retention":7,"domains_enabled":False}
        self.assertEqual(self.send("/api/settings",settings,{"Cookie":cookie,"Origin":"http://localhost"})[0],403)
        hdr={"Cookie":cookie,"Origin":"http://localhost","X-CSRF-Token":csrf}
        self.assertEqual(self.send("/api/settings",settings,hdr)[0],200)
        self.assertEqual(self.send("/api/logout",{},hdr)[0],200)
        self.assertEqual(self.send("/api/report",headers={"Cookie":cookie})[0],401)

    def test_runtime_and_no_source_traversal(self):
        self.assertEqual(json.loads(self.send("/runtime.json")[2])["mode"],"live")
        self.assertEqual(self.send("/../backend/server.py")[0],404)
        self.assertEqual(self.send("/config.json")[0],404)
        self.assertEqual(self.send("/api/health")[0],200)


if __name__=="__main__":unittest.main()

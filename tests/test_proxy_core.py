import base64
import os
import unittest
from unittest.mock import patch
from proxy_core import ServiceError, check_file, authenticate, inspect_file, clean_file, require_settings

class TestCore(unittest.TestCase):
    def setUp(self):
        self.env=patch.dict(os.environ,{
            "WATERMARKS_SERVICE_URL":"https://example.onrender.com",
            "WATERMARKS_SERVER_API_KEY":"upstream",
            "MCP_BEARER_TOKEN":"adapter",
        })
        self.env.start()
    def tearDown(self):
        self.env.stop()
    def test_authentication(self):
        self.assertTrue(authenticate([(b"authorization",b"Bearer adapter")]))
        self.assertFalse(authenticate([(b"authorization",b"Bearer upstream")]))
    def test_traversal(self):
        with self.assertRaises(ServiceError):
            check_file("../secret.docx",base64.b64encode(b"x").decode())
    def test_size(self):
        with self.assertRaises(ServiceError):
            check_file("file.png",base64.b64encode(b"x"*524289).decode())
    def test_upstream(self):
        encoded=base64.b64encode(b"test").decode()
        with patch("proxy_core.request_upstream",return_value={"ok":True,"kind":"text","report":{}}):
            self.assertTrue(inspect_file("x.txt",encoded)["ok"])
        with patch("proxy_core.request_upstream",return_value={"ok":True,"cleaned":encoded,"report":{}}):
            self.assertEqual(clean_file("x.txt",encoded)["output_sha256"],__import__("hashlib").sha256(b"test").hexdigest())
    def test_invalid_origin(self):
        with patch.dict(os.environ,{"WATERMARKS_SERVICE_URL":"http://example.com"}):
            with self.assertRaises(RuntimeError):
                require_settings()
if __name__=="__main__":unittest.main()

import base64
import gzip
import io
import os
import unittest
import zipfile
from unittest.mock import patch

from ctfou.api import ApiError, CTFdClient
from ctfou.solver import inspect_bytes, inspect_text, solve


class SolverTests(unittest.TestCase):
    def test_base64_extraction(self):
        encoded = base64.b64encode(b"THMH{encoded_secret}").decode()
        found = inspect_text("Payload=" + encoded, "question")
        self.assertTrue(any(f.flag == "THMH{encoded_secret}" for f in found))

    def test_hex_extraction(self):
        found = inspect_text("Hint: " + b"THMH{hex_found}".hex(), "question")
        self.assertTrue(any(f.flag == "THMH{hex_found}" for f in found))

    def test_reverse_extraction(self):
        found = inspect_text("}esrever{HMHT", "question")
        self.assertTrue(any(f.flag == "THMH{reverse}" for f in found))

    def test_zip_entry_and_gzip(self):
        memory = io.BytesIO()
        with zipfile.ZipFile(memory, "w") as archive:
            archive.writestr("evidence.txt", "THMH{zip_secret}")
        found = inspect_bytes(memory.getvalue(), "evidence.zip")
        self.assertTrue(any(f.flag == "THMH{zip_secret}" for f in found))
        compressed = gzip.compress(b"THMH{gzip_secret}")
        found = inspect_bytes(compressed, "evidence.gz")
        self.assertTrue(any(f.flag == "THMH{gzip_secret}" for f in found))

    def test_file_url_does_not_allow_cross_origin(self):
        client = CTFdClient("sample")
        for path in ["https://bad.example.com/files/key", "//bad.example.com/files/key", "/api/v1/challenges/attempt"]:
            with self.assertRaises(ApiError):
                client.attachment(path)

    def test_passive_solver_avoids_unnecessary_ai(self):
        class FakeClient:
            def attachment(self, path):
                return b"clue THMH{found_in_file}"
        challenge = {"name": "Sample", "description": "Download file", "files": ["/files/evidence.txt?token=signed"]}
        with patch.dict(os.environ, {"GROQ_API_KEY": "not-a-real-key"}):
            found = solve(challenge, FakeClient())
        self.assertEqual(found.flag, "THMH{found_in_file}")
        self.assertEqual(found.evidence, "extracted")


if __name__ == "__main__":
    unittest.main()

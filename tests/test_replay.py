import contextlib
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.replay import replay_file, main


class TestReplayTool(unittest.TestCase):
    def setUp(self):
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        self.ftth_file = os.path.join(self.fixtures_dir, "sample_ftth.json")
        self.docsis_file = os.path.join(self.fixtures_dir, "sample_docsis.json")

    def test_replay_file_execution(self):
        res = replay_file(self.ftth_file)
        self.assertIn("physical_medium", res)
        med = res["physical_medium"]
        self.assertIn("FTTH", med["predicted_medium"])
        self.assertIn("evidence", med)
        self.assertGreater(len(med["evidence"]), 0)
        # Verifica la presenza dei contributi per evidenza
        self.assertIn("contributions", med["evidence"][0])

    def test_replay_cli_single(self):
        buf = io.StringIO()
        old_argv = sys.argv
        sys.argv = ["replay.py", self.ftth_file]
        try:
            with contextlib.redirect_stdout(buf):
                main()
            out = buf.getvalue()
            self.assertIn("Mezzo Fisico Previsto : FTTH", out)
            self.assertIn("Confidenza Modello", out)
            self.assertIn("Evidenze e Contributi", out)
            self.assertIn("Contributi: FTTH", out)
        finally:
            sys.argv = old_argv

    def test_replay_cli_diff(self):
        buf = io.StringIO()
        old_argv = sys.argv
        sys.argv = ["replay.py", "--diff", self.ftth_file, self.docsis_file]
        try:
            with contextlib.redirect_stdout(buf):
                main()
            out = buf.getvalue()
            self.assertIn("CONFRONTO CLASSIFICAZIONI (DIFF):", out)
            self.assertIn("Mezzo Previsto [A] : FTTH", out)
            self.assertIn("Mezzo Previsto [B] : Indeterminato", out)
            self.assertIn("Delta Punteggi Totali [B - A]:", out)
            self.assertIn("DOCSIS", out)
        finally:
            sys.argv = old_argv


if __name__ == "__main__":
    unittest.main()

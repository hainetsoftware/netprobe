import unittest
from core.performance import PerformanceTester


class TestSummarize(unittest.TestCase):
    def test_zero_intervals_not_discarded(self):
        # Linea reale 15 Mbps, ma consegna a raffiche: 1 s su 2 a 30 Mbps, 1 s a 0
        pt = PerformanceTester()
        series, b = [(0.0, 0)], 0
        for i in range(1, 41):  # 8 s a passi di 0.2 s
            t = i * 0.2
            if int(t * 1) % 2 == 0:
                b += int(30e6 / 8 * 0.2)
            series.append((t, b))
        r = pt._summarize_stream(series, 1.5, 8.0)
        self.assertAlmostEqual(r["sustained_mbps"], 15.0, delta=2.5)

    def test_constant(self):
        pt = PerformanceTester()
        series = [(i * 0.2, int(15e6 / 8 * i * 0.2)) for i in range(0, 41)]
        r = pt._summarize_stream(series, 1.5, 8.0)
        self.assertAlmostEqual(r["sustained_mbps"], 15.0, delta=0.3)
        self.assertGreater(r["stability_pct"], 95)


if __name__ == "__main__":
    unittest.main()

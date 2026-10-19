"""
Property-based testing con Hypothesis per funzioni pure di NetProbe:
- Calcolo CIDR e broadcast
- Parsing OUI e riconoscimento placeholder
- Statistiche temporali (percentili, spread, IQR, MAD)
- Calcolo del jitter RFC 3550 (IPDV)
- Modello vocale MOS ITU-T G.107 (E-Model)
"""

import math
import unittest
from hypothesis import given, strategies as st, assume

from core.oui_data import lookup_vendor, is_placeholder_mac, is_locally_administered_mac
from core.validators import compute_network_and_broadcast, validate_mtu, validate_packet_loss
from core.performance import calculate_rfc3550_jitter, calculate_robust_stats
from core.estimators import NetworkEstimator



class TestHypothesisPureFunctions(unittest.TestCase):

    # 1. CIDR e Broadcast
    @given(
        o1=st.integers(min_value=1, max_value=223),
        o2=st.integers(min_value=0, max_value=255),
        o3=st.integers(min_value=0, max_value=255),
        o4=st.integers(min_value=1, max_value=254),
        prefix=st.integers(min_value=8, max_value=30)
    )
    def test_property_cidr_and_broadcast(self, o1, o2, o3, o4, prefix):
        # Escludi range 127 (loopback)
        assume(o1 != 127)
        ip = f"{o1}.{o2}.{o3}.{o4}"
        netmask = f"/{prefix}"
        net, bcast, p = compute_network_and_broadcast(ip, netmask)
        self.assertIsNotNone(net)
        self.assertIsNotNone(bcast)
        self.assertEqual(p, prefix)
        # Broadcast e network devono terminare con ottetti validi
        b_parts = [int(x) for x in bcast.split(".")]
        n_parts = [int(x) for x in net.split(".")]
        self.assertEqual(len(b_parts), 4)
        self.assertEqual(len(n_parts), 4)
        for b, n in zip(b_parts, n_parts):
            self.assertGreaterEqual(b, n)

    # 2. OUI Parsing e Placeholder detection
    @given(
        mac_bytes=st.lists(st.integers(min_value=0, max_value=255), min_size=6, max_size=6)
    )
    def test_property_oui_placeholder_and_vendor(self, mac_bytes):
        mac = ":".join(f"{b:02x}" for b in mac_bytes)
        vendor = lookup_vendor(mac)
        self.assertIsInstance(vendor, str)
        self.assertTrue(len(vendor) > 0)

        # Regola placeholder all-zero
        if all(b == 0 for b in mac_bytes):
            self.assertTrue(is_placeholder_mac(mac))
            self.assertFalse(is_locally_administered_mac(mac))

        # Regola macOS sysctl mask 02:00:00:00:00:00
        if mac_bytes[0] == 2 and all(b == 0 for b in mac_bytes[1:]):
            self.assertTrue(is_placeholder_mac(mac))
            self.assertFalse(is_locally_administered_mac(mac))
            self.assertEqual(vendor, "Indirizzo non disponibile")

        # Regola broadcast
        if all(b == 0xff for b in mac_bytes):
            self.assertTrue(is_placeholder_mac(mac))
            self.assertEqual(vendor, "Broadcast Layer 2")

        # Se non è placeholder ed ha il bit locale settato
        if not is_placeholder_mac(mac) and (mac_bytes[0] & 0x02):
            self.assertTrue(is_locally_administered_mac(mac))
            # Se non fa parte di una OUI specifica hardcoded
            if f"{mac_bytes[0]:02x}:{mac_bytes[1]:02x}:{mac_bytes[2]:02x}" not in ("02:42:ac", "c2:2a:1c"):
                self.assertIn("Locally Administered", vendor)

    # 3. Percentili, Spread, IQR e MAD
    @given(
        samples=st.lists(
            st.floats(min_value=0.1, max_value=5000.0, allow_nan=False, allow_infinity=False),
            min_size=1,
            max_size=100
        )
    )
    def test_property_robust_stats(self, samples):
        stats = calculate_robust_stats(samples)
        min_v = min(samples)
        max_v = max(samples)

        self.assertAlmostEqual(stats["min_ms"], min_v, delta=0.01)
        self.assertAlmostEqual(stats["max_ms"], max_v, delta=0.01)

        self.assertGreaterEqual(stats["median_ms"], stats["min_ms"] - 1e-6)
        self.assertLessEqual(stats["median_ms"], stats["max_ms"] + 1e-6)

        # Spread = median - min >= 0
        self.assertGreaterEqual(stats["spread_ms"], 0.0)

        # IQR >= 0
        if stats["iqr_ms"] is not None:
            self.assertGreaterEqual(stats["iqr_ms"], 0.0)

        # MAD >= 0
        if stats["mad_ms"] is not None:
            self.assertGreaterEqual(stats["mad_ms"], 0.0)

        # Spike fraction in [0.0, 1.0]
        self.assertGreaterEqual(stats["spike_fraction"], 0.0)
        self.assertLessEqual(stats["spike_fraction"], 1.0)

    # 4. Jitter RFC 3550 (IPDV)
    @given(
        rtts=st.lists(
            st.floats(min_value=0.1, max_value=2000.0, allow_nan=False, allow_infinity=False),
            min_size=0,
            max_size=50
        )
    )
    def test_property_rfc3550_jitter(self, rtts):
        jitter = calculate_rfc3550_jitter(rtts)
        if len(rtts) < 2:
            self.assertIsNone(jitter)
        else:
            self.assertIsNotNone(jitter)
            self.assertGreaterEqual(jitter, 0.0)

    # 5. Modello Vocale MOS (ITU-T G.107)
    @given(
        latency=st.floats(min_value=1.0, max_value=1000.0, allow_nan=False, allow_infinity=False),
        jitter=st.floats(min_value=0.0, max_value=300.0, allow_nan=False, allow_infinity=False),
        loss=st.floats(min_value=0.0, max_value=100.0, allow_nan=False, allow_infinity=False)
    )
    def test_property_itu_mos(self, latency, jitter, loss):
        estimator = NetworkEstimator()
        perf = {
            "primary_latency": {
                "median_ms": latency,
                "jitter_ms": jitter,
                "packet_loss_pct": loss
            }
        }
        res = estimator.calculate_itu_mos(perf)
        self.assertIsNotNone(res)
        mos = res.get("mos_score")
        r_factor = res.get("r_factor")

        # Il punteggio MOS ITU-T è sempre compreso tra 1.0 e 4.5
        self.assertGreaterEqual(mos, 1.0)
        self.assertLessEqual(mos, 4.5)

        # L'R-Factor è compreso tra 0 e 100
        self.assertGreaterEqual(r_factor, 0.0)
        self.assertLessEqual(r_factor, 100.0)

        # Monotonia: se la latenza e il jitter sono minimi e perdita zero, MOS deve essere eccellente (>4.2)
        if latency <= 15.0 and jitter <= 1.0 and loss == 0.0:
            self.assertGreaterEqual(mos, 4.3)


    # 6. Validatori di limiti MTU e Packet Loss
    @given(mtu=st.integers(min_value=-1000, max_value=20000))
    def test_property_validate_mtu(self, mtu):
        ok, reason = validate_mtu(mtu)
        if 576 <= mtu <= 9216:
            self.assertTrue(ok)
            self.assertIsNone(reason)
        else:
            self.assertFalse(ok)
            self.assertIsNotNone(reason)

    @given(loss=st.floats(min_value=-50.0, max_value=150.0, allow_nan=False, allow_infinity=False))
    def test_property_validate_loss(self, loss):
        ok, reason = validate_packet_loss(loss)
        if 0.0 <= loss <= 100.0:
            self.assertTrue(ok)
            self.assertIsNone(reason)
        else:
            self.assertFalse(ok)
            self.assertIsNotNone(reason)


if __name__ == "__main__":
    unittest.main()

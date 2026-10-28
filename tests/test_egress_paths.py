"""Offline regressions for per-path city ownership and CoPP latency bounds."""
import copy
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from core.ixp_analyzer import IXPAnalyzer, merge_multi_target_paths, parse_rdns_metro_and_role
from core.estimators import NetworkEstimator
from core.path_latency import bound_path_rtts


def hop(n, ip, rtt, rdns=None, asn=None):
    return dict(hop=n, ip=ip, rtts=[rtt] if rtt is not None else [],
                rtt_ms=rtt, rdns=rdns, asn=asn)


class EgressPathTests(unittest.TestCase):
    def setUp(self):
        self.cache = tempfile.TemporaryDirectory()
        self.addCleanup(self.cache.cleanup)
        self.analyzer = IXPAnalyzer(self.cache.name)
        self.wan = {'asn': 137, 'coordinates': {'latitude': 43.7228, 'longitude': 10.4017}}
        self.bng = {'ip': '193.206.136.17', 'min_ms': 1.89}
        self.rome = [hop(1, '172.16.4.1', 18.39), hop(2, '192.168.7.13', 11.86),
                     hop(3, '193.206.136.17', 10.83, 'aggr-scuole-li-rl1-pi01.pi01.garr.net', 137),
                     hop(6, '185.191.181.71', 24.26, 'rs1-pi01-rs1-rm02.rm02.garr.net', 137),
                     hop(7, '1.1.1.1', 6.44, asn=13335)]
        self.milan = copy.deepcopy(self.rome)
        self.milan[-2] = hop(6, '185.191.180.157', 25.87, 'rs1-mi02-re1-mi02.mi02.garr.net', 137)
        self.milan[-1] = hop(7, '8.8.8.8', 6.5, asn=15169)
        self.presence = {'facilities': [{'name': 'TOP-IX', 'city': 'Turin'},
                                       {'name': 'MIX presence', 'city': 'Milan'},
                                       {'name': 'NaMeX presence', 'city': 'Rome'}]}

    def replay(self, multi=True, **kwargs):
        return self.analyzer.reclassify_offline(self.wan, copy.deepcopy(self.rome),
            hop2_metrics=self.bng, anycast_colo='MXP',
            multi_target_analysis={'raw_paths': {'google': self.milan}} if multi else {},
            multi_cdn_inspection={'verified_metro_code': 'MXP', 'consensus': True},
            peeringdb_info=self.presence, **kwargs)

    def test_split_exit_binds_milan_metadata_to_milan_router(self):
        result = self.replay()
        metro = result['metro_egress']
        self.assertEqual(metro['routing_topology'], 'MULTI_EXIT_SPLIT')
        self.assertEqual((metro['exit_router_ip'], metro['metro_city']), ('185.191.180.157', 'Milano'))
        self.assertEqual(result['matched_hop_ip'], metro['exit_router_ip'])
        self.assertIsNone(result['datacenter_facility'])
        self.assertEqual(metro['interconnect_type'], 'PNI_OR_COLO_FACILITY')
        self.assertEqual(metro['ixp_match_method'], 'PEERINGDB_CITY_INTERSECTION')
        self.assertEqual({p['city'] for p in metro['exit_paths']}, {'Roma', 'Milano'})
        rome, milan = metro['exit_paths']
        self.assertEqual(rome['border_ip'], '185.191.181.71')
        self.assertEqual(rome['city'], 'Roma')
        self.assertEqual(rome['effective_rtt_ms'], 6.44)
        self.assertEqual(milan['effective_rtt_ms'], 6.5)
        self.assertTrue(all(p['city'] == 'Milan' for p in metro['colocated_peering_presence']))
        self.assertEqual(self.rome[3]['rtt_ms'], 24.26)

    def test_http_cannot_relocate_rome_without_a_milan_border(self):
        result = self.replay(multi=False)
        self.assertEqual(result['ixp_city'], 'Roma')
        self.assertEqual(result['metro_egress']['metro_code'], 'FCO')
        self.assertEqual(result['matched_hop_ip'], '185.191.181.71')
        self.assertEqual(result['metro_egress']['routing_topology'], 'MULTI_EXIT_SPLIT')

    def test_optical_clamps_copp_and_prioritizes_verified_bng(self):
        result = self.replay(multi=False)
        perf = {'primary_latency': {'min_ms': 6.4}, 'gateway_latency': {'min_ms': .54}}
        opt = NetworkEstimator().estimate_optical_routing(self.wan, perf, result, 'FTTH')
        self.assertTrue(opt['copp_clamped'])
        self.assertEqual(opt['measured_rtt_ms'], 6.4)
        self.assertEqual(opt['raw_hub_rtt_ms'], 24.26)
        self.assertEqual(opt['local_access_hop_ms'], 1.89)
        self.assertEqual(opt['optical_backhaul_rtt_ms'], 4.51)
        self.assertGreater(opt['routing_efficiency_pct'], 50)
        self.assertLess(opt['switching_and_queuing_delay_ms'], 2)

    def test_secondary_exit_never_borrows_primary_ping(self):
        result = self.replay()
        perf = {'primary_latency': {'min_ms': 1.0},
                'latency_targets': {'google': {'host': '8.8.8.8', 'min_ms': 6.2}}}
        opt = NetworkEstimator().estimate_optical_routing(self.wan, perf, result, 'FTTH')
        self.assertEqual(opt['latency_target'], '8.8.8.8')
        self.assertEqual(opt['measured_rtt_ms'], 6.2)

    def test_garr_pop_taxonomy_and_authoritative_subdomain(self):
        for token, city in [('pi02','Pisa'), ('rm01','Roma'), ('mi01','Milano'), ('to01','Torino'),
            ('bo02','Bologna'), ('fi01','Firenze'), ('na01','Napoli'), ('ba01','Bari'),
            ('ct01','Catania'), ('pa01','Palermo'), ('ca01','Cagliari'), ('pd01','Padova'),
            ('ve01','Venezia'), ('ge01','Genova'), ('ts01','Trieste')]:
            with self.subTest(token=token):
                parsed = parse_rdns_metro_and_role(f'rs1-mi02-rs1-{token}.{token}.garr.net')
                self.assertEqual(parsed['city'], city)
                self.assertEqual(parsed['asn'], 137)
        parsed = parse_rdns_metro_and_role(self.rome[2]['rdns'])
        self.assertEqual((parsed['access_province'], parsed['pop_token']), ('LI', 'pi01'))
        self.assertIsNone(parse_rdns_metro_and_role('r.garr.net.evil.org')['asn'])

    def test_exact_public_lans_and_domain_signatures(self):
        for ip in ['217.29.66.8', '185.1.227.8', '193.201.29.8', '185.1.193.8',
                   '194.116.99.8', '185.1.114.8', '195.69.148.8', '185.1.201.8',
                   '193.42.140.8', '80.81.199.8', '80.249.215.8', '195.66.227.8',
                   '2001:7f8:15::1']:
            with self.subTest(ip=ip):
                ixp, evidence = self.analyzer._find_ixp_in_hops([hop(2, ip, 3)])
                self.assertIsNotNone(ixp)
                self.assertEqual(evidence['type'], 'peering_subnet_match')
        for domain in ['mix-it.net', 'namex.it', 'top-ix.org', 'minap.it', 'vsix.it',
                       'decix.net', 'ams-ix.net', 'linx.net']:
            with self.subTest(domain=domain):
                self.assertIsNotNone(self.analyzer._find_ixp_in_hops([hop(2, '9.8.7.6', 3, f'r.{domain}')])[0])
                self.assertIsNone(self.analyzer._find_ixp_in_hops([hop(2, '9.8.7.6', 3, f'r.{domain}.evil.org')])[0])
        self.assertIsNone(self.analyzer._find_ixp_in_hops([hop(2, '80.81.200.1', 3)])[0])

    def test_dynamic_prefix_is_required_not_participant_ip_guess(self):
        path = [hop(2, '9.8.7.6', 3)]
        info = {'netixlan': [{'name': 'Example IX', 'city': 'Rome', 'ipaddr4': '9.8.7.1'}]}
        self.assertIsNone(self.analyzer._dynamic_ixp(path, info)[0])
        info['netixlan'][0]['prefixes'] = ['9.8.7.0/24']
        result = self.analyzer.reclassify_offline(self.wan, path, peeringdb_info=info)
        self.assertEqual(result['metro_egress']['ixp_match_method'], 'CIDR_EXACT')
        self.assertEqual(result['metro_egress']['interconnect_type'], 'PUBLIC_IXP_LAN')
        self.assertEqual(result['matched_subnet'], '9.8.7.0/24')

    def test_monotonic_bounds_preserve_missing_and_zero_rtts(self):
        path = [hop(1, '172.16.4.1', 18), hop(2, '*', None), hop(3, '1.1.1.1', 6.44)]
        original = copy.deepcopy(path)
        bounded = bound_path_rtts(path, {'172.16.4.1': {'min_ms': 0}})
        self.assertEqual([h['effective_rtt_ms'] for h in bounded], [0, 6.44, 6.44])
        self.assertEqual(path, original)
        self.assertEqual(bound_path_rtts(path[:-1], target='1.1.1.1', target_rtt=1)[0]['effective_rtt_ms'], 18)

    def test_ecmp_target_ping_bounds_final_hop_and_exit(self):
        path = copy.deepcopy(self.milan)
        path[-1].update(ip='142.251.235.179', asn=None, rtts=[14.68], rtt_ms=14.68,
                        ips=['142.251.235.179', '142.251.235.173', '8.8.8.8'])
        original = copy.deepcopy(path)
        bounded = bound_path_rtts(path, target='8.8.8.8', target_rtt=6.2)
        self.assertEqual(bounded[-1]['effective_rtt_ms'], 6.2)
        self.assertTrue(bounded[-1]['copp_detected'])
        self.assertEqual(bounded[-2]['effective_rtt_ms'], 6.2)
        result = self.analyzer._resolve_exit_path('8.8.8.8', path, self.wan,
            self.presence, None, self.bng, target_rtt=6.2)
        self.assertEqual(result['border_ip'], '185.191.180.157')
        self.assertEqual(result['effective_rtt_ms'], 6.2)
        self.assertEqual(path, original)

    def test_exit_uses_target_ping_for_primary_destination(self):
        path = copy.deepcopy(self.rome)
        path[-1].update(rtts=[14.68], rtt_ms=14.68)
        result = self.analyzer._resolve_exit_path('1.1.1.1', path, self.wan,
            self.presence, None, self.bng, target_rtt=6.4)
        self.assertEqual(result['effective_rtt_ms'], 6.4)
        self.assertTrue(result['copp_detected'])

    def test_merge_uses_terminal_rtt_and_authoritative_border_pop(self):
        for hostname, metro in [('rs1-pi01-rs1-rm02.rm02.garr.net', 'FCO'),
                                ('rs1-to01-rs1-mi02.mi02.garr.net', 'MXP')]:
            with self.subTest(hostname=hostname):
                path = copy.deepcopy(self.milan)
                path[0].update(rtts=[1.43], rtt_ms=1.43)
                path[-2]['rdns'] = hostname
                # Destination-AS hostnames cannot overwrite the ISP border city.
                path[-1]['rdns'] = 'router.fra.example.net'
                path.append(hop(8, '*', None))
                original = copy.deepcopy(path)
                summary = merge_multi_target_paths({'google': path})['targets']['google']
                self.assertEqual(summary['min_rtt_ms'], 6.5)
                self.assertEqual(summary['exit_pop'], metro)
                self.assertEqual(path, original)

    def test_merge_partial_path_uses_clamped_public_terminal_and_cached_pop(self):
        path = copy.deepcopy(self.milan[:-1])
        path[-1].update(effective_rtt_ms=6.2, rdns_parsed={'metro_code': 'FCO'})
        path.extend([hop(8, '192.168.1.1', .1), hop(9, '*', None)])
        summary = merge_multi_target_paths({'google': path})['targets']['google']
        self.assertEqual(summary['min_rtt_ms'], 6.2)
        self.assertEqual(summary['exit_pop'], 'FCO')
        summary = merge_multi_target_paths({'google': [hop(1, '192.168.1.1', 1.43)]})['targets']['google']
        self.assertIsNone(summary['min_rtt_ms'])

    def test_live_pipeline_uses_the_same_per_path_reconciliation(self):
        multi = {'raw_paths': {'cloudflare': self.rome, 'google': self.milan}}
        cdn = {'verified_metro_code': 'MXP', 'consensus': True}
        with patch.dict(os.environ, {}, clear=True), \
             patch('core.ixp_analyzer.probe_multi_cdn_pops', return_value=cdn), \
             patch.object(self.analyzer, 'probe_parallel_targets', return_value=multi), \
             patch.object(self.analyzer, '_probe_hop2_bng', return_value=(self.bng['ip'], self.bng)), \
             patch.object(self.analyzer, 'probe_path_mtu', return_value=1500), \
             patch.object(self.analyzer, 'get_peeringdb_for_asn', return_value=self.presence), \
             patch('core.ixp_analyzer.lookup_ip_rdns', return_value=None):
            result = self.analyzer.analyze_ixp_and_bng(self.wan)
        self.assertEqual(result['metro_egress']['routing_topology'], 'MULTI_EXIT_SPLIT')
        self.assertEqual(result['matched_hop_ip'], '185.191.180.157')
        self.assertEqual(result['metro_egress']['exit_paths'][0]['city'], 'Roma')

    def test_peeringdb_enrichment_and_cache(self):
        responses = {
            'netixlan': [{'ix_id': 10, 'name': 'Example IX', 'ipaddr4': '9.8.7.1'}],
            'netfac': [{'fac': {'name': 'Rome DC', 'city': 'Rome'}}],
            'ix': [{'id': 10, 'city': 'Rome'}],
            'ixpfx': [{'ix_id': 10, 'prefix': '9.8.7.0/24'}]}
        def response(req, **kw):
            from io import BytesIO
            endpoint = req.full_url.split('/api/')[1].split('?')[0]
            return BytesIO(json.dumps({'data': responses[endpoint]}).encode())
        with patch('core.ixp_analyzer.urllib.request.urlopen', side_effect=response) as request:
            result = self.analyzer.get_peeringdb_for_asn(137)
            self.assertEqual(result['netixlan'][0]['prefixes'], ['9.8.7.0/24'])
            self.assertEqual(result['netfac'][0]['city'], 'Rome')
            self.assertEqual(result['facilities'][0]['city'], 'Rome')
            self.assertEqual(self.analyzer.get_peeringdb_for_asn(137), result)
            self.assertEqual(request.call_count, 4)


if __name__ == '__main__':
    unittest.main()

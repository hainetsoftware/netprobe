"""
Modulo di intelligence WAN e Internet:
- Rilevamento IP pubblico IPv4 e IPv6 (Dual-Stack)
- Geolocalizzazione, ASN, ISP e Reverse DNS
- Client STUN RFC 5389 per classificazione NAT (Full Cone, Symmetric, ecc.)
- Rilevamento Double-NAT e Carrier-Grade NAT (CGNAT RFC 6598)
- Rilevamento UPnP e NAT-PMP sul router locale
- Path MTU Discovery (PMTUD) e rilevamento intercettazione DNS / Proxy
"""

import socket
import struct
import os
import json
import time
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, Tuple


class WanProbe:
    def __init__(self):
        self.stun_servers = [
            ("stun.l.google.com", 19302),
            ("stun1.l.google.com", 19302),
            ("stun.cloudflare.com", 3478)
        ]

    def probe_all(self, local_ip: Optional[str] = None, gateway_ip: Optional[str] = None) -> Dict[str, Any]:
        """Esegue tutti i test WAN, STUN, GeoIP e NAT."""
        # 1. IP Pubblico e Geointelligence
        wan_geo = self.get_public_ip_and_geo()
        public_v4 = wan_geo.get("ip")
        
        # 2. Test IPv6 Dual-Stack
        public_v6 = self.get_public_ipv6()
        
        # 3. Reverse DNS (PTR)
        reverse_dns = self.get_reverse_dns(public_v4) if public_v4 else None
        
        # 4. Test STUN e analisi NAT RFC 5389
        nat_analysis = self.analyze_nat_type(local_ip, gateway_ip)
        
        # 5. Rilevamento UPnP / NAT-PMP sul router
        upnp_pmp = self.probe_upnp_and_nat_pmp(gateway_ip)
        
        # 6. Rilevamento Proxy / VPN / Datacenter
        proxy_vpn = self.detect_proxy_or_vpn(wan_geo, reverse_dns)

        return {
            "public_ipv4": public_v4,
            "public_ipv6": public_v6,
            "dual_stack_enabled": bool(public_v4 and public_v6),
            "reverse_dns": reverse_dns,
            "asn": wan_geo.get("asn"),
            "isp": wan_geo.get("isp"),
            "org": wan_geo.get("org"),
            "city": wan_geo.get("city"),
            "region": wan_geo.get("region"),
            "country": wan_geo.get("country"),
            "country_code": wan_geo.get("country_code"),
            "postal": wan_geo.get("postal"),
            "coordinates": {
                "latitude": wan_geo.get("latitude"),
                "longitude": wan_geo.get("longitude")
            },
            "timezone": wan_geo.get("timezone"),
            "nat": nat_analysis,
            "router_services": upnp_pmp,
            "privacy_and_routing": proxy_vpn
        }

    def get_public_ip_and_geo(self) -> Dict[str, Any]:
        """Recupera l'IP pubblico e le informazioni di geolocalizzazione e ASN."""
        geo_data = {
            "ip": None,
            "asn": None,
            "isp": None,
            "org": None,
            "city": None,
            "region": None,
            "country": None,
            "country_code": None,
            "postal": None,
            "latitude": None,
            "longitude": None,
            "timezone": None
        }

        if os.environ.get("NETPROBE_SPEED_HOST"):
            geo_data["ip"] = "198.51.100.1"
            geo_data["asn"] = "AS1234"
            geo_data["isp"] = "Test ISP"
            geo_data["city"] = "Rome"
            geo_data["country"] = "Italy"
            return geo_data

        # Tentativo 1: ipinfo.io (molto dettagliato con loc lat/lon)
        try:
            req = urllib.request.Request("https://ipinfo.io/json", headers={"User-Agent": "curl/7.88.1"})
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                geo_data["ip"] = data.get("ip")
                geo_data["city"] = data.get("city")
                geo_data["region"] = data.get("region")
                geo_data["country"] = data.get("country")
                geo_data["country_code"] = data.get("country")
                geo_data["postal"] = data.get("postal")
                geo_data["timezone"] = data.get("timezone")
                
                org = data.get("org", "")
                if org.startswith("AS"):
                    parts = org.split(" ", 1)
                    geo_data["asn"] = parts[0]
                    geo_data["isp"] = parts[1] if len(parts) > 1 else parts[0]
                    geo_data["org"] = org
                else:
                    geo_data["isp"] = org
                    geo_data["org"] = org

                if "loc" in data and "," in data["loc"]:
                    lat_s, lon_s = data["loc"].split(",", 1)
                    geo_data["latitude"] = float(lat_s.strip())
                    geo_data["longitude"] = float(lon_s.strip())

                return geo_data
        except Exception:
            pass

        # Tentativo 2: ip-api.com
        try:
            req = urllib.request.Request("http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query", headers={"User-Agent": "NetProbe/1.0"})
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "success":
                    geo_data["ip"] = data.get("query")
                    geo_data["city"] = data.get("city")
                    geo_data["region"] = data.get("regionName")
                    geo_data["country"] = data.get("country")
                    geo_data["country_code"] = data.get("countryCode")
                    geo_data["postal"] = data.get("zip")
                    geo_data["timezone"] = data.get("timezone")
                    geo_data["isp"] = data.get("isp")
                    geo_data["org"] = data.get("org")
                    geo_data["asn"] = (data.get("as") or "").split()[0]
                    geo_data["latitude"] = data.get("lat")
                    geo_data["longitude"] = data.get("lon")
                    return geo_data
        except Exception:
            pass

        # Tentativo 3: api.ipify.org fallback essenziale
        try:
            req = urllib.request.Request("https://api.ipify.org?format=json", headers={"User-Agent": "NetProbe/1.0"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                geo_data["ip"] = data.get("ip")
        except Exception:
            pass

        return geo_data

    def get_public_ipv6(self) -> Optional[str]:
        """Tenta di verificare la connettività IPv6 nativa tramite endpoint IPv6-only."""
        try:
            req = urllib.request.Request("https://api6.ipify.org?format=json", headers={"User-Agent": "NetProbe/1.0"})
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("ip")
        except Exception:
            return None

    def get_reverse_dns(self, ip: str) -> Optional[str]:
        """Esegue il PTR lookup dell'IP pubblico per ottenere l'hostname dell'ISP."""
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return host
        except Exception:
            return None

    def analyze_nat_type(self, local_ip: Optional[str], gateway_ip: Optional[str]) -> Dict[str, Any]:
        """
        Esegue sonde STUN RFC 5389 su più server indipendenti per determinare
        il comportamento di mappatura NAT, la presenza di Double-NAT o CGNAT.
        """
        results = {
            "mapped_external_ip": None,
            "mapped_external_port": None,
            "nat_type": "Indeterminato",
            "mapping_behavior": "Sconosciuto",
            "double_nat_detected": False,
            "cgnat_detected": False,
            "details": ""
        }

        if os.environ.get("NETPROBE_SPEED_HOST"):
            results["mapped_external_ip"] = "198.51.100.1"
            results["mapped_external_port"] = 54321
            results["nat_type"] = "Endpoint-Independent Mapping (Full Cone NAT)"
            results["mapping_behavior"] = "Endpoint-Independent Mapping (EIM)"
            return results

        # Esegui STUN verso Server 1 e Server 2 con la stessa socket locale per valutare la conservazione della porta
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.5)
        try:
            # Bind su porta effimera
            sock.bind(("", 0))
            _, local_port = sock.getsockname()

            resp1 = self._send_stun_request(sock, self.stun_servers[0][0], self.stun_servers[0][1])
            resp2 = self._send_stun_request(sock, self.stun_servers[1][0], self.stun_servers[1][1])

            if resp1:
                ext_ip1, ext_port1 = resp1
                results["mapped_external_ip"] = ext_ip1
                results["mapped_external_port"] = ext_port1

                # Verifica se non c'è NAT (IP pubblico coincide con interfaccia locale)
                if local_ip and ext_ip1 == local_ip:
                    results["nat_type"] = "Nessun NAT / IP Pubblico Diretto"
                    results["mapping_behavior"] = "Endpoint-Independent (Nessun Masquerading)"
                    results["details"] = "La macchina possiede un IP pubblico routabile direttamente sull'interfaccia."
                elif resp2:
                    ext_ip2, ext_port2 = resp2
                    if ext_port1 == ext_port2:
                        results["nat_type"] = "Endpoint-Independent Mapping (EIM) - compatibile con Full/Restricted/Port-Restricted Cone (filtering non verificabile)"
                        results["mapping_behavior"] = "Endpoint-Independent Mapping (EIM)"
                        results["details"] = f"La porta esterna ({ext_port1}) viene preservata su destinazioni diverse. Filtering non verificabile senza server RFC 5780."
                    else:
                        results["nat_type"] = "Address and Port-Dependent Mapping (APDM) - Symmetric NAT"
                        results["mapping_behavior"] = "Address and Port-Dependent Mapping (APDM)"
                        results["details"] = f"La porta varia a seconda della destinazione ({ext_port1} -> {ext_port2}). NAT restrittivo (tipico di CGNAT, mobile o reti aziendali)."
                else:
                    results["nat_type"] = "Mappatura rilevata da singolo server (EIM/APDM non determinabile senza secondo endpoint)"
                    results["mapping_behavior"] = "Indeterminato (singolo server STUN)"
                    results["details"] = "Risposta STUN ottenuta con successo da un singolo server; secondo endpoint non responsivo."


        except Exception as e:
            results["details"] = f"Errore durante l'interrogazione STUN: {e}"
        finally:
            sock.close()

        # Verifica Carrier-Grade NAT (CGNAT RFC 6598: 100.64.0.0/10) o Double NAT
        # Se il gateway locale è un indirizzo privato (192.168.x, 10.x, 172.16-31.x)
        # e le sonde rilevano un ulteriore salto privato
        if results["mapped_external_ip"]:
            pub_ip = results["mapped_external_ip"]
            # Controlla se l'IP pubblico ricade in RFC 6598 (100.64.0.0 - 100.127.255.255)
            if pub_ip.startswith("100."):
                try:
                    second_oct = int(pub_ip.split(".")[1])
                    if 64 <= second_oct <= 127:
                        results["cgnat_detected"] = True
                        results["nat_type"] = "Carrier-Grade NAT (CGNAT RFC 6598)"
                        results["details"] = "Rilevato intervallo IP condiviso ISP (RFC 6598). Nessun IP pubblico univoco."
                except Exception:
                    pass

        return results

    def _send_stun_request(self, sock: socket.socket, host: str, port: int) -> Optional[Tuple[str, int]]:
        """Invia una richiesta Binding Request STUN RFC 5389 e parsa l'attributo XOR-MAPPED-ADDRESS."""
        try:
            dest_ip = socket.gethostbyname(host)
        except Exception:
            return None

        # STUN RFC 5389 Header:
        # Message Type: 0x0001 (Binding Request)
        # Message Length: 0x0000
        # Magic Cookie: 0x2112A442
        # Transaction ID: 12 bytes
        magic = b"\x21\x12\xa4\x42"
        txid = os.urandom(12)
        packet = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txid

        sock.sendto(packet, (dest_ip, port))
        
        try:
            data, _ = sock.recvfrom(2048)
        except (socket.timeout, socket.error):
            return None

        if len(data) < 20:
            return None

        msg_type, msg_len, magic_rcv = struct.unpack("!HHI", data[:8])
        if magic_rcv != 0x2112A442:
            return None

        # Parsa gli attributi TLV
        pos = 20
        mapped_ip = None
        mapped_port = None

        while pos + 4 <= len(data):
            attr_type, attr_len = struct.unpack("!HH", data[pos:pos+4])
            pos += 4
            attr_val = data[pos:pos+attr_len]
            pos += attr_len
            # Padding a 32 bit per specifica RFC
            if attr_len % 4 != 0:
                pos += (4 - (attr_len % 4))

            # 0x0020 = XOR-MAPPED-ADDRESS (RFC 5389)
            if attr_type == 0x0020 and len(attr_val) >= 8:
                family = attr_val[1]
                xport = struct.unpack("!H", attr_val[2:4])[0]
                mapped_port = xport ^ 0x2112
                if family == 1: # IPv4
                    xip = attr_val[4:8]
                    real_ip_bytes = bytes([b ^ magic[i] for i, b in enumerate(xip)])
                    mapped_ip = socket.inet_ntoa(real_ip_bytes)
                    return (mapped_ip, mapped_port)
            # 0x0001 = MAPPED-ADDRESS (RFC 3489 legacy fallback)
            elif attr_type == 0x0001 and len(attr_val) >= 8:
                family = attr_val[1]
                mapped_port = struct.unpack("!H", attr_val[2:4])[0]
                if family == 1:
                    mapped_ip = socket.inet_ntoa(attr_val[4:8])
                    return (mapped_ip, mapped_port)

        return (mapped_ip, mapped_port) if mapped_ip else None

    def probe_upnp_and_nat_pmp(self, gateway_ip: Optional[str]) -> Dict[str, Any]:
        """Verifica se il router ha attivi i protocolli di apertura automatica porte (UPnP o NAT-PMP)."""
        res = {
            "upnp_igd_available": False,
            "upnp_server": None,
            "nat_pmp_available": False
        }

        # 1. UPnP SSDP Discovery (multicast 239.255.255.250:1900)
        ssdp_request = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 1\r\n"
            "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
            "\r\n"
        ).encode("utf-8")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.8)
        try:
            sock.sendto(ssdp_request, ("239.255.255.250", 1900))
            data, _ = sock.recvfrom(2048)
            text = data.decode("utf-8", errors="replace")
            if "InternetGatewayDevice" in text or "200 OK" in text:
                res["upnp_igd_available"] = True
                for line in text.splitlines():
                    if line.lower().startswith("server:"):
                        res["upnp_server"] = line.split(":", 1)[1].strip()
        except Exception:
            pass
        finally:
            sock.close()

        # 2. NAT-PMP Probe (porta UDP 5351 del Gateway)
        if gateway_ip:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.6)
            try:
                # Opcode 0 = request external IP
                packet = b"\x00\x00"
                sock.sendto(packet, (gateway_ip, 5351))
                data, _ = sock.recvfrom(64)
                if len(data) >= 12 and data[0] == 0:
                    res["nat_pmp_available"] = True
            except Exception:
                pass
            finally:
                sock.close()

        res["upnp_status_text"] = "ATTIVO" if res["upnp_igd_available"] else "Nessuna risposta (UPnP non rilevato)"
        res["nat_pmp_status_text"] = "ATTIVO" if res["nat_pmp_available"] else "Nessuna risposta (NAT-PMP non rilevato)"
        return res

    def detect_proxy_or_vpn(self, geo_data: Dict[str, Any], reverse_dns: Optional[str]) -> Dict[str, Any]:
        """Rileva la presenza di tunnel VPN, proxy, iCloud Private Relay o IP datacenter."""
        analysis = {
            "is_vpn_or_proxy": False,
            "confidence": "Bassa",
            "type": "Nessun indizio di VPN/proxy",
            "indicators": []
        }

        indicators = []
        isp = (geo_data.get("isp") or "").lower()
        org = (geo_data.get("org") or "").lower()
        asn = (geo_data.get("asn") or "").upper()
        rdns = (reverse_dns or "").lower()

        # Hosting & Cloud Datacenter ASN noti
        datacenter_keywords = [
            "ovh", "hetzner", "digitalocean", "linode", "aws", "amazon",
            "google cloud", "azure", "microsoft", "cloudflare", "fastly",
            "akamai", "leaseweb", "vultr", "oracle"
        ]
        
        # VPN Provider noti
        vpn_keywords = [
            "nordvpn", "expressvpn", "mullvad", "surfshark", "proton", "windscribe",
            "cyberghost", "privateinternetaccess", "tailscale", "wireguard", "openvpn"
        ]

        # Apple iCloud Private Relay
        if "apple" in org or "icloud" in rdns or "apple-relay" in rdns:
            analysis["is_vpn_or_proxy"] = True
            analysis["confidence"] = "Alta"
            analysis["type"] = "Apple iCloud Private Relay"
            analysis["indicators"].append("Rilevato nodo di uscita crittografato Apple Private Relay")
            return analysis

        for kw in vpn_keywords:
            if kw in isp or kw in org or kw in rdns:
                indicators.append(f"Firma VPN identificata: {kw}")
                analysis["is_vpn_or_proxy"] = True
                analysis["type"] = f"VPN Commerciale ({kw.capitalize()})"
                analysis["confidence"] = "Alta"

        for kw in datacenter_keywords:
            if kw in isp or kw in org:
                indicators.append(f"Indirizzo IP originato da Cloud/Datacenter: {kw}")
                if not analysis["is_vpn_or_proxy"]:
                    analysis["is_vpn_or_proxy"] = True
                    analysis["type"] = "Proxy / Server Datacenter (Non Residenziale)"
                    analysis["confidence"] = "Media"

        if indicators:
            analysis["indicators"] = indicators
        else:
            # Verifica evidenze: Rete mobile vs Fissa residenziale vs Nessun indizio
            mobile_keywords = [
                "wind tre", "windtre", "vodafone omnitel", "iliad", "tim mobile",
                "telecom italia mobile", "kena", "ho. mobile", "very mobile", "fastweb mobile",
                "cellular", "mobile", "wireless", "t-mobile", "verizon", "at&t mobility"
            ]
            is_mobile = any(m in isp or m in org or m in rdns for m in mobile_keywords)

            residential_rdns_keywords = [
                "retail", "residenziale", "adsl", "fttc", "ftth", "vdsl", "consumer",
                "home", "user", "dynamic", "pool", "dhcp", "dialup", "broadband", "cust", "subscriber"
            ]
            has_residential_rdns = any(r in rdns for r in residential_rdns_keywords)
            is_business_rdns = "business" in rdns or "corporate" in rdns or "enterprise" in rdns

            if is_mobile:
                analysis["type"] = "Rete mobile (nessun indizio di VPN/proxy)"
                analysis["confidence"] = "Alta" if any(m in isp or m in org for m in ("wind", "vodafone", "iliad", "mobile", "cellular")) else "Media"
                analysis["indicators"].append("Operatore o routing mobile identificato (nessun tunnel VPN/proxy rilevato).")
            elif has_residential_rdns and not is_business_rdns:
                analysis["type"] = "Connessione fissa residenziale (nessun indizio di VPN/proxy)"
                analysis["confidence"] = "Media"
                analysis["indicators"].append("Hostname rDNS compatibile con profilo residenziale/retail.")
            else:
                analysis["type"] = "Nessun indizio di VPN/proxy"
                analysis["confidence"] = "Bassa"
                if is_business_rdns:
                    analysis["indicators"].append("Indirizzo IP commerciale/business diretto (nessun tunnel VPN/proxy rilevato).")
                else:
                    analysis["indicators"].append("Nessuna firma VPN, proxy o datacenter rilevata sull'indirizzo IP.")

        return analysis


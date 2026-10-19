"""
Modulo di validazione DNSSEC avanzato con dnspython.
Verifica la convalida crittografica DNSSEC per ciascun resolver configurato,
confrontando una zona firmata valida e una zona deliberatamente corrotta,
con controllo di coerenza runtime su resolver pubblico validante.
"""

from typing import List, Dict, Any, Optional

try:
    import dns.resolver
    import dns.flags
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False


def validate_dnssec_resolvers(
    resolvers: List[str],
    good_zone: str = "sigok.verteiltesysteme.net",
    broken_zone: str = "sigfail.verteiltesysteme.net",
    fallback_broken_zone: str = "dnssec-failed.org",
    control_servers: Optional[List[str]] = None,
    timeout: float = 2.0
) -> Dict[str, Any]:
    """
    Verifica la convalida crittografica DNSSEC per ciascun resolver configurato.
    Ritorna un report dettagliato con esito per ciascun server (validante, non validante, inconclusivo).
    """
    if not _HAS_DNSPYTHON:
        return {
            "available": False,
            "error": "Libreria dnspython non installata",
            "resolvers": [{"ip": ip, "status": "inconclusivo", "reason": "dnspython assente"} for ip in resolvers],
            "overall_status": "INCONCLUSIVO"
        }

    control_ns = control_servers or ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    control_ok = False
    control_tested_server = None

    # Verifica preliminare di controllo: un resolver validante pubblico DEVE fallire sulla zona corrotta
    for c_ip in control_ns:
        try:
            rc = dns.resolver.Resolver()
            rc.nameservers = [c_ip]
            rc.timeout = timeout
            rc.lifetime = timeout
            rc.set_flags(dns.flags.RD | dns.flags.AD)

            # Il controllo deve risolvere la zona valida
            rc.resolve(good_zone, "A")

            # E DEVE fallire (SERVFAIL / NoNameservers) sulla zona corrotta
            try:
                rc.resolve(broken_zone, "A")
            except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
                control_ok = True
                control_tested_server = c_ip
                break
            except Exception:
                pass
        except Exception:
            continue

    if not control_ok:
        # Tenta fallback con dnssec-failed.org
        for c_ip in control_ns:
            try:
                rc = dns.resolver.Resolver()
                rc.nameservers = [c_ip]
                rc.timeout = timeout
                rc.lifetime = timeout
                try:
                    rc.resolve(fallback_broken_zone, "A")
                except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
                    control_ok = True
                    broken_zone = fallback_broken_zone
                    control_tested_server = c_ip
                    break
            except Exception:
                continue

    per_resolver = []
    validating_count = 0
    non_validating_count = 0
    inconclusive_count = 0

    for ip in resolvers:
        if not control_ok:
            per_resolver.append({
                "ip": ip,
                "status": "inconclusivo",
                "ad_flag": False,
                "broken_blocked": False,
                "good_resolved": False,
                "reason": "Controllo runtime fallito: i resolver pubblici di riferimento non hanno confermato la corruzione della zona di test."
            })
            inconclusive_count += 1
            continue

        r = dns.resolver.Resolver()
        r.nameservers = [ip]
        r.timeout = timeout
        r.lifetime = timeout
        r.set_flags(dns.flags.RD | dns.flags.AD)

        good_resolved = False
        ad_flag = False
        try:
            ans = r.resolve(good_zone, "A")
            good_resolved = True
            if ans.response and hasattr(ans.response, "flags"):
                ad_flag = bool(ans.response.flags & dns.flags.AD)
        except Exception:
            pass

        broken_blocked = False
        broken_resolved = False
        try:
            r.resolve(broken_zone, "A")
            broken_resolved = True
        except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
            broken_blocked = True
        except Exception:
            pass

        if not good_resolved and not broken_resolved and not broken_blocked:
            status = "inconclusivo"
            reason = "Nessuna risposta ricevuta dal resolver per le zone di test (timeout o filtraggio porta 53)."
            inconclusive_count += 1
        elif broken_blocked and (good_resolved or ad_flag):
            status = "validante"
            reason = f"Convalida crittografica attiva: bloccata con successo la zona non valida ({broken_zone})."
            validating_count += 1
        elif broken_resolved:
            status = "non validante"
            reason = f"Convalida crittografica assente: risolta con successo la zona volutamente corrotta ({broken_zone})."
            non_validating_count += 1
        else:
            status = "inconclusivo"
            reason = "Comportamento ambiguo durante il test delle zone crittografiche."
            inconclusive_count += 1

        per_resolver.append({
            "ip": ip,
            "status": status,
            "ad_flag": ad_flag,
            "broken_blocked": broken_blocked,
            "good_resolved": good_resolved,
            "reason": reason
        })

    if validating_count == len(resolvers) and validating_count > 0:
        overall = "VALIDANTE"
    elif non_validating_count == len(resolvers) and non_validating_count > 0:
        overall = "NON VALIDANTE"
    elif validating_count > 0 and non_validating_count > 0:
        overall = "PARZIALE"
    else:
        overall = "INCONCLUSIVO"

    return {
        "available": True,
        "control_verified": control_ok,
        "control_resolver": control_tested_server,
        "test_zone_good": good_zone,
        "test_zone_broken": broken_zone,
        "resolvers": per_resolver,
        "overall_status": overall,
        "dnssec_validation_active": (overall in ("VALIDANTE", "PARZIALE"))
    }

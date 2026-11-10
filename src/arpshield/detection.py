from __future__ import annotations

from collections import OrderedDict
from time import monotonic
from typing import Any


CAPTURE_FIELDS = (
    "frame.time",
    "frame.number",
    "frame.protocols",
    "eth.src",
    "eth.dst",
    "arp.opcode",
    "arp.src.proto_ipv4",
    "arp.src.hw_mac",
    "arp.dst.proto_ipv4",
    "arp.dst.hw_mac",
    "dns.qry.name",
    "dns.flags.response",
    "dns.a",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "dhcp.type",
    "dhcp.option.dhcp_server_id",
    "dhcp.id",
    "dns.id",
    "nbns.id",
    "nbns.flags.response",
    "nbns.name",
    "nbns.addr",
    "icmpv6.type",
    "icmpv6.nd.na.target_address",
    "icmpv6.nd.ns.target_address",
    "dns.aaaa",
    "dhcpv6.msgtype",
    "dhcpv6.xid",
    "udp.srcport",
    "udp.dstport",
)
CAPTURE_FIELD_COUNT = len(CAPTURE_FIELDS)
FIELD_DHCP_MESSAGE_TYPE = 17
FIELD_DHCP_SERVER_ID = 18
FIELD_BOOTP_TRANSACTION_ID = 19
FIELD_NBNS_TRANSACTION_ID = 21
FIELD_NBNS_RESPONSE = 22
FIELD_NBNS_NAME = 23
FIELD_NBNS_ADDRESS = 24
FIELD_ICMPV6_TYPE = 25
FIELD_NDP_NA_TARGET = 26
FIELD_NDP_NS_TARGET = 27
FIELD_DNS_AAAA = 28
FIELD_DHCPV6_MESSAGE_TYPE = 29
FIELD_DHCPV6_TRANSACTION_ID = 30

ALERT_COOLDOWN_SECONDS = 30
STATE_TTL_SECONDS = 300
MAX_TRACKED_TRANSACTIONS = 2048


def _normalize_mac(value: str) -> str:
    return value.replace("-", ":").strip().upper()


def _is_true(value: str) -> bool:
    return value.strip().casefold() in {"1", "true", "yes"}


def _normalize_dns_answers(*values: str) -> str:
    answers = {
        answer.strip().casefold()
        for value in values
        for answer in value.split(",")
        if answer.strip()
    }
    return ",".join(sorted(answers))


class SpoofingDetector:
    def __init__(self) -> None:
        self._recent_alerts: OrderedDict[tuple[str, str, str], float] = OrderedDict()
        self._dns_answers: OrderedDict[tuple[str, str, str], tuple[str, str, float]] = OrderedDict()
        self._dhcp_offers: OrderedDict[str, tuple[str, str, float]] = OrderedDict()
        self._local_name_answers: OrderedDict[
            tuple[str, str, str], tuple[str, str, float]
        ] = OrderedDict()
        self._ipv6_neighbors: OrderedDict[str, tuple[str, float]] = OrderedDict()

    @staticmethod
    def _remember(
        state: OrderedDict[Any, Any],
        key: Any,
        value: Any,
        now: float,
    ) -> None:
        expired = [
            item_key
            for item_key, item in state.items()
            if now - (item if isinstance(item, (int, float)) else item[-1]) > STATE_TTL_SECONDS
        ]
        for item_key in expired:
            del state[item_key]
        state[key] = value
        state.move_to_end(key)
        while len(state) > MAX_TRACKED_TRANSACTIONS:
            state.popitem(last=False)

    def _make_alert(
        self,
        alert_type: str,
        severity: str,
        attacker_mac: str,
        spoofed_ip: str,
        evidence: str,
        evidence_details: dict[str, str],
        now: float,
    ) -> dict[str, Any] | None:
        fingerprint = (alert_type, attacker_mac.casefold(), spoofed_ip.casefold())
        last_seen = self._recent_alerts.get(fingerprint)
        if last_seen is not None and now - last_seen < ALERT_COOLDOWN_SECONDS:
            return None
        self._remember(self._recent_alerts, fingerprint, now, now)
        return {
            "alert_type": alert_type,
            "severity": severity,
            "attacker_mac": attacker_mac or "UNKNOWN",
            "spoofed_ip": spoofed_ip or "UNKNOWN",
            "packet_count": 1,
            "evidence_summary": evidence,
            "evidence_details": evidence_details,
        }

    def analyze(
        self,
        capture_record: str,
        baseline: list[dict[str, Any]],
        capture_source: str = "TShark",
    ) -> list[dict[str, Any]]:
        fields = capture_record.rstrip("\r\n").split("\t")
        if not any(fields):
            return []
        fields.extend([""] * max(0, CAPTURE_FIELD_COUNT - len(fields)))
        now = monotonic()

        protocols = {item.casefold() for item in fields[2].split(":")}
        eth_src = _normalize_mac(fields[3])
        arp_opcode = fields[5]
        arp_src_ip = fields[6]
        arp_src_mac = _normalize_mac(fields[7])
        dns_query = fields[10].rstrip(".").casefold()
        dns_response = _is_true(fields[11])
        dns_answer = _normalize_dns_answers(fields[12], fields[FIELD_DNS_AAAA])
        ip_src = fields[13] or fields[15] or arp_src_ip
        dns_id = fields[20] if len(fields) > 20 else ""
        udp_ports = {fields[31], fields[32]}
        is_mdns = "mdns" in protocols or "5353" in udp_ports
        is_llmnr = "llmnr" in protocols or "5355" in udp_ports
        local_protocol = "llmnr" if is_llmnr else "mdns" if is_mdns else None
        packet_details = {
            "capture_source": capture_source,
            **dict(zip(CAPTURE_FIELDS, fields)),
        }

        baseline_by_ip = {
            str(entry["ip_address"]): _normalize_mac(str(entry["mac_address"]))
            for entry in baseline
            if entry.get("ip_address") and entry.get("mac_address")
            and _normalize_mac(str(entry["mac_address"])) != "00:00:00:00:00:00"
        }
        baseline_type_by_ip = {
            str(entry["ip_address"]): str(entry.get("device_type", "KNOWN_HOST"))
            for entry in baseline
            if entry.get("ip_address")
        }
        baseline_ips_by_mac: dict[str, set[str]] = {}
        for ip, mac in baseline_by_ip.items():
            baseline_ips_by_mac.setdefault(mac, set()).add(ip)
        gateway_macs = {
            _normalize_mac(str(entry["mac_address"]))
            for entry in baseline
            if entry.get("device_type") == "GATEWAY" and entry.get("mac_address")
        }
        trusted_macs = set(baseline_by_ip.values())
        dns_servers = {
            str(entry["ip_address"])
            for entry in baseline
            if entry.get("device_type") == "DNS_SERVER" and entry.get("ip_address")
        }
        dhcp_servers = {
            str(entry["ip_address"])
            for entry in baseline
            if entry.get("device_type") == "DHCP_SERVER" and entry.get("ip_address")
        }
        dhcp_server_macs = {
            _normalize_mac(str(entry["mac_address"]))
            for entry in baseline
            if entry.get("device_type") == "DHCP_SERVER" and entry.get("mac_address")
        }
        alerts: list[dict[str, Any]] = []

        def append_alert(
            alert_type: str,
            severity: str,
            mac: str,
            target: str,
            evidence: str,
        ) -> None:
            alert = self._make_alert(
                alert_type,
                severity,
                mac,
                target,
                evidence,
                packet_details,
                now,
            )
            if alert:
                alerts.append(alert)

        observed_arp_mac = arp_src_mac or eth_src
        if "arp" in protocols and arp_opcode and arp_src_ip in baseline_by_ip:
            expected_mac = baseline_by_ip[arp_src_ip]
            if observed_arp_mac and observed_arp_mac != expected_mac:
                append_alert(
                    "GATEWAY_SPOOFING"
                    if baseline_type_by_ip.get(arp_src_ip) == "GATEWAY"
                    else "ARP_SPOOFING",
                    "HIGH" if baseline_type_by_ip.get(arp_src_ip) == "GATEWAY" else "MEDIUM",
                    eth_src or observed_arp_mac,
                    arp_src_ip,
                    f"Anuncio ARP: {arp_src_ip} se asocia a {observed_arp_mac}; "
                    f"la línea base verificada indica {expected_mac}. MAC Ethernet de origen: {eth_src or 'desconocida'}.",
                )
            elif arp_src_mac and eth_src and arp_src_mac != eth_src:
                append_alert(
                    "ARP_SPOOFING",
                    "HIGH",
                    eth_src,
                    arp_src_ip,
                    f"La MAC Ethernet de origen ({eth_src}) no coincide con la MAC anunciada en ARP ({arp_src_mac}).",
                )

        if "arp" not in protocols and ip_src in baseline_by_ip and eth_src and eth_src != baseline_by_ip[ip_src]:
            expected_mac = baseline_by_ip[ip_src]
            is_gateway = baseline_type_by_ip.get(ip_src) == "GATEWAY"
            append_alert(
                "GATEWAY_SPOOFING" if is_gateway else "IP_SPOOFING",
                "HIGH" if is_gateway else "MEDIUM",
                eth_src,
                ip_src,
                f"El tráfico que afirma proceder de {ip_src} llegó desde {eth_src}; "
                f"la línea base indica {expected_mac}. Verifica la línea base y posibles interfaces "
                "virtuales, multihoming o cambios legítimos de NIC.",
            )
            trusted_ips = baseline_ips_by_mac.get(eth_src, set())
            if trusted_ips and ip_src not in trusted_ips:
                expected_ips = ", ".join(sorted(trusted_ips))
                append_alert(
                    "MAC_SPOOFING",
                    "MEDIUM",
                    eth_src,
                    ip_src,
                    f"La MAC registrada para {expected_ips} también se observó con el origen IP {ip_src}. "
                    "Esto puede deberse a multihoming o enrutamiento; verifica antes de tratarlo como suplantación.",
                )

        dhcp_type = fields[FIELD_DHCP_MESSAGE_TYPE]
        transaction_id = fields[FIELD_BOOTP_TRANSACTION_ID]
        dhcp_server = fields[FIELD_DHCP_SERVER_ID] or ip_src
        if dhcp_type in {"2", "5"} and transaction_id and dhcp_server:
            if dhcp_servers and dhcp_server not in dhcp_servers:
                append_alert(
                    "DHCP_SPOOFING",
                    "MEDIUM",
                    eth_src,
                    dhcp_server,
                    f"Respuesta DHCP desde {dhcp_server}, que no está en la lista de servidores DHCP confiables. "
                    "Puede ser un servidor legítimo aún no clasificado.",
                )
            previous = self._dhcp_offers.get(transaction_id)
            if previous and previous[0] != dhcp_server and now - previous[2] <= STATE_TTL_SECONDS:
                append_alert(
                    "DHCP_SPOOFING",
                    "MEDIUM",
                    eth_src,
                    dhcp_server,
                    f"El mismo intercambio DHCP recibió ofertas/respuestas de {previous[0]} y {dhcp_server}; "
                    "confirma que ambos servidores estén autorizados.",
                )
            else:
                self._remember(
                    self._dhcp_offers,
                    transaction_id,
                    (dhcp_server, eth_src, now),
                    now,
                )

        dhcpv6_type = fields[FIELD_DHCPV6_MESSAGE_TYPE]
        dhcpv6_transaction = fields[FIELD_DHCPV6_TRANSACTION_ID]
        if dhcpv6_type in {"2", "7"} and dhcpv6_transaction and eth_src:
            if dhcp_server_macs and eth_src not in dhcp_server_macs:
                append_alert(
                    "DHCPV6_SPOOFING",
                    "MEDIUM",
                    eth_src,
                    ip_src,
                    f"Respuesta DHCPv6 desde la MAC {eth_src}, que no está clasificada como servidor DHCP confiable. "
                    "La lista IPv4 de servidores no se usa para juzgar direcciones IPv6.",
                )
            previous = self._dhcp_offers.get(f"dhcpv6:{dhcpv6_transaction}")
            if previous and previous[1] != eth_src and now - previous[2] <= STATE_TTL_SECONDS:
                append_alert(
                    "DHCPV6_SPOOFING",
                    "MEDIUM",
                    eth_src,
                    f"DHCPv6:{dhcpv6_transaction}",
                    f"El mismo intercambio DHCPv6 recibió anuncios/respuestas desde "
                    f"{previous[1]} y {eth_src}; confirma que ambos servidores estén autorizados.",
                )
            else:
                self._remember(
                    self._dhcp_offers,
                    f"dhcpv6:{dhcpv6_transaction}",
                    ("", eth_src, now),
                    now,
                )

        if "dns" in protocols and not local_protocol and dns_response and dns_query and dns_id:
            if dns_servers and ip_src not in dns_servers:
                append_alert(
                    "DNS_SPOOFING",
                    "MEDIUM",
                    eth_src,
                    dns_query,
                    f"Respuesta DNS para {dns_query} desde {ip_src}, que no está en la lista de DNS confiables. "
                    "Verifica si se trata de un resolver legítimo, VPN o DNS alternativo.",
                )
            transaction_key = (dns_id, dns_query, fields[14] or fields[16])
            previous = self._dns_answers.get(transaction_key)
            if (
                previous
                and dns_answer
                and previous[0] != dns_answer
                and previous[1] != eth_src
                and now - previous[2] <= STATE_TTL_SECONDS
            ):
                append_alert(
                    "DNS_SPOOFING",
                    "MEDIUM",
                    eth_src,
                    dns_query,
                    f"Respuestas DNS distintas para la misma consulta {dns_query}: "
                    f"{previous[0]} y {dns_answer}. Puede ser una respuesta concurrente, balanceo "
                    "o DNS de horizonte dividido; confirma el servidor y el contexto antes de escalar.",
                )
            elif dns_answer:
                self._remember(
                    self._dns_answers,
                    transaction_key,
                    (dns_answer, eth_src, now),
                    now,
                )

        if fields[FIELD_NBNS_RESPONSE] and _is_true(fields[FIELD_NBNS_RESPONSE]):
            name, answer = fields[FIELD_NBNS_NAME].casefold(), fields[FIELD_NBNS_ADDRESS]
            txid = fields[FIELD_NBNS_TRANSACTION_ID]
            if name and answer and txid:
                key = (txid, name, "nbns")
                previous = self._local_name_answers.get(key)
                if previous and previous[0] != answer and now - previous[2] <= STATE_TTL_SECONDS:
                    append_alert(
                        "NBNS_SPOOFING",
                        "MEDIUM",
                        eth_src,
                        name,
                        f"Respuestas NBNS distintas para {name}: {previous[0]} y {answer}. "
                        "Puede tratarse de nombres duplicados legítimos; valida qué equipo debe responder.",
                    )
                else:
                    self._remember(self._local_name_answers, key, (answer, eth_src, now), now)

        if local_protocol and dns_response and dns_query and dns_answer:
            key = (dns_id, dns_query, local_protocol)
            previous = self._local_name_answers.get(key)
            if previous and previous[0] != dns_answer and now - previous[2] <= STATE_TTL_SECONDS:
                alert_type = "LLMNR_SPOOFING" if local_protocol == "llmnr" else "MDNS_SPOOFING"
                append_alert(
                    alert_type,
                    "MEDIUM",
                    eth_src,
                    dns_query,
                    f"Respuestas {local_protocol.upper()} contradictorias para {dns_query}: {previous[0]} y {dns_answer}.",
                )
            else:
                self._remember(self._local_name_answers, key, (dns_answer, eth_src, now), now)

        icmpv6_type = fields[FIELD_ICMPV6_TYPE]
        if icmpv6_type == "134" and gateway_macs and eth_src not in gateway_macs:
            append_alert(
                "NDP_SPOOFING",
                "MEDIUM",
                eth_src,
                ip_src,
                f"Router Advertisement IPv6 recibido desde {eth_src}, no asociado a un gateway clasificado. "
                "Verifica si existe un segundo router IPv6 autorizado.",
            )
        elif icmpv6_type == "134" and not gateway_macs and eth_src not in trusted_macs:
            append_alert(
                "NDP_SPOOFING",
                "MEDIUM",
                eth_src,
                ip_src,
                f"Router Advertisement IPv6 recibido desde la MAC no registrada {eth_src}; "
                "verifica si el router está autorizado.",
            )
        elif icmpv6_type == "136":
            target = fields[FIELD_NDP_NA_TARGET] or fields[FIELD_NDP_NS_TARGET]
            if target and eth_src:
                previous = self._ipv6_neighbors.get(target)
                if previous and previous[0] != eth_src and now - previous[1] <= STATE_TTL_SECONDS:
                    append_alert(
                        "NDP_SPOOFING",
                        "MEDIUM",
                        eth_src,
                        target,
                        f"Neighbor Advertisement contradictorios para {target}: {previous[0]} y {eth_src}. "
                        "Verifica si hubo cambio legítimo de NIC, failover o privacidad IPv6.",
                    )
                else:
                    self._remember(self._ipv6_neighbors, target, (eth_src, now), now)

        return alerts

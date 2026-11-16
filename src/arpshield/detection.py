from __future__ import annotations

import ipaddress
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
ARP_BURST_WINDOW_SECONDS = 10.0
ARP_BURST_THRESHOLD = 10
ARP_REQUEST_TTL_SECONDS = 5.0
DNS_QUERY_TTL_SECONDS = 10.0


def _first_value(value: str) -> str:
    return value.split(",", maxsplit=1)[0].strip()


def _normalize_mac(value: str) -> str:
    return _first_value(value).replace("-", ":").strip().upper()


def _is_true(value: str) -> bool:
    return _first_value(value).casefold() in {"1", "true", "yes"}


def _normalize_dns_answers(*values: str) -> str:
    answers = {
        answer.strip().casefold()
        for value in values
        for answer in value.split(",")
        if answer.strip()
    }
    return ",".join(sorted(answers))


def _select_attacker_mac(previous_mac: str, current_mac: str, trusted_macs: set[str]) -> str:
    if current_mac in trusted_macs and previous_mac and previous_mac not in trusted_macs:
        return previous_mac
    return current_mac or previous_mac


def _is_link_local_ipv6(value: str) -> bool:
    try:
        return ipaddress.IPv6Address(value).is_link_local
    except ipaddress.AddressValueError:
        return False


class SpoofingDetector:
    def __init__(self) -> None:
        self._recent_alerts: OrderedDict[tuple[str, str, str], float] = OrderedDict()
        self._dns_answers: OrderedDict[tuple[str, ...], tuple[str, str, float]] = OrderedDict()
        self._dns_queries: OrderedDict[tuple[str, str, str, str], float] = OrderedDict()
        self._dhcp_offers: OrderedDict[str, tuple[str, str, float]] = OrderedDict()
        self._local_name_answers: OrderedDict[
            tuple[str, str, str], tuple[str, str, float]
        ] = OrderedDict()
        self._ipv6_neighbors: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._arp_neighbors: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._arp_requests: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._arp_mac_ips: OrderedDict[str, tuple[set[str], float]] = OrderedDict()
        self._arp_reply_bursts: OrderedDict[tuple[str, str], list[float]] = OrderedDict()

    def reset(self) -> None:
        self._recent_alerts.clear()
        self._dns_answers.clear()
        self._dns_queries.clear()
        self._dhcp_offers.clear()
        self._local_name_answers.clear()
        self._ipv6_neighbors.clear()
        self._arp_neighbors.clear()
        self._arp_requests.clear()
        self._arp_mac_ips.clear()
        self._arp_reply_bursts.clear()

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
        arp_opcode = _first_value(fields[5])
        arp_src_ip = _first_value(fields[6])
        arp_src_mac = _normalize_mac(fields[7])
        arp_dst_ip = _first_value(fields[8])
        dns_query = _first_value(fields[10]).rstrip(".").casefold()
        dns_response = _is_true(fields[11])
        dns_answer = _normalize_dns_answers(fields[12], fields[FIELD_DNS_AAAA])
        ip_src = _first_value(fields[13]) or _first_value(fields[15]) or arp_src_ip
        ip_dst = _first_value(fields[14]) or _first_value(fields[16])
        dns_id = _first_value(fields[20]) if len(fields) > 20 else ""
        udp_ports = {_first_value(fields[31]), _first_value(fields[32])}
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
        if "arp" in protocols and arp_opcode:
            if arp_opcode == "1" and arp_src_ip and arp_dst_ip:
                self._remember(
                    self._arp_requests,
                    (arp_dst_ip, arp_src_ip),
                    now,
                    now,
                )
            elif arp_opcode == "2":
                request_key = (arp_src_ip, arp_dst_ip)
                request_time = self._arp_requests.pop(request_key, None)
                has_recent_request = (
                    request_time is not None
                    and now - request_time <= ARP_REQUEST_TTL_SECONDS
                )
                is_gratuitous = bool(
                    arp_src_ip and arp_dst_ip and arp_src_ip == arp_dst_ip
                )
                baseline_match = baseline_by_ip.get(arp_src_ip) == observed_arp_mac
                if is_gratuitous:
                    append_alert(
                        "ARP_SPOOFING",
                        "MEDIUM",
                        eth_src or observed_arp_mac,
                        arp_src_ip,
                        f"Respuesta ARP gratuita (is-at) de {arp_src_ip} desde {observed_arp_mac}; "
                        "valida si el anuncio corresponde a una actualización legítima.",
                    )
                elif (
                    not has_recent_request
                    and not baseline_match
                    and arp_src_ip not in baseline_by_ip
                    and not (arp_src_mac and eth_src and arp_src_mac != eth_src)
                ):
                    append_alert(
                        "ARP_SPOOFING",
                        "MEDIUM",
                        eth_src or observed_arp_mac,
                        arp_src_ip or "UNKNOWN",
                        f"Respuesta ARP is-at sin solicitud correspondiente observada para "
                        f"{arp_src_ip or 'IP desconocida'} desde {observed_arp_mac}; "
                        "la captura puede haber comenzado a mitad de una conversación.",
                    )

            if arp_src_ip in baseline_by_ip:
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
                        "GATEWAY_SPOOFING"
                        if baseline_type_by_ip.get(arp_src_ip) == "GATEWAY"
                        else "ARP_SPOOFING",
                        "HIGH" if baseline_type_by_ip.get(arp_src_ip) == "GATEWAY" else "MEDIUM",
                        eth_src,
                        arp_src_ip,
                        f"La MAC Ethernet de origen ({eth_src}) no coincide con la MAC anunciada en ARP "
                        f"({arp_src_mac}) para {arp_src_ip}. Verifica la topología y el equipo que originó la trama.",
                    )
            else:
                if arp_src_mac and eth_src and arp_src_mac != eth_src:
                    append_alert(
                        "ARP_SPOOFING",
                        "MEDIUM",
                        eth_src,
                        arp_src_ip or "UNKNOWN",
                        f"La MAC Ethernet de origen ({eth_src}) no coincide con la MAC anunciada en ARP "
                        f"({arp_src_mac}) para {arp_src_ip or 'IP desconocida'}.",
                    )
                if arp_src_ip and arp_src_ip != "0.0.0.0" and observed_arp_mac:
                    previous_arp = self._arp_neighbors.get(arp_src_ip)
                    if (
                        previous_arp
                        and previous_arp[0] != observed_arp_mac
                        and now - previous_arp[1] <= STATE_TTL_SECONDS
                    ):
                        attacker = _select_attacker_mac(
                            previous_arp[0], eth_src or observed_arp_mac, trusted_macs
                        )
                        append_alert(
                            "ARP_SPOOFING",
                            "MEDIUM",
                            attacker,
                            arp_src_ip,
                            f"Asociación ARP en conflicto para {arp_src_ip}: se observó con "
                            f"{previous_arp[0]} y {observed_arp_mac}.",
                        )
                        if observed_arp_mac in trusted_macs:
                            self._remember(
                                self._arp_neighbors, arp_src_ip, (observed_arp_mac, now), now
                            )
                    else:
                        self._remember(
                            self._arp_neighbors, arp_src_ip, (observed_arp_mac, now), now
                        )

            if arp_src_ip and arp_src_ip != "0.0.0.0" and observed_arp_mac:
                existing_ips_record = self._arp_mac_ips.get(observed_arp_mac)
                if existing_ips_record and now - existing_ips_record[1] <= STATE_TTL_SECONDS:
                    claimed_ips = set(existing_ips_record[0])
                else:
                    claimed_ips = set()
                claimed_ips.add(arp_src_ip)
                self._remember(self._arp_mac_ips, observed_arp_mac, (claimed_ips, now), now)
                trusted_for_mac = baseline_ips_by_mac.get(observed_arp_mac, set())
                if len(claimed_ips) >= 2 and not claimed_ips.issubset(trusted_for_mac):
                    sorted_ips = ", ".join(sorted(claimed_ips))
                    has_gateway = any(
                        baseline_type_by_ip.get(ip) == "GATEWAY" for ip in claimed_ips
                    )
                    append_alert(
                        "MULTIPLE_IPS_PER_MAC",
                        "HIGH" if has_gateway else "MEDIUM",
                        eth_src or observed_arp_mac,
                        sorted_ips,
                        f"La MAC {observed_arp_mac} reclama múltiples direcciones IP por ARP: {sorted_ips}.",
                    )

            if arp_opcode == "2" and observed_arp_mac:
                burst_key = (observed_arp_mac, arp_src_ip)
                recent_replies = [
                    ts
                    for ts in self._arp_reply_bursts.get(burst_key, [])
                    if now - ts <= ARP_BURST_WINDOW_SECONDS
                ]
                recent_replies.append(now)
                self._arp_reply_bursts[burst_key] = recent_replies
                if len(recent_replies) >= ARP_BURST_THRESHOLD:
                    append_alert(
                        "ARP_BURST_UNSOLICITED",
                        "MEDIUM",
                        eth_src or observed_arp_mac,
                        arp_src_ip or "UNKNOWN",
                        f"Ráfaga de {len(recent_replies)} respuestas ARP desde {observed_arp_mac} "
                        f"en menos de {int(ARP_BURST_WINDOW_SECONDS)} segundos.",
                    )

        if "arp" not in protocols and ip_src and eth_src:
            eth_dst = _normalize_mac(fields[4])
            if ip_src in baseline_by_ip and eth_src != baseline_by_ip[ip_src]:
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
            elif ip_src not in baseline_by_ip and "." in ip_src and ip_src != "0.0.0.0":
                subnet_prefix = ".".join(ip_src.split(".")[:3])
                if eth_dst and eth_dst != "FF:FF:FF:FF:FF:FF":
                    gateway_key = f"gw_subnet:{eth_dst}"
                    prev_subnet = self._arp_neighbors.get(gateway_key)
                    if (
                        prev_subnet
                        and prev_subnet[0] != subnet_prefix
                        and eth_src != eth_dst
                        and now - prev_subnet[1] <= STATE_TTL_SECONDS
                    ):
                        append_alert(
                            "IP_SPOOFING",
                            "MEDIUM",
                            eth_src,
                            ip_src,
                            f"Tráfico saliente hacia {eth_dst} con IP de origen {ip_src} fuera de la subred local "
                            f"observada ({prev_subnet[0]}.0/24) desde la MAC {eth_src}.",
                        )
                    else:
                        self._remember(self._arp_neighbors, gateway_key, (subnet_prefix, now), now)

        dhcp_type = _first_value(fields[FIELD_DHCP_MESSAGE_TYPE])
        transaction_id = _first_value(fields[FIELD_BOOTP_TRANSACTION_ID])
        dhcp_server = _first_value(fields[FIELD_DHCP_SERVER_ID]) or ip_src
        if dhcp_type in {"2", "5"} and dhcp_server:
            previous = (
                self._dhcp_offers.get(transaction_id) if transaction_id else None
            ) or self._dhcp_offers.get("__active_dhcp_server__")
            has_conflict = (
                previous is not None
                and (previous[0] != dhcp_server or (previous[1] and eth_src and previous[1] != eth_src))
                and now - previous[2] <= STATE_TTL_SECONDS
            )
            untrusted_dhcp = bool(
                not dhcp_servers
                or (
                    dhcp_server not in dhcp_servers
                    or (dhcp_server in baseline_by_ip and eth_src and eth_src != baseline_by_ip[dhcp_server])
                )
            )
            if has_conflict and previous is not None:
                allowed_macs = dhcp_server_macs or trusted_macs
                attacker = _select_attacker_mac(previous[1], eth_src, allowed_macs)
                spoofed_target = (
                    previous[0]
                    if attacker == previous[1] and previous[1] != eth_src
                    else dhcp_server
                )
                append_alert(
                    "DHCP_SPOOFING",
                    "MEDIUM",
                    attacker,
                    spoofed_target,
                    f"Se detectaron múltiples servidores DHCP respondiendo en la red: {previous[0]} ({previous[1] or 'MAC N/D'}) "
                    f"y {dhcp_server} ({eth_src or 'MAC N/D'}); confirma que ambos servidores estén autorizados.",
                )
                if eth_src in allowed_macs:
                    if transaction_id:
                        self._remember(
                            self._dhcp_offers,
                            transaction_id,
                            (dhcp_server, eth_src, now),
                            now,
                        )
                    self._remember(
                        self._dhcp_offers,
                        "__active_dhcp_server__",
                        (dhcp_server, eth_src, now),
                        now,
                    )
            else:
                if untrusted_dhcp:
                    append_alert(
                        "DHCP_SPOOFING",
                        "MEDIUM",
                        eth_src,
                        dhcp_server,
                        f"Respuesta DHCP desde {dhcp_server}, que no está en la lista de servidores DHCP confiables. "
                        "Puede ser un servidor legítimo aún no clasificado.",
                    )
                if transaction_id:
                    self._remember(
                        self._dhcp_offers,
                        transaction_id,
                        (dhcp_server, eth_src, now),
                        now,
                    )
                self._remember(
                    self._dhcp_offers,
                    "__active_dhcp_server__",
                    (dhcp_server, eth_src, now),
                    now,
                )

        dhcpv6_type = _first_value(fields[FIELD_DHCPV6_MESSAGE_TYPE])
        dhcpv6_transaction = _first_value(fields[FIELD_DHCPV6_TRANSACTION_ID])
        if dhcpv6_type in {"2", "7"} and eth_src:
            if not dhcp_server_macs or eth_src not in dhcp_server_macs:
                append_alert(
                    "DHCPV6_SPOOFING",
                    "MEDIUM",
                    eth_src,
                    ip_src,
                    f"Respuesta DHCPv6 desde la MAC {eth_src}, que no está clasificada como servidor DHCP confiable. "
                    "La lista IPv4 de servidores no se usa para juzgar direcciones IPv6.",
                )
            if dhcpv6_transaction:
                previous = self._dhcp_offers.get(f"dhcpv6:{dhcpv6_transaction}")
                if previous and previous[1] != eth_src and now - previous[2] <= STATE_TTL_SECONDS:
                    allowed_macs = dhcp_server_macs or trusted_macs
                    attacker = _select_attacker_mac(previous[1], eth_src, allowed_macs)
                    append_alert(
                        "DHCPV6_SPOOFING",
                        "MEDIUM",
                        attacker,
                        f"DHCPv6:{dhcpv6_transaction}",
                        f"El mismo intercambio DHCPv6 recibió anuncios/respuestas desde "
                        f"{previous[1]} y {eth_src}; confirma que ambos servidores estén autorizados.",
                    )
                    if eth_src in allowed_macs:
                        self._remember(
                            self._dhcp_offers,
                            f"dhcpv6:{dhcpv6_transaction}",
                            ("", eth_src, now),
                            now,
                        )
                else:
                    self._remember(
                        self._dhcp_offers,
                        f"dhcpv6:{dhcpv6_transaction}",
                        ("", eth_src, now),
                        now,
                    )

        if "dns" in protocols and not local_protocol:
            if dns_response:
                if dns_id:
                    query_key = (dns_id, dns_query, ip_dst, ip_src)
                    query_time = self._dns_queries.pop(query_key, None)
                    if query_time is None or now - query_time > DNS_QUERY_TTL_SECONDS:
                        append_alert(
                            "DNS_SPOOFING",
                            "MEDIUM",
                            eth_src or ip_src,
                            dns_query or ip_src or "DNS",
                            f"Respuesta DNS no solicitada observada para "
                            f"{dns_query or 'consulta desconocida'} desde "
                            f"{ip_src or 'servidor desconocido'}; valida si la captura empezó "
                            "a mitad del intercambio.",
                        )
                if dns_query and dns_id:
                    transaction_key = (dns_id, dns_query, ip_dst)
                    previous = self._dns_answers.get(transaction_key)
                    has_dns_conflict = bool(
                        previous
                        and dns_answer
                        and previous[0] != dns_answer
                        and now - previous[2] <= DNS_QUERY_TTL_SECONDS
                    )
                    untrusted_dns = bool(
                        dns_servers
                        and (
                            ip_src not in dns_servers
                            or (
                                ip_src in baseline_by_ip
                                and eth_src
                                and eth_src != baseline_by_ip[ip_src]
                            )
                        )
                    )
                    if has_dns_conflict and previous is not None:
                        attacker = _select_attacker_mac(previous[1], eth_src, trusted_macs)
                        append_alert(
                            "DNS_SPOOFING",
                            "MEDIUM",
                            attacker,
                            dns_query,
                            f"Respuestas DNS distintas para la misma consulta {dns_query}: "
                            f"{previous[0]} ({previous[1] or 'MAC N/D'}) y "
                            f"{dns_answer} ({eth_src or 'MAC N/D'}). Puede ser una respuesta "
                            "concurrente, balanceo o DNS de horizonte dividido; confirma el "
                            "servidor y el contexto antes de escalar.",
                        )
                        if eth_src in trusted_macs and dns_answer:
                            self._remember(
                                self._dns_answers,
                                transaction_key,
                                (dns_answer, eth_src, now),
                                now,
                            )
                    else:
                        if untrusted_dns:
                            append_alert(
                                "DNS_SPOOFING",
                                "MEDIUM",
                                eth_src,
                                dns_query,
                                f"Respuesta DNS para {dns_query} desde {ip_src}, que no está "
                                "en la lista de DNS confiables. Verifica si se trata de un "
                                "resolver legítimo, VPN o DNS alternativo.",
                            )
                        if dns_answer:
                            self._remember(
                                self._dns_answers,
                                transaction_key,
                                (dns_answer, eth_src, now),
                                now,
                            )
            elif dns_query and dns_id and ip_src and ip_dst:
                query_key = (dns_id, dns_query, ip_src, ip_dst)
                self._remember(self._dns_queries, query_key, now, now)

        if fields[FIELD_NBNS_RESPONSE] and _is_true(fields[FIELD_NBNS_RESPONSE]):
            name = _first_value(fields[FIELD_NBNS_NAME]).casefold()
            answer = _normalize_dns_answers(fields[FIELD_NBNS_ADDRESS])
            txid = _first_value(fields[FIELD_NBNS_TRANSACTION_ID])
            if eth_src not in trusted_macs:
                append_alert(
                    "NBNS_SPOOFING",
                    "MEDIUM",
                    eth_src,
                    name or ip_src or "NBNS",
                    f"Respuesta NB-NS para {name or 'nombre desconocido'} desde la MAC no "
                    f"autorizada {eth_src or 'desconocida'}; valida el host que respondió.",
                )
            if name and answer and txid:
                key = (txid, name, "nbns")
                previous = self._local_name_answers.get(key)
                if previous and previous[0] != answer and now - previous[2] <= DNS_QUERY_TTL_SECONDS:
                    attacker = _select_attacker_mac(previous[1], eth_src, trusted_macs)
                    append_alert(
                        "NBNS_SPOOFING",
                        "MEDIUM",
                        attacker,
                        name,
                        f"Respuestas NBNS distintas para {name}: {previous[0]} y {answer}. "
                        "Puede tratarse de nombres duplicados legítimos; valida qué equipo debe responder.",
                    )
                    if eth_src in trusted_macs:
                        self._remember(self._local_name_answers, key, (answer, eth_src, now), now)
                else:
                    self._remember(self._local_name_answers, key, (answer, eth_src, now), now)

        if local_protocol and dns_response and dns_query:
            alert_type = "LLMNR_SPOOFING" if local_protocol == "llmnr" else "MDNS_SPOOFING"
            if eth_src not in trusted_macs:
                append_alert(
                    alert_type,
                    "MEDIUM",
                    eth_src,
                    dns_query,
                    f"Respuesta {local_protocol.upper()} para {dns_query} desde la MAC no "
                    f"autorizada {eth_src or 'desconocida'}; valida el equipo que respondió.",
                )
            if dns_answer:
                key = (dns_id, dns_query, local_protocol)
                previous = self._local_name_answers.get(key)
                if previous and previous[0] != dns_answer and now - previous[2] <= DNS_QUERY_TTL_SECONDS:
                    attacker = _select_attacker_mac(previous[1], eth_src, trusted_macs)
                    append_alert(
                        alert_type,
                        "MEDIUM",
                        attacker,
                        dns_query,
                        f"Respuestas {local_protocol.upper()} contradictorias para "
                        f"{dns_query}: {previous[0]} y {dns_answer}.",
                    )
                    if eth_src in trusted_macs:
                        self._remember(self._local_name_answers, key, (dns_answer, eth_src, now), now)
                else:
                    self._remember(self._local_name_answers, key, (dns_answer, eth_src, now), now)

        icmpv6_types = {item.strip() for item in fields[FIELD_ICMPV6_TYPE].split(",") if item.strip()}
        if (
            "134" in icmpv6_types
            and _is_link_local_ipv6(ip_src)
            and eth_src not in gateway_macs
        ):
            append_alert(
                "NDP_SPOOFING",
                "MEDIUM",
                eth_src,
                ip_src,
                f"Router Advertisement IPv6 desde la dirección link-local {ip_src} y la MAC "
                f"no autorizada {eth_src or 'desconocida'}; verifica si el router está autorizado.",
            )
        elif "136" in icmpv6_types:
            target = _first_value(fields[FIELD_NDP_NA_TARGET]) or _first_value(fields[FIELD_NDP_NS_TARGET])
            if target and eth_src:
                previous = self._ipv6_neighbors.get(target)
                if previous and previous[0] != eth_src and now - previous[1] <= STATE_TTL_SECONDS:
                    attacker = _select_attacker_mac(previous[0], eth_src, trusted_macs)
                    append_alert(
                        "NDP_SPOOFING",
                        "MEDIUM",
                        attacker,
                        target,
                        f"Neighbor Advertisement contradictorios para {target}: {previous[0]} y {eth_src}. "
                        "Verifica si hubo cambio legítimo de NIC, failover o privacidad IPv6.",
                    )
                    if eth_src in trusted_macs:
                        self._remember(self._ipv6_neighbors, target, (eth_src, now), now)
                else:
                    self._remember(self._ipv6_neighbors, target, (eth_src, now), now)

        return alerts

# ARPShield

ARPShield es un monitor local de red para detectar señales de suplantación en LAN pequeñas. Incluye análisis pasivo de ARP, direcciones IP/MAC, respuestas DNS, ofertas DHCP/DHCPv6 en conflicto, LLMNR/NBNS/mDNS y anuncios NDP/IPv6 cuando esos paquetes son visibles en la interfaz capturada.

## Objetivo

- Detectar cambios sospechosos en la tabla ARP local.
- Registrar alertas y evidencia forense en SQLite.
- Mostrar un panel con estado de la red y alertas relevantes.
- Preparar la base para mitigación mediante `netsh` en Windows.

## Estructura inicial

- `src/arpshield`: código fuente principal del proyecto.
- `tests`: pruebas unitarias del almacenamiento de datos y lógica base.
- `docs`: especificaciones de arquitectura, seguridad y base de datos.

## Requisitos

- Python 3.10+
- PySide6
- Scapy

## Ejecución

```bash
python -m pip install -r requirements.txt
python main.py
```

## Base de diseño

La implementación sigue la línea de la documentación del proyecto:

- Base de datos local con `trusted_baseline`, `security_alerts` y `audit_logs`.
- Validación de IPv4 y MAC antes de invocar procesos del sistema.
- Ventana principal con línea base, alertas y acciones de mitigación.
- Motor de detección con escaneo local de red y análisis sencillo de anomalías.

## Detección pasiva de spoofing

En la pestaña **Tráfico**, inicia una captura con el filtro predeterminado para analizar ARP, DNS, DHCP/DHCPv6/BOOTP, LLMNR, NBNS, mDNS e ICMPv6/NDP. En Windows, instala Wireshark con Npcap y asegúrate de contar con permisos de captura. Las alertas detectadas durante la captura o el análisis de PCAP se guardan en SQLite y aparecen en el dashboard.

Los detectores comparan anuncios IP/MAC y gateways IPv6 con la línea base; comparan respuestas DNS con DNS marcados como confiables y correlacionan respuestas del mismo intercambio; y revisan DHCP/DHCPv6 y respuestas de nombres locales. mDNS y LLMNR se distinguen de DNS por sus puertos UDP para no tratarlos erróneamente como resolvers DNS convencionales. Tras escanear, abre **Ajustes** para clasificar gateway, DNS y DHCP autorizados. La línea base es sensible: el primer escaneo agrega equipos nuevos, pero **no reemplaza automáticamente** las asociaciones existentes. Un primer escaneo durante un ataque podría registrar una MAC falsa; verifica IP/MAC por una fuente independiente antes de confiar en la línea base.

Al seleccionar una alerta del dashboard se abre su detalle: resumen, severidad, fecha, dispositivo y campos de paquete capturados por TShark (incluyendo número de trama, protocolo, IP/MAC, puertos y campos específicos del protocolo disponibles). No se almacena el payload de aplicación. Las señales que dependen de reglas de confianza o respuestas concurrentes son de revisión (MEDIUM), no una afirmación de ataque confirmado; cambios en NIC, multihoming, DNS round-robin/split-horizon y varios routers o servidores autorizados pueden explicar discrepancias. Una MAC/IP desconocida se compara con la línea base solo si esta existe y está correctamente clasificada.

Esto **no garantiza detectar todo spoofing**. Las categorías `MULTIPLE_IPS_PER_MAC` y `ARP_BURST_UNSOLICITED` están reservadas en el esquema, pero aún no tienen reglas de detección implementadas. Una captura en un PC de una red conmutada puede no ver paquetes unicast entre otros equipos; DNS cifrado (DoH/DoT), redes Wi-Fi que requieren modo monitor, ataques fuera de la interfaz, suplantaciones de aplicación/TLS y protocolos que no aparezcan en la captura quedan fuera. El filtro elegido también limita la visibilidad. Usa un puerto espejo/TAP o sensores en los segmentos pertinentes y configura referencias confiables para elevar la cobertura. Las alertas indican señales sospechosas, no una prueba definitiva de intrusión.

En Windows, ARPShield relaciona las interfaces de Npcap con adaptadores físicos y muestra su estado, excluyendo miniports WAN y fuentes remotas no configuradas. Para una LAN cableada, selecciona el adaptador Ethernet físico; si no aparece, verifica que haya una tarjeta conectada/habilitada, su controlador y Npcap. Si la captura funciona pero no muestra tráfico de otros dispositivos, es una limitación normal de los switches: configura port mirroring/SPAN o usa un TAP de red. ARPShield no puede observar paquetes que el adaptador no recibe.

## Uso en equipos con recursos limitados

La interfaz limita el historial visible a los últimos 500 paquetes y 100 alertas, actualiza la tabla de paquetes por lotes y consulta estadísticas agregadas para el dashboard. El panel se actualiza cada 15 segundos solo cuando está visible. Estos límites reducen el consumo de memoria y CPU cuando hay historial extenso; no limitan los registros que ya están guardados en SQLite.

En equipos con 4 GB de RAM, se recomienda cerrar aplicaciones pesadas durante la captura y mantener el filtro de tráfico acotado (por defecto, ARP, DNS, DHCP/DHCPv6, LLMNR/NBNS/mDNS e ICMPv6). La captura sigue dependiendo de TShark/Wireshark y del sistema operativo, por lo que el consumo total varía según el tráfico y los programas abiertos.

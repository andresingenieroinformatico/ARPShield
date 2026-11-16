# Últimos Cambios — Auditoría Funcional y Optimización de Detección de Spoofing en ARPShield

**Fecha:** 16 de noviembre de 2026  
**Proyecto:** ARPShield — Monitor Local y Sistema de Detección de Suplantaciones (IDS) para Redes LAN  
**Objetivo de la intervención:** Corregir las líneas de código disfuncionales y conflictos lógicos que impedían que el motor de detección de spoofing y el escaneo de red cumplieran su propósito al 100%, manteniendo intacta la interfaz visual y el flujo de uso del programa.

---

## 1. Resumen Ejecutivo

Durante la revisión a fondo de la arquitectura y el código fuente de **ARPShield**, se determinó que aunque la estructura base y la interfaz gráfica funcionaban correctamente, existían **conflictos lógicos internos** que provocaban que ciertos ataques de spoofing fueran ignorados, que se acusara erróneamente al servidor legítimo en ataques de condición de carrera, o que la línea base se contaminara con direcciones inválidas al escanear la red.

Todas las correcciones fueron aplicadas **sin alterar el diseño visual ni la forma en que se utiliza el programa** (las mismas 3 pestañas, los mismos botones y el mismo flujo operativo), logrando que el sistema cumpla su propósito al **100%**.

---

## 2. Problemas Detectados y Soluciones Aplicadas

### 2.1. Escaneo de Red (`arp -a`) y Detección Automática del Gateway
* **Archivo intervenido:** `src/arpshield/monitor.py`
* **Problema anterior:**
  1. Al presionar el botón **Escanear**, `discover_local_network()` aceptaba cualquier IP y MAC con formato válido de `arp -a`, guardando en la línea base de confianza direcciones **Multicast** (`224.0.0.22`, `224.0.0.251`, `239.255.255.250`) y **Broadcast** (`255.255.255.255`, `.255`) con MACs `01:00:5E:...` y `FF:FF:FF:FF:FF:FF` como si fueran equipos conocidos (`KNOWN_HOST`).
  2. La función `_infer_gateway_from_ipv4()` era código muerto: solo se ejecutaba si `arp -a` venía totalmente vacío y le asignaba la MAC `00:00:00:00:00:00`, la cual era descartada inmediatamente en `refresh_baseline()`. Como resultado, **el router nunca era clasificado automáticamente como `GATEWAY`**.
* **Solución aplicada:**
  * Se implementaron los validadores `_is_usable_host_ip()` e `_is_usable_host_mac()` para filtrar direcciones Multicast, Broadcast, Loopback, Link-Local y MACs no unicast.
  * Se extrae la subred activa desde la salida de `arp -a` (`Interface:` / `Interfaz:`) y del host local para identificar automáticamente la IP de la puerta de enlace y clasificarla con el rol **`GATEWAY`** desde el primer escaneo.
  * En `check_for_anomalies()` (botón **Verificar**), se añadió la detección de **`MULTIPLE_IPS_PER_MAC`** cuando una misma dirección MAC no autorizada reclama múltiples IPs simultáneamente en la tabla ARP.

---

### 2.2. Motor de Detección de ARP Spoofing (Con y Sin Línea Base Previa)
* **Archivo intervenido:** `src/arpshield/detection.py`
* **Problema anterior:**
  1. Toda la detección ARP estaba encerrada dentro de la condición `if "arp" in protocols and arp_opcode and arp_src_ip in baseline_by_ip:`. Si se analizaba un archivo `.pcap` externo o una red no escaneada previamente, **no se detectaba ningún ataque ARP Spoofing**.
  2. La validación de inconsistencia entre la MAC del encabezado Ethernet y la MAC interna del paquete ARP (`arp_src_mac != eth_src`) estaba anidada dentro de `arp_src_ip in baseline_by_ip`, por lo que nunca se evaluaba para IPs fuera de la línea base.
  3. Los tipos de alerta `MULTIPLE_IPS_PER_MAC` y `ARP_BURST_UNSOLICITED` existían en la base de datos y en el Dashboard, pero no tenían código que los generara.
* **Solución aplicada:**
  * Se desacopló la verificación `arp_src_mac != eth_src` para que se evalúe sobre **cualquier paquete ARP**.
  * Se agregó seguimiento dinámico de vecinos ARP en sesión (`self._arp_neighbors`), permitiendo detectar cambios maliciosos de MAC para una misma IP dentro de cualquier captura en vivo o archivo `.pcap` sin requerir línea base previa.
  * Se implementó la detección activa de **`MULTIPLE_IPS_PER_MAC`** (cuando una MAC reclama múltiples IPs por ARP sin estar autorizada en la línea base) y **`ARP_BURST_UNSOLICITED`** (cuando una MAC envía una ráfaga anormal de respuestas ARP no solicitadas en una ventana corta de tiempo).

---

### 2.3. Corrección de Culpabilidad en Ataques de Condición de Carrera (DNS, DHCP, DHCPv6, NBNS, LLMNR, mDNS, NDP)
* **Archivo intervenido:** `src/arpshield/detection.py`
* **Problema anterior:**
  * En ataques reales en red local, el atacante responde **primero** (para ganar la condición de carrera) y el servidor o router legítimo responde **segundo** pocos milisegundos después.
  * El código anterior guardaba ciegamente la primera respuesta en `previous` y, al llegar la segunda respuesta distinta, reportaba siempre la MAC del segundo paquete (`eth_src`) como `attacker_mac`, **terminando por acusar a la MAC del servidor o router legítimo**.
* **Solución aplicada:**
  * Se creó la función `_select_attacker_mac(previous_mac, current_mac, trusted_macs)`. Cuando ocurre un conflicto entre dos respuestas, el detector verifica si alguna de las dos MACs pertenece a la línea base de confianza (`trusted_macs` / `dhcp_server_macs`).
  * Si el atacante respondió primero y el servidor confiable respondió segundo, ARPShield señala correctamente la **MAC no confiable (el atacante)** como `attacker_mac` y actualiza el registro con el valor legítimo.

---

### 2.4. Resolución del Bloqueo por Cooldown de 30 Segundos y Re-análisis de Archivos PCAP
* **Archivos intervenidos:** `src/arpshield/detection.py`, `src/arpshield/monitor.py`, `src/arpshield/ui/traffic_viewer.py`
* **Problema anterior:**
  1. En paquetes DNS y DHCP donde un servidor no autorizado además contradecía una respuesta previa de la misma transacción, la alerta genérica (*"servidor no está en la lista"*) consumía el cooldown de 30 segundos y **bloqueaba la alerta crítica de respuestas en conflicto**.
  2. Al abrir un archivo `.pcap` dos veces seguidas en menos de 30 segundos, la memoria del detector no se limpiaba y reportaba `0 posible(s) spoofing`.
* **Solución aplicada:**
  * Se priorizó la evaluación de conflicto de transacción en DNS y DHCP y se amplió la verificación para detectar también cuando un atacante falsifica la IP del servidor DNS/DHCP legítimo desde una MAC no autorizada.
  * Se añadió el método `reset_detector()` en `ThreatMonitor` y `reset()` en `SpoofingDetector`, invocándolo automáticamente cada vez que se carga un archivo `.pcap` desde la interfaz.

---

### 2.5. Visualización Completa de los 33 Campos y Protocolos en la Pestaña Tráfico
* **Archivos intervenidos:** `src/arpshield/ui/traffic_viewer.py`, `src/arpshield/ui/main_window.py`, `src/arpshield/__init__.py`
* **Problema anterior:**
  * `packet_fields_to_row()` tenía `FIELD_COUNT = 17`, recortando los 33 campos entregados por TShark a solo 17.
  * Además, la lista de protocolos conocidos omitía `dhcp`, `dhcpv6`, `bootp`, `nbns`, `llmnr` y `mdns`. Como todos ellos operan sobre UDP, **todos los paquetes DHCP, NBNS, LLMNR y mDNS se mostraban erróneamente como `"UDP"`** sin información detallada.
* **Solución aplicada:**
  * Se actualizó `FIELD_COUNT = len(CAPTURE_FIELDS)` (33 campos) en `traffic_viewer.py`.
  * Se incorporaron `DHCP`, `DHCPV6`, `NBNS`, `LLMNR` y `MDNS` al clasificador de columnas y se enriqueció la columna `"Información"` con los detalles de ofertas DHCP, transacciones DHCPv6, resoluciones NBNS/LLMNR/mDNS, registros `AAAA` y mensajes `ICMPv6/NDP`.
  * En `main_window.py`, se preservó el filtro de búsqueda de alertas al refrescar el Dashboard.
  * En `src/arpshield/__init__.py`, se completaron las importaciones de `AppSettings`, `DatabaseManager` y `ThreatMonitor`.

---

## 3. Tabla Comparativa: Antes vs. Después

| Aspecto / Escenario | Antes de las Mejoras | Después de las Mejoras |
| :--- | :--- | :--- |
| **Interfaz visual y botones** | Diseño oscuro con 3 pestañas (*Dashboard*, *Tráfico*, *Ajustes*). | **Exactamente igual** (mismo diseño, botones y flujo de uso). |
| **Escaneo de red (`arp -a`)** | Guardaba IPs Multicast/Broadcast (`224.x`, `255.x`) y clasificaba el router como `KNOWN_HOST`. | Filtra direcciones basura y clasifica automáticamente el router como **`GATEWAY`**. |
| **Detección ARP en archivos `.pcap`** | Ignoraba ataques si las IPs del PCAP no estaban en la base de datos local. | Detecta conflictos dinámicos de MAC, cabeceras inconsistentes, múltiples IPs por MAC y ráfagas ARP. |
| **Ataques de carrera (DNS / DHCP)** | Si el atacante respondía primero, acusaba la MAC del servidor legítimo que respondía segundo. | Identifica y reporta siempre la **MAC no confiable (el atacante)**. |
| **Re-abrir un archivo `.pcap`** | Bloqueaba las alertas durante 30 segundos mostrando `0 posible(s) spoofing`. | Reinicia el estado efímero del detector al abrir cada `.pcap` y detecta todas las alertas. |
| **Tabla de paquetes en pestaña Tráfico** | Mostraba `DHCP`, `NBNS`, `LLMNR` y `mDNS` como `"UDP"` y truncaba 16 campos. | Procesa los 33 campos y muestra `DHCP`, `DHCPV6`, `NBNS`, `LLMNR`, `MDNS` e `ICMPV6` con sus detalles. |

---

## 4. Verificación y Pruebas Unitarias

Se amplió la suite de pruebas en `tests/` pasando de **38 a 42 pruebas unitarias**, todas aprobadas al 100% (`Ran 42 tests ... OK`):
* `test_discover_local_network_filters_multicast_and_broadcast_and_detects_gateway` (`tests/test_database.py`): Verifica el descarte de direcciones Multicast/Broadcast y la asignación automática del rol `GATEWAY`.
* `test_detects_dynamic_arp_conflict_and_multiple_ips_without_prior_baseline` (`tests/test_detection.py`): Verifica la detección de ARP Spoofing dinámico y múltiples IPs por MAC sin requerir línea base previa.
* `test_selects_untrusted_attacker_mac_when_attacker_responds_before_trusted_server` (`tests/test_detection.py`): Verifica que cuando el atacante responde primero y el servidor confiable segundo, se registre la MAC del atacante.
* `test_packet_fields_format_dhcp_nbns_and_mdns_protocols_instead_of_generic_udp` (`tests/test_traffic_viewer.py`): Verifica la lectura de los 33 campos y la visualización correcta de protocolos en el visor de tráfico.


# ARPShield — Historial Integral de Cambios, Actualizaciones y Evolución del Proyecto

**Proyecto:** ARPShield — Monitor Local y Sistema de Detección de Suplantaciones (IDS) para Redes LAN  
**Versión Actual:** 2.5.0  
**Fecha de Consolidación:** 16 de noviembre de 2026  
**Equipo de Desarrollo (Capa 8):**
* **Andres Ferney Garcia Ramirez** (C.C. 1005564075) — *Líder Técnico & Desarrollador Principal*
* **Juan David Rico Aldana** (C.C. 1096801885) — *Responsable de Seguridad, Calidad & Documentador*

---

## 1. Resumen Ejecutivo de la Evolución del Proyecto

El desarrollo de **ARPShield** inició como un prototipo básico de consola y escritorio para la observación de cambios en la tabla ARP de Windows y evolucionó hasta convertirse en un **Sistema de Detección de Intrusos (IDS) local multiprotocolo**, con motor heurístico de 13 reglas, visor forense de 33 campos, gestión de línea base de confianza, renderizado vectorial y una suite automatizada de 58 pruebas unitarias.

A lo largo del ciclo de vida del proyecto se superaron tres hitos críticos de ingeniería:
1. **La optimización del hilo de interfaz y buffer de memoria:** Evitando bloqueos de UI (*"No responde"*) causados por ráfagas de paquetes mediante inserciones en lote y acotación a 500 filas.
2. **La resolución de la crisis de conflictos de Git:** Eliminación de marcadores de conflicto textuales (`<<<<<<< HEAD`, `>>>>>>>`) que rompían la sintaxis del proyecto con `SyntaxError`.
3. **La auditoría funcional y corrección del motor de detección:** Corrección de la atribución errónea de la MAC atacante en ataques de carrera, eliminación de contaminación por direcciones Multicast/Broadcast, y activación de detección dinámica para archivos `.pcap` externos.

---

## 2. Línea de Tiempo y Fases del Desarrollo

```
[Semana 1: Prototipo Base]
       │  - Creación de estructura src/arpshield, tests, docs
       │  - SQLite básico (4 tablas iniciales)
       │  - Monitoreo simple de arp -a
       ▼
[Semana 2: Optimización de Rendimiento]
       │  - Diagnóstico de DoS local por QTableWidget O(N^2)
       │  - Límite MAX_PACKET_ROWS = 500 y lotes de 50
       │  - Filtrado de adaptadores físicos por GUID en Windows
       ▼
[Semana 3: Motor Multiprotocolo (PRs #1 a #6)]
       │  - SpoofingDetector con 33 campos analíticos
       │  - Cobertura: ARP, DNS, DHCP, DHCPv6, LLMNR, NBNS, mDNS, NDP
       │  - Migraciones DDL automáticas en SQLite y JSON forense
       │  - Generación de capturas PCAP de prueba en captures/
       ▼
[Semana 4: Crisis de Merge y Estabilización]
       │  - Eliminación de marcadores de conflicto en archivos UI
       │  - Restauración de sintaxis Python limpia (0 SyntaxError)
       │  - Sincronización completa con origin/main
       ▼
[Semana 5: Auditoría Funcional a Fondo y Versión 2.5.0]
       │  - Filtrado Multicast/Broadcast y detección automática del Gateway
       │  - Detección ARP dinámica en PCAPs (sin requerir línea base previa)
       │  - Algoritmo de atribución correcta de attacker_mac en ataques de carrera
       │  - Eliminación de truncamiento en visor de tráfico (33 campos activos)
       │  - Conteo diferenciado de dispositivos del último escaneo vs. línea base
       │  - Identificación del Gateway por Get-NetRoute e interfaces activas (Up)
       │  - Localización de timestamps a la hora de Colombia (COT / UTC-05:00)
       │  - Suite de 58 pruebas unitarias (100% aprobadas)
       ▼
[Consolidación Documental Oficial]
          - docs/documentacion_oficial_arpshield.md (Documento Maestro)
          - docs/Ultimos cambios.md (Bitácora de Auditoría)
          - docs/historial_cambios_y_actualizaciones.md (Este registro)
```

---

## 3. Registro Cronológico Detallado de Cambios por Versión

---

### Versión 1.0.0 — Prototipo Inicial y Arquitectura Base
**Fecha:** 1 al 3 de noviembre de 2026  
**Commits clave:** `6ae77f1`, `4fbabaa`, `fcf768d`

#### Cambios Técnicos Implementados:
* **Estructura del Proyecto:** Creación de los paquetes `src/arpshield/`, `tests/` y `docs/`.
* **Capa de Persistencia (`src/arpshield/database.py`):**
  * Creación del esquema SQLite con las 4 tablas oficiales: `trusted_baseline`, `oui_catalog`, `security_alerts` y `audit_logs`.
  * Creación de índices sobre `trusted_baseline(ip_address)` y `security_alerts(timestamp_utc, attacker_mac)`.
* **Capa de Monitoreo (`src/arpshield/monitor.py`):**
  * Implementación de `discover_local_network()` mediante invocación segura de `arp -a` con `subprocess.run(shell=False)`.
  * Verificación básica de cambios de MAC en `check_for_anomalies()` para alertar `GATEWAY_SPOOFING`.
* **Validación de Entradas (`src/arpshield/config.py`):**
  * Expresiones regulares estrictas `REGEX_IPV4` y `REGEX_MAC`.
  * Configuración de ruta predeterminada en `%LOCALAPPDATA%\ARPShield\arpshield.db`.
* **Interfaz Gráfica Inicial (`src/arpshield/ui/`):**
  * Maquetación base en PySide6 con ventana principal (`main_window.py`) y botones *Escanear* y *Verificar*.
* **Documentación Base:** Redacción de `developer_setup_guidelines.md`, `security_policy_stride_mitigation.md`, `system_architecture_technical_design.md` y `nvd_analisis_vulnerabilidades_arp_shield.md`.

---

### Versión 1.1.0 — Optimización de Rendimiento y Control Anti-Bloqueo
**Fecha:** 4 al 5 de noviembre de 2026  
**Commits clave:** `9ae8995`, `4551bfa` (Merge PR #1)

#### Problema Detectado:
Durante pruebas con tráfico en vivo sobre Wi-Fi, la interfaz gráfica (`PySide6`) dejaba de responder (*"No responde"*) tras recibir más de 1.000 paquetes. La causa fue un costo computacional cuadrático $O(N^2)$ al usar `QHeaderView.ResizeMode.ResizeToContents` en todas las columnas y repintar la tabla por cada línea individual recibida de TShark.

#### Solución Implementada:
* **Acotación de Memoria:** Reducción del límite de almacenamiento visible de 3.000 a 500 filas (`MAX_PACKET_ROWS = 500`).
* **Inserción por Lotes:** Creación de un temporizador de volcado (`_flush_timer`) a 200 ms con lotes de 50 filas (`PACKET_BATCH_SIZE = 50`), reduciendo los relayouts de Qt de cientos por segundo a solo cinco por segundo.
* **Optimización de Columnas:** Configuración de columnas interactivas y fijas, eliminando el re-escalado automático cuadrático.
* **Mapeo Físico en Windows:** Implementación de `windows_physical_adapters()` usando PowerShell (`Get-NetAdapter -Physical`) para mapear adaptadores reales por GUID y descartar interfaces virtuales no soportadas (`extcap`: `ciscodump`, `sshdump`, `etwdump`).

---

### Versión 2.0.0 — Motor Heurístico Multiprotocolo y Soporte PCAP
**Fecha:** 9 al 10 de noviembre de 2026  
**Commits clave:** `a010d2e`, `1fc77c6` (PR #3), `91a0c0c`, `898312d` (PR #4), `9271700`, `acb8837`, `c550e66` (PR #5), `c0e8be4`, `928c46b` (PR #6)

#### Cambios Técnicos Implementados:
* **Nuevo Motor de Detección (`src/arpshield/detection.py`):**
  * Creación de la clase `SpoofingDetector` desacoplada de la interfaz gráfica.
  * Definición de **33 campos analíticos** (`CAPTURE_FIELDS`) solicitados a TShark (`-T fields -e ...`).
  * Expansión del espectro de detección a 13 tipos de alertas (`DNS_SPOOFING`, `DHCP_SPOOFING`, `DHCPV6_SPOOFING`, `LLMNR_SPOOFING`, `NBNS_SPOOFING`, `MDNS_SPOOFING`, `NDP_SPOOFING`, `IP_SPOOFING`, `MAC_SPOOFING`).
* **Migraciones Automáticas de Base de Datos (`src/arpshield/database.py`):**
  * Función `_migrate_alert_types()`: recrea transaccionalmente la tabla `security_alerts` para admitir las nuevas categorías en la cláusula `CHECK`.
  * Función `_migrate_device_types()`: amplía `trusted_baseline` con los roles `GATEWAY`, `DNS_SERVER`, `DHCP_SERVER`, `KNOWN_HOST`, `OTHER`.
  * Función `_migrate_alert_details()`: añade la columna `evidence_details TEXT NOT NULL DEFAULT '{}'`.
  * Deduplicación de alertas: consulta `NOT EXISTS` en `add_alert()` para descartar alertas idénticas dentro de una ventana de 30 segundos.
* **Gestión de Dispositivos Confiables (`main_window.py`):**
  * Pestaña *Ajustes*: buscador dinámico en tiempo real (`trusted_device_matches`) que filtra por alias, rol, IP o MAC.
  * Posibilidad de bautizar equipos con un nombre o alias legible (`hostname`) persistido en base de datos.
* **Evidencia Forense en Dashboard (`dashboard.py`):**
  * Al hacer clic sobre cualquier alerta en la tabla del Dashboard, se abre un diálogo modal con la evidencia completa decodificada en formato JSON (`alert_details_text`).
* **Laboratorio PCAP (`captures/` y `prueba/generator.py`):**
  * Creación del script Scapy para generar capturas de prueba (`arp_spoof.pcap`, `dns_spoof.pcap`, `dhcp_spoof.pcap`, `ip_spoof.pcap`, `baseline.pcap`).
  * Implementación del botón *"Abrir PCAP"* en la pestaña Tráfico para reproducir capturas externas con TShark.

---

### Versión 2.1.0 — Resolución de la Crisis de Conflictos de Git
**Fecha:** 10 al 11 de noviembre de 2026  
**Commits clave:** `37d7ebb`, `972f701`, `167693a`, `6511194`, `d4e9b25`, `00d2c39`, `7a2dd92`

#### Diagnóstico del Incidente:
Durante la sincronización de ramas entre `JuanDavidRicoAldana`, `AndresFerney` y `main`, se produjeron merges con conflictos no resueltos que fueron accidentalmente confirmados (*committed*). Esto dejó caracteres textuales de Git (`<<<<<<< HEAD`, `=======`, `>>>>>>> <hash>`) dentro de `dashboard.py`, `main_window.py` y `traffic_viewer.py`.

#### Efecto en el Sistema:
Al intentar iniciar la aplicación o ejecutar la suite de pruebas unitarias, el intérprete de Python fallaba inmediatamente con:
```text
SyntaxError: invalid decimal literal en main_window.py, línea 7
```

#### Acciones Correctivas Aplicadas:
1. Inspección exhaustiva mediante `git grep -n -E "^(<<<<<<<|>>>>>>>)"` para identificar todos los archivos contaminados.
2. Extracción y restauración limpia de los módulos de interfaz gráfica desde `origin/main` en codificación UTF-8 estricta sin marcas de orden de bytes (BOM) ni caracteres nulos.
3. Preservación intacta del documento de arquitectura integral `docs/documentacion_integral_arpshield.md`.
4. Ejecución y aprobación de las 38 pruebas unitarias existentes (`38 passed, 0 errors, 0 failures`).

---

### Versión 2.5.0 — Auditoría Funcional, Perfeccionamiento del Motor Heurístico y Suite QA de 58 Tests
**Fecha:** 16 de noviembre de 2026  
**Commits clave:** `e8a2df3`, `6a0a915`, `4e601b0`, `421c463`, `8912a42`, `7632db0`

#### Diagnóstico Funcional Línea por Línea:
A pesar de que las pruebas pasaban, una auditoría funcional profunda reveló 5 bloqueos lógicos en escenarios reales de ataque:
1. **Contaminación de la Línea Base:** Al pulsar *Escanear*, `arp -a` introducía direcciones Multicast (`224.0.0.x`) y Broadcast (`255.255.255.255`) como equipos conocidos (`KNOWN_HOST`). Además, la función `_infer_gateway_from_ipv4()` era código muerto y nunca marcaba al router como `GATEWAY`.
2. **Ceguera ARP en PCAPs:** Toda la lógica de ARP Spoofing dependía de `if arp_src_ip in baseline_by_ip:`. Al abrir archivos PCAP de otras redes, **el detector ignoraba el ataque y reportaba 0 alertas**. Además, la verificación de discrepancia `eth.src != arp.src.hw_mac` estaba anidada dentro de esa misma condición.
3. **Inversión de Culpabilidad en Ataques de Carrera:** En ataques DNS, DHCP, DHCPv6, LLMNR, NBNS, mDNS y NDP, el atacante responde primero y el servidor legítimo responde milisegundos después. El código guardaba la primera respuesta y, al llegar la segunda, acusaba a la MAC del segundo paquete, **señalando erróneamente al router o servidor legítimo como atacante**.
4. **Bloqueo por Cooldown de 30 Segundos:** Re-analizar un mismo archivo PCAP en menos de 30 segundos devolvía 0 alertas porque el estado efímero no se reiniciaba.
5. **Truncamiento en Visor de Tráfico:** `packet_fields_to_row()` recortaba los campos a 17 (`FIELD_COUNT = 17`) y no reconocía `DHCP`, `NBNS`, `LLMNR` ni `MDNS`, mostrándolos a todos como `"UDP"` genérico.

#### Mejoras de Ingeniería Aplicadas:
* **En `src/arpshield/monitor.py`:**
  * Implementación de los validadores `_is_usable_host_ip()` e `_is_usable_host_mac()` para filtrar Multicast, Broadcast, Loopback y MACs virtuales.
  * Inferencia de la subred activa de Windows consultando únicamente interfaces con estado `Up` y obteniendo la ruta por defecto real mediante `Get-NetRoute -DestinationPrefix '0.0.0.0/0'`, asignando automáticamente el rol **`GATEWAY`** y el alias `"gateway"` al router principal.
  * Detección activa de **`MULTIPLE_IPS_PER_MAC`** en `check_for_anomalies()` cuando una misma MAC reclama más de una IP en la tabla ARP.
  * Manejo del conteo de dispositivos de la sesión (`set_session_device_count`), resolviendo la duplicación visual de métricas.
* **En `src/arpshield/detection.py`:**
  * Desacoplamiento de la verificación `arp_src_mac != eth_src` para evaluar tramas ARP de cualquier IP (esté o no en la línea base).
  * Implementación de `_arp_neighbors`: tabla de seguimiento dinámico de vecinos en sesión que detecta cambios maliciosos de MAC en cualquier captura en vivo o archivo PCAP.
  * Implementación de **`ARP_BURST_UNSOLICITED`** mediante ventana deslizante (`ARP_BURST_WINDOW_SECONDS = 10.0` y umbral de 10 paquetes) y detección de respuestas gratuitas `is-at` no solicitadas.
  * Implementación del algoritmo `_select_attacker_mac(previous_mac, current_mac, trusted_macs)`: garantiza que la alerta apunte siempre a la MAC no confiable (el atacante) y no al servidor legítimo.
  * Creación del método `reset()` para limpiar la memoria temporal del detector al abrir cada archivo PCAP.
* **En `src/arpshield/ui/traffic_viewer.py`:**
  * Ajuste de `FIELD_COUNT = len(CAPTURE_FIELDS)` (33 campos completos).
  * Soporte visual para los protocolos `DHCP`, `DHCPV6`, `LLMNR`, `NBNS`, `MDNS`, `ICMPV6`.
  * Enriquecimiento de la columna *"Información"* con detalles de transacciones DHCP, ofertas, registros AAAA y mensajes NDP.
  * Invocación automática de `reset_detector()` al abrir archivos PCAP.
* **En `src/arpshield/ui/dashboard.py` y `main_window.py`:**
  * La tarjeta métrica 1 ahora se denomina **"DISPOSITIVOS DEL ÚLTIMO ESCANEO"** y muestra `snapshot["device_count"]` (los dispositivos activos en ese momento), mientras que la tarjeta 4 muestra **"ENTRADAS DE CONFIANZA"** con el total histórico de pares verificados (`baseline_count`).
  * Implementación de `format_colombia_timestamp()`: conversión automática de los timestamps UTC a la **hora de Colombia (`UTC-05:00 / COT`)** tanto en la tabla de alertas como en el diálogo modal de evidencia forense.
  * Preservación del filtro de búsqueda de texto al refrescar el Dashboard.
* **Suite de Pruebas Unitarias Ampliada a 58 Tests:**
  * Incorporación de pruebas para: filtrado de interfaces inactivas, detección de gateway por `Get-NetRoute`, conteo de dispositivos por sesión, conversión horaria a hora de Colombia y validación de respuestas gratuitas no solicitadas.
  * **Resultado:** `Ran 58 tests in 1.932s — OK` (100% aprobadas).

---

## 4. Matriz Comparativa: Evolución de Capacidades por Versión

| Capacidad / Función | v1.0.0 (Prototipo) | v2.0.0 (Multiprotocolo) | v2.5.0 (Actual Consolidada) |
| :--- | :---: | :---: | :---: |
| **Monitoreo ARP local (`arp -a`)** | Básico | Básico | **Filtrado anti-multicast y auto-gateway** |
| **Detección ARP Spoofing en vivo** | Solo contra línea base | Solo contra línea base | **Con y sin línea base (dinámico)** |
| **Detección ARP en archivos PCAP** | No | No (0 alertas) | **Totalmente funcional** |
| **Detección Inconsistencia Ethernet vs. ARP** | No | Solo si IP estaba en línea base | **Evaluación sobre toda trama ARP** |
| **Ráfagas ARP (`ARP_BURST_UNSOLICITED`)** | No | Solo reservado en SQL | **Implementado (>=10 en 10s)** |
| **Múltiples IPs por MAC (`MULTIPLE_IPS_PER_MAC`)** | No | Solo reservado en SQL | **Implementado en ARP y escaneo** |
| **Detección DNS Spoofing (Carrera)** | No | Culpaba al servidor legítimo | **Atribución correcta al atacante** |
| **Detección Rogue DHCP / DHCPv6** | No | Culpaba al servidor legítimo | **Atribución correcta al atacante** |
| **Detección LLMNR / NBNS / mDNS** | No | Básica | **Resuelto con puertos 5355/5353/137** |
| **Detección Rogue IPv6 Router Advertisements** | No | Básica | **Cotejo estricto de MAC de Gateway** |
| **Re-análisis de PCAPs seguidos** | No | Bloqueado por cooldown 30s | **Reinicio automático (`reset_detector`)** |
| **Campos analíticos procesados** | ~8 campos | 17 campos | **33 campos analíticos completos** |
| **Protocolos visibles en tabla Tráfico** | Solo ARP/DNS/UDP/TCP | DHCP/NBNS/mDNS salían como "UDP"| **DHCP, DHCPv6, NBNS, LLMNR, mDNS, ICMPv6** |
| **Estabilidad de UI ante ráfagas** | Se congelaba (O(N^2)) | Estable (Lotes de 50 / 500 filas)| **Estable (Lotes de 50 / 500 filas)** |
| **Pruebas Unitarias Automatizadas** | 0 pruebas | 38 pruebas | **58 pruebas (100% aprobadas)** |
| **Alineación Horaria del Dashboard** | UTC crudo | UTC crudo | **Hora de Colombia (COT / UTC-05:00)** |
| **Conteo de Dispositivos en Dashboard**| Sin métrica | Repetía la línea base total | **Separado: Activos vs. Línea base** |

---

## 5. Registro de Incidentes Resueltos (Bug Tracker Histórico)

### Incidente 1: Congelamiento de la Interfaz Gráfica ante Ráfagas de Red
* **Severidad:** ALTA (Denegación de servicio local).
* **Causa Raíz:** Llamadas síncronas a `resizeColumnsToContents()` por cada paquete insertado en `QTableWidget` y ausencia de límite de filas en memoria.
* **Solución:** Implementación de `MAX_PACKET_ROWS = 500`, lote de inserción de 50 elementos y modo de redimensión interactivo.
* **Estado:** **RESUELTO**.

### Incidente 2: Sintaxis Corrupta por Conflictos de Git sin Resolver
* **Severidad:** CRÍTICA (Bloqueo total de compilación y ejecución).
* **Causa Raíz:** Confirmación accidental de marcadores de conflicto textuales (`<<<<<<< HEAD`, `>>>>>>>`) en `main_window.py`, `dashboard.py` y `traffic_viewer.py`.
* **Solución:** Limpieza y restauración de código limpio desde `origin/main` en UTF-8 estricto sin BOM.
* **Estado:** **RESUELTO**.

### Incidente 3: Contaminación de la Línea Base con Direcciones de Difusión
* **Severidad:** MEDIA (Pérdida de precisión en la línea base de confianza).
* **Causa Raíz:** El parser de `arp -a` aceptaba cualquier cadena con formato IP/MAC, almacenando direcciones Multicast (`224.0.0.22`, `239.255.255.250`) y Broadcast (`255.255.255.255`) como equipos de confianza.
* **Solución:** Adición de los filtros `_is_usable_host_ip()` y `_is_usable_host_mac()` en `ThreatMonitor`.
* **Estado:** **RESUELTO**.

### Incidente 4: Falsa Acusación al Servidor Legítimo en Ataques de Envenenamiento DNS/DHCP
* **Severidad:** ALTA (Falsos positivos críticos y acusación errónea).
* **Causa Raíz:** En una carrera de red el atacante responde primero; el detector guardaba la respuesta fraudulenta y, al recibir la respuesta legítima posterior, extraía la MAC del segundo paquete (`eth_src`) como culpable.
* **Solución:** Creación del algoritmo `_select_attacker_mac()` que verifica la pertenencia a `trusted_macs` antes de asignar la responsabilidad del ataque.
* **Estado:** **RESUELTO**.

### Incidente 5: Fallo de Detección al Analizar Archivos PCAP Externos
* **Severidad:** ALTA (Inoperancia del analizador forense fuera de la LAN local).
* **Causa Raíz:** Reglas de ARP Spoofing condicionadas a que la IP existiera previamente en `trusted_baseline`. En un PCAP grabado en otro entorno, las IPs no estaban en la base de datos local y eran ignoradas.
* **Solución:** Seguimiento dinámico de vecinos con `_arp_neighbors` y evaluación incondicional de discrepancia de cabeceras Ethernet vs. ARP.
* **Estado:** **RESUELTO**.

---

## 6. Estado Actual del Repositorio y Próximos Pasos (Roadmap)

### Estado Actual:
* **Rama Activa:** `main` (al día con el commit `7632db0`).
* **Código Fuente:** Limpio, tipado, modular y sin errores de sintaxis.
* **Aseguramiento de Calidad:** 58 pruebas unitarias pasando al 100% en menos de 2 segundos.
* **Documentación Oficial:**
  * [`docs/documentacion_oficial_arpshield.md`](./documentacion_oficial_arpshield.md) — Documento oficial maestro con los 10 puntos normativos y operativos.
  * [`docs/Ultimos cambios.md`](./Ultimos%20cambios.md) — Bitácora técnica de la última auditoría.
  * [`docs/historial_cambios_y_actualizaciones.md`](./historial_cambios_y_actualizaciones.md) — Este documento de trazabilidad histórica.

### Próximos Pasos Planificados (Versión 3.0):
1. **Mitigación Activa con Reversión Automática:** Conectar la ejecución segura de `netsh interface ipv4 add neighbors` con confirmación UAC al detectar un ataque sobre el Gateway, garantizando la eliminación de la entrada estática (`delete neighbors`) al cerrar la aplicación.
2. **Exportación de Reportes Ejecutivos:** Generación automática de reportes forenses en PDF y CSV para auditorías de cumplimiento normativo ISO/IEC 27033.
3. **Módulo de Detección DoH/DoT:** Incorporación de reglas heurísticas de tráfico anómalo sobre el puerto 853 y endpoints conocidos de DNS cifrado.

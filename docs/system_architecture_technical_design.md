# ARPShield - Documento de Arquitectura y Diseño Técnico

## 1. Visión General del Sistema
**ARPShield** es un monitor local de red que busca señales de suplantación en LAN: ARP, direcciones IP/MAC, DNS, DHCP/DHCPv6, LLMNR, NBNS, mDNS y NDP/IPv6. Es detección pasiva y basada en paquetes visibles y referencias confiables; no garantiza detectar cualquier ataque ni aplica mitigación automática.

---

## 2. Componentes de la Infraestructura

| # | Componente | Descripción y Función | Tecnología | Dependencias Directas |
|---|---|---|---|---|
| 1 | **Captura de Tráfico** | TShark captura los protocolos seleccionados desde una interfaz o analiza archivos PCAP/PCAPNG. | TShark, Wireshark, Npcap, `QProcess` | Interfaz y permisos de captura |
| 2 | **Analizador de Amenazas** | Correlaciona campos de paquetes con la línea base y respuestas contradictorias de DNS/nombres locales y DHCP. | Python, `SpoofingDetector` | Componente 1 y línea base |
| 3 | **Base de Datos y Línea Base** | Almacena pares IP-MAC, roles confiables, alertas y bitácora de auditoría; migra las restricciones de esquema al iniciar. | SQLite | Ninguna |
| 4 | **Panel de Monitoreo (GUI)** | Visualiza alertas y permite clasificar dispositivos confiables; no aplica mitigaciones de red. | Python, PySide6 | Componentes 2 y 3 |
| 5 | **Dashboard y Analytics** | Reúne métricas totales, distribución por severidad, tráfico sospechoso, inventario activo y tendencia de eventos. | PySide6, pandas, matplotlib, SQLite | Componentes 3 y 4 |
| 6 | **Visualizador de Tráfico y PCAP** | Muestra como máximo 500 paquetes y agrupa inserciones de la tabla para limitar el uso de recursos. | PySide6, TShark | Componentes 1 y 2 |
| 7 | **Canal de captura** | Lee la salida de TShark de forma asíncrona; el análisis y la persistencia se ejecutan en el proceso local de la aplicación. | `QProcess`, Python | Componentes 1 y 2 |
| 8 | **Análisis de archivos PCAP** | Inspección de archivos PCAP/PCAPNG mediante TShark y el mismo motor de correlación. | TShark | Componentes 1 y 2 |
| 9 | **Mitigación de tabla ARP (planificada)** | El proyecto contempla entradas estáticas, pero el código actual no ejecuta `netsh` ni bloquea tráfico. | Diseño futuro | No implementado |
| 10 | **Gestión de Evidencia y Reportes** | Guarda evidencias, screenshots, paquetes relevantes y reportes para revisión forense y cumplimiento. | SQLite, JSON, archivos PCAP | Componentes 3, 5, 8 |

---

## 3. Captura y Rendimiento

```
+-----------------------------------------------------------------------+
|                            PySide6 GUI                                |
|                  Dashboard, tráfico y ajustes                         |
+-----------------------------------------------------------------------+
                     | QProcess / salida por lotes
                     v
                +-----------+
                | TShark    |
                +-----------+
                     |
                     v
            SpoofingDetector -> SQLite
```

TShark se gestiona de forma asíncrona con `QProcess`. La interfaz conserva hasta 500 paquetes visibles y la inserción se agrupa en lotes. La correlación y persistencia de alertas son locales; un flujo muy alto de paquetes puede afectar la respuesta de la interfaz.

---

## 4. Flujo Principal de Datos

1. **Inicialización y Verificación:**
   - La aplicación inicia en hilo principal con privilegios estándar de usuario.
   - Valida la integridad de la base de datos local SQLite mediante hash SHA-256.
2. **Construcción de Línea Base:**
   - El escaneo agrega equipos observados a la línea base. El usuario verifica de forma independiente los datos y clasifica gateway, DNS y DHCP autorizados desde Ajustes; el escaneo no debe considerarse prueba de legitimidad.
3. **Inspección en Tiempo Real:**
   - TShark/Npcap captura ARP, IPv4/IPv6, DNS, DHCP/DHCPv6, LLMNR, NBNS, mDNS e ICMPv6/NDP en la interfaz seleccionada.
   - El motor compara los campos observados con la tabla de confianza y busca respuestas conflictivas en la misma captura.
4. **Detección y Alerta:**
   - Ante discrepancias IP/MAC, respuestas de servidores fuera de la lista confiable, respuestas concurrentes o anuncios IPv6 no clasificados, el sistema registra señales en SQLite con los campos de TShark usados para el análisis. Las reglas de allowlist y correlación se presentan como indicios para revisión, no como prueba de ataque; los cambios legítimos de NIC, servidores redundantes, DNS round-robin/split-horizon y routers IPv6 múltiples pueden producir discrepancias.
5. **Visualización en Dashboard:**
   - El dashboard consulta métricas agregadas y alertas recientes desde SQLite. Al hacer clic en una fila se muestran los metadatos de la alerta y los campos capturados del paquete, sin payload de aplicación.
6. **Análisis Forense y Tráfico:**
   - El usuario puede abrir una vista de paquetes con filtros de protocolo, IP o MAC utilizando TShark/Wireshark.
   - Se habilitan capturas de archivo PCAP para inspección offline con PyShark y revisión de flujo real del incidente.
7. **Mitigación:**
   - La mitigación automática no está implementada. El operador debe responder usando los controles de red y procedimientos de su organización.

---

## 5. Dashboard, Visualización del Tráfico y Forense

### 5.1 Dashboard Central de Seguridad
El dashboard será el componente principal para la observabilidad de toda la plataforma. Debe incluir:
- Estado general de la red (subred activa, dispositivos detectados, puertos relevantes y gateways).
- Totales por severidad: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- Lista de alertas con origen, dirección IP afectada, MAC sospechosa, evidencia y timestamp.
- Historial de eventos en línea y resumen de anomalías detectadas por ventana temporal.
- Inventario de dispositivos autorizados y su relación con `trusted_baseline`.
- Mapa de actividad por dirección IP y fabricante OUI.
- Botones de acción: iniciar captura, detener análisis, confirmar incidente, mitigar y exportar evidencia.

### 5.2 Vista de Tráfico y Captura Forense
La vista actual usa TShark/Wireshark para captura local y análisis de archivos `.pcap`/`.pcapng`:
- El filtro predeterminado incluye ARP, DNS, DHCP/DHCPv6, LLMNR, NBNS, mDNS e ICMPv6.
- Muestra campos clave: direcciones MAC/IP, protocolo, hora, tipo ARP e información DNS.
- Limita la tabla visible a 500 paquetes; la tabla no representa todo el tráfico de una red conmutada.

### 5.3 Flujo de Datos del Dashboard
```text
Captura (TShark/Npcap)
        |
        v
Correlación / detección de amenazas
        |
        v
Persistencia en SQLite / evidencias
        |
        +--> Dashboard de métricas y alertas
        +--> Visualizador de tráfico (TShark/PyShark)
        +--> Reportes forenses y auditoría
```

El selector de interfaces conserva los destinos locales de captura enumerados por `tshark -D`; en Windows los enriquece con IP y estado de `Get-NetAdapter`, sin filtrar por hardware físico, estado `Up` o asociación de GUID. Los destinos no asociados se muestran con datos no disponibles y los dispositivos desconectados no se pueden capturar hasta activarlos. El indicador de dispositivos muestra el número de entradas IP/MAC observadas en la caché ARP, no el tamaño acumulado de `trusted_baseline`. En Windows el escaneo incluye interfaces locales activas con IPv4, físicas y virtuales (como Host-Only); en otros sistemas usa la interfaz de la ruta predeterminada. La línea base conserva entradas históricas y roles confiables; no se elimina al iniciar. Los contadores de alertas/anomalías son de sesión: las alertas anteriores permanecen en SQLite, pero no se incluyen en las métricas de la nueva ejecución. El escaneo consulta la caché ARP del sistema y no garantiza descubrir dispositivos que no hayan generado una asociación ARP visible.

### 5.4 Cobertura y cautelas de las reglas
- `GATEWAY_SPOOFING`: discrepancia con una IP clasificada explícitamente como gateway; severidad alta.
- `ARP_SPOOFING`, `IP_SPOOFING` y `MAC_SPOOFING`: detectan conflictos con pares IP/MAC de la línea base y señales directas en frío (respuesta ARP sin solicitud observada, ARP gratuito o discrepancia Ethernet/ARP). Las señales directas son de revisión porque la captura puede empezar a mitad de una conversación.
- `DNS_SPOOFING`: detecta respuesta DNS sin una consulta coincidente observada, resolver fuera de la lista DNS cuando esta se configuró y respuestas distintas para la misma consulta/transacción; severidad media. La ventana de correlación es corta para evitar confundir reutilización de ID con conflicto.
- `DHCP_SPOOFING` y `DHCPV6_SPOOFING`: alerta sobre Offer/ACK o Advertise/Reply si no hay una allowlist configurada o si el servidor no está clasificado, además de detectar servidores competidores. Clasifica los servidores autorizados como `DHCP_SERVER`; varios servidores pueden ser legítimos.
- `LLMNR_SPOOFING`, `NBNS_SPOOFING` y `MDNS_SPOOFING`: marcan respuestas de una MAC que no está en la línea base y respuestas contradictorias. En una red sin línea base es una señal de revisión, no confirmación por sí sola.
- `NDP_SPOOFING`: marca Router Advertisements desde IPv6 link-local (`fe80::/10`) cuya MAC no está clasificada como gateway; Neighbor Advertisements contradictorios también se correlacionan.
- `MULTIPLE_IPS_PER_MAC` detecta una MAC que reclama varias IP; `ARP_BURST_UNSOLICITED` cuenta respuestas por par IP/MAC dentro de una ventana temporal. Ambas reglas son heurísticas.
- La detección requiere que TShark exponga los campos y que la interfaz reciba los paquetes. Los tipos y campos ausentes, el filtro, la visibilidad de switch/Wi-Fi y una línea base incompleta reducen la cobertura.

---

## 6. Exclusiones Explícitas del Alcance
- No descifrará tráfico cifrado (HTTPS / TLS) ni inspeccionará cargas útiles (payloads) de la capa de aplicación.
- No sustituirá las funciones de hardware de switches gestionados (como Dynamic ARP Inspection o IEEE 802.1X).
- No modificará infraestructura de red institucional; la contención se limita estrictamente a la máquina cliente local.
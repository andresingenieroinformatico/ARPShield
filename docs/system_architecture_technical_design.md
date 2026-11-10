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
   - Ante discrepancias IP/MAC, servidores no incluidos en la lista confiable, respuestas contradictorias o anuncios IPv6 sospechosos, el sistema registra alertas en SQLite. El resultado depende de la visibilidad de la interfaz y de la calidad de la línea base.
5. **Visualización en Dashboard:**
   - Los datos recopilados se exponen en un dashboard con métricas de red, severidad, inventario activo, tabla ARP, tráfico sospechoso y timeline de alertas.
   - El dashboard se actualiza desde la cola de eventos y la base de datos para ofrecer una vista continua del estado de seguridad.
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

---

## 6. Exclusiones Explícitas del Alcance
- No descifrará tráfico cifrado (HTTPS / TLS) ni inspeccionará cargas útiles (payloads) de la capa de aplicación.
- No sustituirá las funciones de hardware de switches gestionados (como Dynamic ARP Inspection o IEEE 802.1X).
- No modificará infraestructura de red institucional; la contención se limita estrictamente a la máquina cliente local.
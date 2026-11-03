# ARPShield - Documento de Arquitectura y Diseño Técnico

## 1. Visión General del Sistema
**ARPShield** es un sistema de detección y prevención de intrusiones (IDS/IPS) enfocado en la capa de enlace (Capa 2) y resolución de nombres (Capa 3). Su objetivo es proteger equipos cliente en redes locales compartidas (universidades o PyMEs) frente a ataques de envenenamiento ARP y falsificación DNS (Man-in-the-Middle).

---

## 2. Componentes de la Infraestructura

| # | Componente | Descripción y Función | Tecnología | Dependencias Directas |
|---|---|---|---|---|
| 1 | **Captura de Tráfico** | Captura paquetes ARP y consultas DNS en tiempo real desde las interfaces del sistema. | Python, Scapy (v2.8.0), Npcap | Ninguna |
| 2 | **Analizador de Amenazas (Motor de Correlación)** | Examina tramas ARP y respuestas DNS cotejándolas con la línea base para detectar discrepancias y anomalias. | Python, Scapy | Componente 1 (Captura) |
| 3 | **Base de Datos y Línea Base** | Almacena pares IP-MAC de confianza, inventario OUI, registro forense de alertas y bitácora de auditoría. | SQLite / SQLCipher (v1.2.0) | Ninguna |
| 4 | **Panel de Monitoreo (GUI)** | Interfaz de usuario para la visualización de alertas explicables, estado de la red y control de mitigación. | Python, PySide6 (v6.6.0) | Componente 2 (Analizador) |
| 5 | **Dashboard y Analytics** | Reúne métricas totales, distribución por severidad, tráfico sospechoso, inventario activo y tendencia de eventos. | PySide6, pandas, matplotlib, SQLite | Componentes 3 y 4 |
| 6 | **Visualizador de Tráfico y PCAP** | Muestra el tráfico capturado mediante TShark/Wireshark, con filtros por IP, MAC, protocolo y ventanas temporales. | PyShark, TShark, Wireshark | Componentes 1 y 5 |
| 7 | **Bus de eventos / Cola de trabajo** | Coordinación entre captura, correlación, persistencia y render del dashboard, evitando bloqueos de interfaz. | Python queue / threads / signals | Componentes 1, 2, 4, 5 |
| 8 | **Análisis de Archivos PCAP** | Inspección forense fuera de línea de capturas de tráfico previamente guardadas. | Python, PyShark (v0.6.0), TShark | Componente 2 (Analizador) |
| 9 | **Protección de Tabla ARP** | Invocación de utilidades del SO para fijar/restaurar entradas ARP estáticas en la puerta de enlace. | Python, `subprocess`, `netsh` (Windows) | Componente 3 (Base de datos) |
| 10 | **Gestión de Evidencia y Reportes** | Guarda evidencias, screenshots, paquetes relevantes y reportes para revisión forense y cumplimiento. | SQLite, JSON, archivos PCAP | Componentes 3, 5, 8 |

---

## 3. Modelo de Concurrencia y Rendimiento

```
+-----------------------------------------------------------------------+
|                            PySide6 GUI                                |
|                        (Hilo Principal / UI)                          |
+-----------------------------------------------------------------------+
                                   ^
                                   | Signals / Slots (PySide6)
                                   v
+-----------------------------------------------------------------------+
|                          Worker Thread                                |
|                        (QThread Secundario)                           |
|  +-----------------------------------------------------------------+  |
|  | Circular Buffer (Capacidad Máxima: 1.000 Paquetes)              |  |
|  +-----------------------------------------------------------------+  |
|  | Motor de Correlación ARP / DNS                                   |  |
|  +-----------------------------------------------------------------+  |
|  | Hilo de Captura en Tiempo Real (Scapy Sniffer)                   |  |
+-----------------------------------------------------------------------+
```

### Principios de Concurrencia:
1. **Aislamiento de la Interfaz de Usuario:** Ninguna operación de red I/O ni interacción con el sistema de archivos debe ejecutarse en el hilo principal de PySide6 para evitar congelamientos de interfaz (OWASP ASVS V5.1.4).
2. **Buffer Circular Mitigador:** La captura de paquetes se encola en un buffer circular en memoria limitado a 1.000 paquetes. Si la velocidad de entrada excede el procesamiento, los paquetes viejos o tramas con longitudes anómalas se descartan para prevenir saturación por denegación de servicio local.
3. **Comunicación Directa en Memoria:** La transmisión de alertas entre el hilo de inspección (`QThread`) y el panel de monitoreo se realiza nativamente mediante señales y ranuras (`Signals` / `Slots`) de PySide6.

---

## 4. Flujo Principal de Datos

1. **Inicialización y Verificación:**
   - La aplicación inicia en hilo principal con privilegios estándar de usuario.
   - Valida la integridad de la base de datos local SQLite mediante hash SHA-256.
2. **Construcción de Línea Base:**
   - Se escanea la subred local para identificar y registrar la MAC e IP legítimas del router (gateway), servidores DNS y dispositivos conocidos.
3. **Inspección en Tiempo Real:**
   - Scapy/Npcap captura tramas ARP (`who-has`, `is-at`) y consultas/respuestas DNS.
   - El Motor de Correlación compara cada trama recibida contra la tabla de confianza (`trusted_baseline`).
4. **Detección y Alerta:**
   - Ante cambios intempestivos de MAC para la IP del router, presencia de múltiples IPs asociadas a una misma MAC o ráfagas ARP no solicitadas, el sistema registra el incidente en SQLite y emite una alerta gráfica explicable.
5. **Visualización en Dashboard:**
   - Los datos recopilados se exponen en un dashboard con métricas de red, severidad, inventario activo, tabla ARP, tráfico sospechoso y timeline de alertas.
   - El dashboard se actualiza desde la cola de eventos y la base de datos para ofrecer una vista continua del estado de seguridad.
6. **Análisis Forense y Tráfico:**
   - El usuario puede abrir una vista de paquetes con filtros de protocolo, IP o MAC utilizando TShark/Wireshark.
   - Se habilitan capturas de archivo PCAP para inspección offline con PyShark y revisión de flujo real del incidente.
7. **Blindaje Local (Mitigación IPS):**
   - El usuario decide aplicar el blindaje estático.
   - Se invoca un diálogo UAC para solicitar permisos elevados puntualmente y ejecutar `netsh interface ipv4 add neighbors` mediante el módulo `subprocess`.
8. **Reversión:**
   - Al cerrar la sesión o desconectarse de la red, la entrada de la tabla ARP se restituye al estado dinámico.

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
Se requiere un módulo dedicado para exposición del tráfico local mediante TShark/Wireshark:
- Visualización de paquetes en tiempo real o desde archivos `.pcap`.
- Filtros por `arp`, `dns`, `ip.src`, `ip.dst`, `eth.addr` y tiempo de captura.
- Muestra de campos clave: dirección MAC origen, destino, tipo de trama, protocolo y duración.
- Panel lateral con detalles del paquete seleccionado y marco Ethernet/ARP/DNS asociado.
- Integración con el motor de correlación para marcar automáticamente paquetes relevantes como evidencia de un ataque.

### 5.3 Flujo de Datos del Dashboard
```text
Captura (Scapy/Npcap)
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
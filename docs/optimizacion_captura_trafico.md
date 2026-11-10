# Optimización de Rendimiento y Control Anti-Bloqueo en Captura de Tráfico

**Fecha:** 4 de noviembre de 2026  
**Módulo intervenido:** [`src/arpshield/ui/traffic_viewer.py`](../src/arpshield/ui/traffic_viewer.py)  
**Control normativo asociado:** `OWASP ASVS V5.1.4` (Prevención de Denegación de Servicio local por agotamiento de memoria/CPU) · **Modelo STRIDE #1 (DoS)**.

---

## 1. Diagnóstico del Problema

Durante las pruebas en vivo de captura de tráfico con `TShark` sobre la interfaz Wi-Fi, la ventana principal de **ARPShield** procesaba correctamente los primeros paquetes, pero al acumularse un volumen elevado de tráfico (más de 1.000 tramas) el hilo principal de la interfaz gráfica (`PySide6`) dejaba de responder (*"No responde"*) y terminaba cerrándose abruptamente.

Se identificaron cuatro causas raíz en [`TrafficViewerPanel`](../src/arpshield/ui/traffic_viewer.py):

1. **Recálculo cuadrático de columnas (`ResizeToContents`):** Las columnas `Hora`, `N.º` y `Protocolo` utilizaban `QHeaderView.ResizeMode.ResizeToContents`. En Qt, este modo obliga al hilo de interfaz a medir el ancho en píxeles de **todas las filas acumuladas** cada vez que se inserta o elimina una fila, degradando el rendimiento a `O(N^2)`.
2. **Repintado y desplazamiento (`scrollToBottom`) por cada paquete individual:** El método `_read_output()` invocaba `_append_packet()` y `scrollToBottom()` por cada línea individual recibida de `TShark`, provocando decenas de relayouts por segundo durante ráfagas ARP/DNS.
3. **Tope de filas superior al límite normativo (`MAX_PACKET_ROWS = 3000`):** Se mantenían hasta `24.000` instancias de `QTableWidgetItem` en memoria, superando el límite de `1.000` paquetes definido en la arquitectura (`OWASP ASVS V5.1.4`).
4. **Ausencia de filtro BPF de captura (`-f`) en vivo:** `TShark` se ejecutaba únicamente con filtro de visualización (`-Y "arp or dns"`), obligando a `dumpcap` a capturar y almacenar temporalmente todo el tráfico de la tarjeta de red (HTTPS, video, descargas) antes de filtrarlo.

---

## 2. Solución Implementada

Se aplicaron cuatro mejoras de ingeniería en [`src/arpshield/ui/traffic_viewer.py`](../src/arpshield/ui/traffic_viewer.py):

| # | Mejora | Implementación en `traffic_viewer.py` | Beneficio Técnico |
|---|---|---|---|
| **1** | **Buffer circular en memoria (`collections.deque`)** | `MAX_PACKET_ROWS = 1000` y `self._pending_rows = deque(maxlen=MAX_PACKET_ROWS)`. | Cumple estrictamente con `OWASP ASVS V5.1.4`. Si ocurre una inundación ARP, el buffer circular descarta los paquetes antiguos en tiempo constante `O(1)` sin saturar la RAM. |
| **2** | **Renderizado por lotes temporizado (`QTimer`)** | `UI_FLUSH_INTERVAL_MS = 100` y método `_flush_pending_packets()` envuelto en `setUpdatesEnabled(False)` / `setUpdatesEnabled(True)`. | Desacopla la lectura del proceso `TShark` del repintado de la tabla Qt, actualizando la interfaz como máximo 10 veces por segundo y ejecutando un único `scrollToBottom()` por lote. |
| **3** | **Columnas con dimensionamiento `Interactive`** | Sustitución de `ResizeToContents` en las columnas `0..6` por `QHeaderView.ResizeMode.Interactive` con anchos iniciales fijos. | Elimina el recálculo global de ancho de texto por paquete, manteniendo la inserción de filas en tiempo constante `O(1)`. |
| **4** | **Filtro BPF en controlador Npcap (`-f`)** | Método `_live_capture_filter()` que traduce `arp or dns`, `arp` y `dns` al filtro BPF `-f "arp or port 53"`. | Descarta el tráfico pesado no relacionado directamente en el kernel/Npcap antes de que llegue a `TShark` y Python. |

---

## 3. Verificación

- Se incorporó la prueba unitaria `test_circular_buffer_limit_matches_asvs_control` en [`tests/test_traffic_viewer.py`](../tests/test_traffic_viewer.py) para garantizar que `MAX_PACKET_ROWS` permanezca fijado en `1000`.
- La interfaz gráfica mantiene fluidez continua tanto en capturas prolongadas en vivo como al cargar archivos `.pcap` / `.pcapng` de gran tamaño.


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

Los detectores comparan anuncios IP/MAC y gateways IPv6 con la línea base; comparan respuestas DNS con DNS marcados como confiables y correlacionan respuestas del mismo intercambio; y revisan DHCP/DHCPv6 y respuestas de nombres locales. Estas reglas usan las direcciones observadas en la captura y la línea base configurada; no dependen de `192.168.56.1`. mDNS y LLMNR se distinguen de DNS por sus puertos UDP para no tratarlos erróneamente como resolvers DNS convencionales. En Windows, el rol `GATEWAY` se asigna según la ruta IPv4 predeterminada real, sin asumir una red `/24` ni una dirección `.1`; una interfaz Host-Only sin ruta predeterminada no se etiquetará por error como gateway. Tras escanear, abre **Ajustes** para clasificar gateway, DNS y DHCP autorizados. La línea base es sensible: el primer escaneo agrega equipos nuevos, pero **no reemplaza automáticamente** las asociaciones existentes. Un primer escaneo durante un ataque podría registrar una MAC falsa; verifica IP/MAC por una fuente independiente antes de confiar en la línea base.

En **Ajustes**, cada dispositivo se muestra con un rol legible, IP y MAC. Puedes asignarle un nombre o alias local (por ejemplo, “Router principal” o “Impresora recepción”) cuando la red no publica un hostname; se conserva en la línea base. Clasifica los servidores DHCP como **Servidor DHCP** y los routers IPv6 como **Gateway / router** para que funcionen como listas de autorización. Al seleccionar una alerta del dashboard se abre su detalle: resumen, severidad, fecha, dispositivo y campos de paquete capturados por TShark (incluyendo número de trama, protocolo, IP/MAC, puertos y campos específicos del protocolo disponibles). No se almacena el payload de aplicación. En arranque en frío, una respuesta ARP sin solicitud observada, un anuncio ARP gratuito, una respuesta DNS sin consulta observada, respuestas LLMNR/NBNS/mDNS de MAC no registrada y ofertas DHCP/DHCPv6 sin servidor autorizado producen señales MEDIUM para revisión. La captura puede empezar a mitad de una conversación y las respuestas mDNS/NBNS legítimas pueden provenir de dispositivos aún no clasificados; estas alertas no confirman por sí solas un ataque.

Esto **no garantiza detectar todo spoofing**. `MULTIPLE_IPS_PER_MAC` y `ARP_BURST_UNSOLICITED` tienen reglas heurísticas; la ráfaga considera respuestas por cada par IP/MAC en una ventana temporal. Una captura en un PC de una red conmutada puede no ver paquetes unicast entre otros equipos; DNS cifrado (DoH/DoT), redes Wi-Fi que requieren modo monitor, ataques fuera de la interfaz, suplantaciones de aplicación/TLS y protocolos que no aparezcan en la captura quedan fuera. El filtro elegido también limita la visibilidad. Usa un puerto espejo/TAP o sensores en los segmentos pertinentes y configura referencias confiables para elevar la cobertura. Las alertas indican señales sospechosas, no una prueba definitiva de intrusión.

El desplegable **Interfaz** conserva las interfaces de captura local que enumera `tshark -D`, incluso si Windows no puede asociarlas a un adaptador o no tienen IP. En Windows muestra el nombre del adaptador, las IP asignadas y su estado cuando puede consultarlos; los adaptadores desconectados se muestran, pero no se pueden capturar hasta activarlos. Para una LAN cableada selecciona Ethernet; para pruebas en una VM, elige el adaptador virtual de la red asignada a Kali (por ejemplo, VirtualBox Host-Only para `192.168.56.0/24`). Si la captura funciona pero no muestra tráfico de otros dispositivos, puede ser una limitación normal de switches o del modo Wi-Fi: configura port mirroring/SPAN o usa un TAP de red. ARPShield no puede observar paquetes que el adaptador no recibe.

## Uso en equipos con recursos limitados

La interfaz limita el historial visible a los últimos 500 paquetes y 100 alertas, actualiza la tabla de paquetes por lotes y consulta estadísticas agregadas para el dashboard. El panel se actualiza cada 15 segundos solo cuando está visible. Estos límites reducen el consumo de memoria y CPU cuando hay historial extenso; no limitan los registros que ya están guardados en SQLite.

En equipos con 4 GB de RAM, se recomienda cerrar aplicaciones pesadas durante la captura y mantener el filtro de tráfico acotado (por defecto, ARP, DNS, DHCP/DHCPv6, LLMNR/NBNS/mDNS e ICMPv6). La captura sigue dependiendo de TShark/Wireshark y del sistema operativo, por lo que el consumo total varía según el tráfico y los programas abiertos.

El conteo **Dispositivos del último escaneo** refleja las entradas IP/MAC observadas en la caché ARP local, no es el total acumulado de la línea base. En Windows incluye las interfaces locales activas con IPv4, físicas o virtuales; en otros sistemas usa la interfaz de la ruta predeterminada. La línea base conserva entradas históricas para no borrar roles ni confianza verificados, por lo que puede ser mucho mayor que el número de equipos conectados actualmente. El botón **Escanear** consulta la caché ARP local: no sondea activamente todos los equipos, así que un dispositivo silencioso o cuya asociación no esté en caché puede no aparecer. Los contadores de alertas y riesgo son de la sesión actual y comienzan en cero al iniciar la aplicación; el historial guardado en SQLite se conserva.

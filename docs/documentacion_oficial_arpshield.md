# ARPShield — Documentación Oficial Integral del Proyecto

**Proyecto:** ARPShield — Monitor Local y Sistema de Detección de Suplantaciones (IDS) para Redes LAN  
**Versión del Sistema:** 2.5.0 (Actualizada con Motor de Detección Multiprotocolo, Visor Forense de 33 Campos, Conversión a Hora de Colombia y Suite QA de 58 Pruebas)  
**Fecha de Consolidación:** 16 de noviembre de 2026  
**Equipo de Desarrollo (Capa 8):**
* **Andres Ferney Garcia Ramirez** (C.C. 1005564075) — *Líder Técnico & Desarrollador Principal*
* **Juan David Rico Aldana** (C.C. 1096801885) — *Responsable de Seguridad, Calidad & Documentador*

**Marcos Normativos y Estándares de Referencia:**
* **Ingeniería de Requisitos:** IEEE Std 830 / ISO/IEC/IEEE 29148
* **Seguridad en Aplicaciones:** OWASP Application Security Verification Standard (ASVS v4.0.3)
* **Desarrollo Seguro:** NIST Secure Software Development Framework (SSDF — SP 800-218)
* **Seguridad de Redes:** ISO/IEC 27033-1 (Cláusula 9.3) e ISO/IEC 27033-3 (Cláusula 7.2)
* **Modelado de Amenazas y Vulnerabilidades:** Microsoft STRIDE, NIST NVD (CVE / CVSS v3.1 & v4.0 / CWE) y CISA KEV

---

## Tabla de Contenidos

1. [Ficha Técnica y Portada del Proyecto](#1-ficha-técnica-y-portada-del-proyecto)
2. [Visión General, Propósito y Alcance del Sistema](#2-visión-general-propósito-y-alcance-del-sistema)
   * 2.1 Contexto y Problemática
   * 2.2 Propósito Operativo
   * 2.3 Exclusiones Explícitas y Límites Operativos
3. [Arquitectura del Sistema y Stack Tecnológico Real](#3-arquitectura-del-sistema-y-stack-tecnológico-real)
   * 3.1 Diagrama de Componentes y Flujo de Datos
   * 3.2 Stack Tecnológico Oficial y Dependencias Reales
   * 3.3 Estructura Modular del Repositorio
4. [Guía de Instalación y Puesta a Punto](#4-guía-de-instalación-y-puesta-a-punto)
   * 4.1 Requisitos de Hardware y Sistema Operativo
   * 4.2 Instalación de Dependencias de Captura (Npcap y TShark)
   * 4.3 Despliegue del Entorno Virtual de Python y Ejecución
5. [Manual de Uso de la Aplicación (Guía Operativa)](#5-manual-de-uso-de-la-aplicación-guía-operativa)
   * 5.1 Barra Superior y Controles Globales (Escanear y Verificar)
   * 5.2 Pestaña 1: Dashboard Central de Seguridad
   * 5.3 Pestaña 2: Visor de Tráfico en Vivo y Análisis Forense PCAP
   * 5.4 Pestaña 3: Ajustes y Clasificación de Dispositivos Confiables
6. [Motor Heurístico de Detección de Spoofing (Protocolos y Reglas)](#6-motor-heurístico-de-detección-de-spoofing-protocolos-y-reglas)
   * 6.1 Detección ARP y Gateway Spoofing
   * 6.2 Detección de Ráfagas e Inundaciones (Burst & Multiple IPs)
   * 6.3 Detección de Suplantación IP y MAC
   * 6.4 Detección de Servidores DHCP/DHCPv6 no Autorizados (Rogue DHCP)
   * 6.5 Detección de Suplantación DNS y Envenenamiento de Caché
   * 6.6 Detección en Resolución de Nombres Locales (LLMNR, NBNS, mDNS)
   * 6.7 Detección de Anuncios IPv6 / NDP no Autorizados (Rogue RA)
   * 6.8 Algoritmo de Atribución Correcta de la MAC Atacante
7. [Modelo de Datos y Persistencia (SQLite)](#7-modelo-de-datos-y-persistencia-sqlite)
   * 7.1 Esquema Relacional DDL (SQL Script)
   * 7.2 Diccionario de Datos Detallado
   * 7.3 Estructura Forense JSON (`evidence_details`)
8. [Marco de Seguridad Normativa y Modelado de Amenazas STRIDE](#8-marco-de-seguridad-normativa-y-modelado-de-amenazas-stride)
   * 8.1 Matriz de Trazabilidad Normativa (ASVS, NIST, ISO)
   * 8.2 Matriz de Modelado de Amenazas STRIDE Aplicada
   * 8.3 Sustento Técnico con Vulnerabilidades Históricas NIST NVD
9. [Plan de Pruebas, Verificación y Aseguramiento de Calidad (QA)](#9-plan-de-pruebas-verificación-y-aseguramiento-de-calidad-qa)
   * 9.1 Suite de Pruebas Unitarias Automatizadas (58 Tests)
   * 9.2 Pruebas de Laboratorio con Archivos PCAP Sintéticos
   * 9.3 Pruebas de Penetración en Vivo con Kali Linux y VirtualBox
10. [Conclusiones, Cautelas Operativas y Roadmap Futuro](#10-conclusiones-cautelas-operativas-y-roadmap-futuro)
    * 10.1 Consideraciones en Redes Conmutadas (Switches y Wi-Fi)
    * 10.2 Plan de Mitigación Activa mediante `netsh`
    * 10.3 Recomendaciones para el Administrador de Red

---

## 1. Ficha Técnica y Portada del Proyecto

| Parámetro | Detalle Oficial |
| :--- | :--- |
| **Nombre del Sistema** | **ARPShield** |
| **Tipo de Sistema** | Monitor Local Pasivo y Sistema de Detección de Suplantaciones (IDS) de Red |
| **Versión Consolidada** | **v2.5.0** (Noviembre 2026) |
| **Lenguaje Base** | Python 3.10+ |
| **Interfaz Gráfica (GUI)** | PySide6 (Qt 6 for Python) con motor de renderizado vectorial nativo |
| **Captura y Decodificación** | Wireshark TShark CLI (`tshark.exe`) asistido por Npcap |
| **Motor de Persistencia** | SQLite 3 (con migraciones automáticas DDL y deduplicación por ventana temporal) |
| **Cobertura de Protocolos** | ARP, IPv4, IPv6, DNS, DHCP, DHCPv6, BOOTP, LLMNR, NBNS, mDNS e ICMPv6 (NDP) |
| **Equipo de Ingeniería (Capa 8)**| Andres Ferney Garcia Ramirez (Líder Técnico) & Juan David Rico Aldana (Seguridad y QA) |

---

## 2. Visión General, Propósito y Alcance del Sistema

### 2.1 Contexto y Problemática
En redes locales Ethernet y Wi-Fi domésticas, corporativas o de laboratorio, los protocolos fundacionales de asignación y resolución de direcciones (como **ARP** — *RFC 826*, **DNS** — *RFC 1035*, **DHCP** — *RFC 2131* e **ICMPv6/NDP** — *RFC 4861*) carecen de mecanismos criptográficos de autenticación por diseño. Cualquier dispositivo conectado a la LAN puede responder a solicitudes que no le pertenecen, enviando respuestas falsificadas para posicionarse en medio de la comunicación (*Man-in-the-Middle* o *MiTM*), desviar el tráfico hacia servidores fraudulentos o causar denegaciones de servicio locales (*DoS*).

### 2.2 Propósito Operativo
**ARPShield** fue diseñado como un agente de seguridad local e IDS pasivo que opera en el equipo del usuario (cliente Windows), monitoreando de forma continua las tablas del sistema operativo y el tráfico observable de la tarjeta de red física. Su objetivo es:
1. Detectar discrepancias entre la línea base autorizada de la red y las tramas que circulan por el medio físico.
2. Identificar atacantes en tiempo real sin requerir hardware corporativo costoso.
3. Registrar evidencia forense estructurada en JSON de cada paquete anómalo para auditoría y respuesta a incidentes.
4. Alertar al usuario mediante una interfaz visual clara, intuitiva y centralizada.

### 2.3 Exclusiones Explícitas y Límites Operativos
Para garantizar la integridad y la viabilidad técnica, el proyecto delimita estrictamente su frontera de operación:
* **No inspecciona cargas útiles (payloads) de capa de aplicación:** No descifra tráfico TLS/HTTPS ni vulnera la privacidad de los usuarios (*OWASP ASVS V7.4.1*).
* **No sustituye controles de switches gestionados:** En redes conmutadas modernas, un switch entrega a cada puerto únicamente su propio tráfico unicast. ARPShield analiza el tráfico broadcast, multicast y aquel que llega a la tarjeta de red monitoreada. Para visibilidad total de la LAN, se requiere un puerto espejo (*SPAN / Port Mirroring*) o un *Network TAP*.
* **No realiza modificaciones intrusivas a la infraestructura de red:** El software se ejecuta de forma pasiva y no emite tráfico malicioso ni altera las configuraciones del router central.

---

## 3. Arquitectura del Sistema y Stack Tecnológico Real

### 3.1 Diagrama de Componentes y Flujo de Datos

```
+----------------------------------------------------------------------------------------------------+
|                                      INTERFAZ GRÁFICA (PySide6)                                     |
|                                                                                                    |
|   +--------------------------+    +-----------------------------+    +-------------------------+   |
|   |     Pestaña Dashboard    |    |      Pestaña de Tráfico     |    |    Pestaña de Ajustes   |   |
|   |  - Métricas agregadas    |    |  - Adaptadores físicos      |    |  - Clasificar roles     |   |
|   |  - Gráfico de tendencia  |    |  - Captura en vivo          |    |  - Asignar alias/nombre |   |
|   |  - Detalle forense JSON  |    |  - Análisis de PCAP / PCAPNG|    |  - Búsqueda en tiempo r.|   |
|   +--------------------------+    +-----------------------------+    +-------------------------+   |
+--------------------------------------------------+-------------------------------------------------+
                                                   |
                        +--------------------------+--------------------------+
                        | Canal Asíncrono QProcess (Salida por lotes / 33 campos)
                        v
     +--------------------------------------+      +----------------------------------------+
     |   Subproceso Externo: TShark.exe     |      |          Tabla ARP de Windows          |
     |   - Captura promiscua con Npcap      |      |   - Comando seguro: arp -a             |
     |   - Lectura de archivos .pcap/.pcapng|      |   - Filtrado automático de Multicast   |
     +--------------------------------------+      +----------------------------------------+
                        |                                              |
                        +----------------------+-----------------------+
                                               v
                        +-----------------------------------------------+
                        |     Orquestador del Monitor (monitor.py)      |
                        |     - Detección de Gateway activa/inferida    |
                        |     - Gestión de línea base de confianza      |
                        +-----------------------------------------------+
                                               |
                                               v
                        +-----------------------------------------------+
                        |   Motor Heurístico (detection.py)             |
                        |   - 13 reglas multiprotocolo activas          |
                        |   - Seguimiento dinámico de vecinos ARP/NDP   |
                        |   - Algoritmo de atribución de atacante       |
                        +-----------------------------------------------+
                                               |
                                               v
                        +-----------------------------------------------+
                        |     Persistencia Local SQLite (database.py)   |
                        |     - trusted_baseline     - security_alerts  |
                        |     - oui_catalog          - audit_logs       |
                        +-----------------------------------------------+
```

### 3.2 Stack Tecnológico Oficial y Dependencias Reales
El proyecto cumple estrictamente con el principio de ligereza y robustez. No requiere frameworks pesados ni dependencias superfluas:

```txt
PySide6>=6.6.0
scapy>=2.8.0
```

* **Python 3.10+:** Entorno de ejecución principal con tipado estático (`typing`, `__future__.annotations`).
* **PySide6 (Qt 6.6+):** Plataforma para la interfaz gráfica, manejo asíncrono de subprocesos (`QProcess`), temporizadores de refresco (`QTimer`) y renderizado vectorial de gráficos mediante `QPainter`.
* **Scapy (>= 2.8.0):** Empleado en scripts de aseguramiento de calidad y utilidades para forjar y decodificar paquetes de prueba.
* **TShark / Wireshark:** Motor binario estándar en la industria para la captura profunda de paquetes y disección de protocolos sin interfaz gráfica.
* **Npcap:** Controlador de captura de paquetes a nivel de enlace de datos para Windows con soporte NDIS 6.
* **SQLite 3 (`sqlite3` nativo):** Motor de base de datos relacional serverless con modo journal `DELETE` y consultas transaccionales directas.

### 3.3 Estructura Modular del Repositorio

```
ARPShield/
│
├── main.py                               # Punto de entrada de la aplicación
├── requirements.txt                      # Dependencias oficiales de Python
├── pyproject.toml                        # Configuración de herramientas del entorno
├── README.md                             # Guía rápida de presentación
│
├── src/arpshield/                        # Código fuente del paquete principal
│   ├── __init__.py                       # Exportación de AppSettings, DatabaseManager, ThreatMonitor
│   ├── config.py                         # Configuración, rutas y expresiones regulares de validación
│   ├── database.py                       # Gestor de base de datos, DDL, índices y migraciones
│   ├── detection.py                      # Motor heurístico multiprotocolo de detección de spoofing
│   ├── monitor.py                        # Orquestador del monitor local, lectura de red y gateway
│   │
│   └── ui/                               # Capa de presentación visual (PySide6)
│       ├── main_window.py                # Ventana principal, navegación, topbar y ajustes
│       ├── dashboard.py                  # Panel dashboard, tarjetas métricas y gráficos vectoriales
│       └── traffic_viewer.py             # Visor de tráfico, control de TShark y reproductor PCAP
│
├── tests/                                # Suite de aseguramiento de calidad (QA)
│   ├── test_database.py                  # Pruebas de base de datos, migraciones y deduplicación
│   ├── test_detection.py                 # Pruebas del motor heurístico contra ataques simulados
│   ├── test_dashboard.py                 # Pruebas de formato de evidencia y métricas
│   ├── test_main_window.py               # Pruebas de filtrado y etiquetas de dispositivos
│   └── test_traffic_viewer.py            # Pruebas de mapeo de campos, argumentos TShark y buffers
│
├── captures/                             # Capturas PCAP de prueba para auditoría y validación
│   ├── arp_spoof.pcap                    # Escenario de suplantación de router vía ARP
│   ├── dns_spoof.pcap                    # Escenario de envenenamiento de caché DNS
│   ├── dhcp_spoof.pcap                   # Escenario de servidor DHCP pirata en conflicto
│   ├── ip_spoof.pcap                     # Escenario de falsificación de IP de origen externa
│   └── baseline.pcap                     # Escenario de tráfico normal de referencia (sin alertas)
│
├── prueba/                               # Scripts auxiliares de generación de tráfico
│   └── generator.py                      # Script Scapy generador de escenarios PCAP
│
└── docs/                                 # Documentación técnica formal del sistema
    ├── documentacion_oficial_arpshield.md # Este documento integral consolidado
    ├── Ultimos cambios.md                # Bitácora detallada de la auditoría y refactorización
    ├── database_model_data_dictionary.md # Especificación técnica DDL y diccionario de datos
    ├── developer_setup_guidelines.md     # Guía para desarrolladores y reglas de subprocesos
    ├── security_policy_stride_mitigation.md # Políticas de seguridad y matriz STRIDE
    ├── system_architecture_technical_design.md # Diseño técnico de arquitectura
    └── nvd_analisis_vulnerabilidades_arp_shield.md # Análisis de CVEs y justificación NVD
```

---

## 4. Guía de Instalación y Puesta a Punto

### 4.1 Requisitos de Hardware y Sistema Operativo
* **Sistema Operativo:** Windows 10 o Windows 11 (64 bits).
* **Procesador:** Procesador de 2 o más núcleos (x86_64).
* **Memoria RAM:** Mínimo 4 GB de RAM (se recomiendan 8 GB durante capturas extensas).
* **Almacenamiento:** Mínimo 500 MB de espacio disponible en disco (SSD recomendado).
* **Privilegios:** Usuario estándar para ejecución general; permisos de Administrador para instalar Npcap.

### 4.2 Instalación de Dependencias de Captura (Npcap y TShark)
1. **Instalar Wireshark / TShark:**
   * Descarga el instalador oficial de Wireshark para Windows desde su sitio web oficial.
   * Durante la instalación, asegúrate de marcar la casilla para instalar **TShark** (la utilidad de línea de comandos).
   * Deja la ruta de instalación por defecto (`C:\Program Files\Wireshark`). Si la modificas, asegúrate de agregar dicha carpeta a la variable de entorno `PATH` del sistema.
2. **Instalar Npcap:**
   * El asistente de instalación de Wireshark incluye Npcap. Marca la opción *"Install Npcap in WinPcap API-compatible Mode"*.
   * Reinicia la terminal o Visual Studio Code tras la instalación para que los cambios en el `PATH` sean detectados.

### 4.3 Despliegue del Entorno Virtual de Python y Ejecución
1. **Clonar o abrir el directorio del proyecto en PowerShell:**
   ```powershell
   cd c:\Users\David\Desktop\RepoDelCoso\ARPShield
   ```
2. **Crear y activar el entorno virtual:**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
3. **Instalar los requisitos oficiales:**
   ```powershell
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```
4. **Ejecutar la suite completa de pruebas unitarias para validar la instalación:**
   ```powershell
   python -m unittest discover -s tests -v
   ```
   *(Debe reportar: `Ran 58 tests ... OK`)*.
5. **Iniciar la aplicación:**
   ```powershell
   python main.py
   ```

---

## 5. Manual de Uso de la Aplicación (Guía Operativa)

La interfaz de ARPShield utiliza una estética moderna en tema oscuro (*Dark Security UI*), optimizada para evitar la fatiga visual de analistas de seguridad durante jornadas operativas.

### 5.1 Barra Superior y Controles Globales (Escanear y Verificar)
En la parte superior de la ventana se ubican los controles maestros del sistema:
* **Buscador global:** Permite filtrar instantáneamente las alertas del Dashboard por IP, MAC, tipo o resumen.
* **Indicador de estado:** Muestra en tiempo real la salud del monitor (ejemplo: `● 3 dispositivos en línea base`).
* **Botón "Escanear" (Color Azul Principal):**
  * Invoca `arp -a` a bajo nivel mediante subprocesos protegidos.
  * Filtra automáticamente direcciones Multicast (`224.0.0.0/4`) y Broadcast (`255.255.255.255`, `.255`).
  * Infiere la subred activa y marca automáticamente el router con el rol **`GATEWAY`**.
  * Carga o actualiza los equipos observados en la tabla `trusted_baseline`.
* **Botón "Verificar" (Color Secundario):**
  * Compara la tabla ARP actual del sistema operativo con la línea base de confianza.
  * Si detecta que la MAC del Gateway u otro equipo cambió sin autorización, genera una alerta inmediata (`GATEWAY_SPOOFING` o `ARP_SPOOFING`) y abre un diálogo informativo en pantalla.
  * Detecta si una misma MAC reclama más de una dirección IP (`MULTIPLE_IPS_PER_MAC`).

---

### 5.2 Pestaña 1: Dashboard Central de Seguridad
Es la pantalla de visualización principal. Se actualiza automáticamente cada 15 segundos o ante eventos de captura:
1. **Tarjetas de Métricas Superiores:**
   * **Dispositivos del Último Escaneo (Azul):** Cantidad de equipos activos detectados en la red local durante el escaneo más reciente de la sesión (`device_count`).
   * **Alertas de esta Sesión (Verde):** Conteo de incidentes de seguridad ocurridos desde que se abrió la aplicación.
   * **Riesgo Alto / Crítico (Naranja/Rojo):** Cantidad de alertas que comprometen el Gateway o la integridad del enrutamiento.
   * **Entradas de Confianza (Rojo):** Muestra la totalidad de pares IP-MAC verificados y acumulados en la base de datos local (`baseline_count`).
2. **Gráfico de Tendencia de Alertas (Izquierda):**
   * Gráfico de línea y área vectorial con gradiente suave que traza el volumen de incidentes ocurridos en los últimos 12 días.
3. **Gráfico de Clasificación de Incidentes (Derecha):**
   * Gráfico de anillo (*Donut Chart*) interactivo que desglosa el porcentaje de ataques detectados por categoría (`ARP_SPOOFING`, `DNS_SPOOFING`, `DHCP_SPOOFING`, etc.).
4. **Tabla de Alertas Recientes y Modal Forense:**
   * Muestra las columnas: *Fecha y hora (Colombia)*, *Tipo*, *Severidad*, *IP afectada*, *MAC observada* y *Evidencia*.
   * **Conversión Horaria Local:** Los timestamps UTC almacenados en base de datos se convierten automáticamente a la zona horaria de Colombia (`UTC-05:00 / COT`) para que la hora mostrada coincida con el reloj local del analista.
   * **Exploración Forense:** Al hacer **doble clic o clic simple sobre cualquier alerta**, se despliega una ventana modal con el objeto JSON completo de la evidencia capturada (número de trama, marcas de tiempo precisas en hora de Colombia, puertos y campos específicos decodificados por TShark).

---

### 5.3 Pestaña 2: Visor de Tráfico en Vivo y Análisis Forense PCAP
Permite la inspección en tiempo real del tráfico o el análisis retrospectivo de archivos de captura:
1. **Selector de Adaptador Físico:** Detecta automáticamente las interfaces de red físicas de Windows asociadas al driver Npcap (Ethernet, Wi-Fi), mostrando su GUID y estado operativo (`Up` / `Down`). Descarta interfaces virtuales no soportadas.
2. **Filtro de Tráfico Wireshark:** Por defecto aplica un filtro optimizado que solo captura protocolos relevantes:
   ```text
   arp or dns or dhcp or dhcpv6 or bootp or llmnr or nbns or mdns or icmpv6
   ```
3. **Botón "Iniciar captura" / "Detener":** Arranca la captura en vivo mediante un proceso hijo asíncrono con `tshark.exe`.
4. **Botón "Abrir PCAP":** Permite cargar cualquier archivo `.pcap` o `.pcapng` externo. El sistema reinicia el estado efímero del detector y procesa las tramas como si estuvieran ocurriendo en vivo, generando las alertas correspondientes en el Dashboard.
5. **Tabla de Tráfico en Tiempo Real:**
   * Muestra las columnas: *Hora*, *N.º*, *Protocolo*, *IP origen*, *IP destino*, *MAC origen*, *MAC destino* e *Información*.
   * Procesa **33 campos analíticos**.
   * Identifica con precisión los protocolos `ARP`, `DNS`, `DHCP`, `DHCPV6`, `LLMNR`, `NBNS`, `MDNS`, `ICMPV6`, `TCP`, `UDP`, coloreando las etiquetas para rápida identificación.
   * Acota el buffer en memoria a **500 filas** con inserción en lotes de 50 para evitar la congelación de la interfaz gráfica (*OWASP ASVS V5.1.4*).

---

### 5.4 Pestaña 3: Ajustes y Clasificación de Dispositivos Confiables
Permite al administrador auditar y enriquecer la línea base de la red:
1. **Buscador en Vivo de Dispositivos:** Permite buscar y filtrar instantáneamente cualquier equipo por su dirección IP, dirección MAC, nombre asignado o rol de red.
2. **Asignación de Roles de Red:**
   * `GATEWAY`: Puerta de enlace / router principal (activa reglas de severidad `HIGH`).
   * `DNS_SERVER`: Servidor DNS autorizado en la red.
   * `DHCP_SERVER`: Servidor DHCP/DHCPv6 autorizado para asignar direcciones.
   * `KNOWN_HOST`: Equipos conocidos legítimos (estaciones de trabajo, impresoras).
   * `OTHER`: Otros dispositivos de la red.
3. **Asignación de Alias Legible:** Permite nombrar un dispositivo (ejemplo: *"Router Sala"*, *"Laptop de Ana"*, *"Servidor NAS"*) para que los reportes y alertas muestren un nombre familiar en lugar de solo números IP/MAC.
4. **Botón "Guardar nombre y rol":** Persiste las modificaciones en SQLite y recarga el estado del monitor en caliente sin reiniciar la aplicación.

---

## 6. Motor Heurístico de Detección de Spoofing (Protocolos y Reglas)

El archivo [`src/arpshield/detection.py`](file:///c:/Users/David/Desktop/RepoDelCoso/ARPShield/src/arpshield/detection.py) contiene el motor heurístico central (`SpoofingDetector`). A continuación se detallan las 13 reglas operativas implementadas:

```
+-----------------------------------------------------------------------------------------------------+
|                                 REGLAS ACTIVAS EN SPOOFINGDETECTOR                                  |
+----------------------+--------------------+---------------------------------------------------------+
| Identificador Alerta | Severidad Asignada | Condición de Activación                                 |
+----------------------+--------------------+---------------------------------------------------------+
| GATEWAY_SPOOFING     | HIGH               | Anuncio ARP o tráfico IP de la IP Gateway con MAC falsa |
| ARP_SPOOFING         | MEDIUM / HIGH      | eth.src != arp.hw_mac o cambio de MAC para una IP       |
| IP_SPOOFING          | MEDIUM / HIGH      | Tráfico IP desde una MAC distinta a la línea base o subr|
| MAC_SPOOFING         | MEDIUM             | MAC registrada para otra IP observada con origen nuevo  |
| MULTIPLE_IPS_PER_MAC | MEDIUM / HIGH      | Una misma MAC reclama >= 2 IPs simultáneas en la red    |
| ARP_BURST_UNSOLICITED| MEDIUM             | Ráfaga de >= 10 respuestas ARP opcode=2 en <= 10 seg.   |
| DNS_SPOOFING         | MEDIUM             | Respuestas contradictorias a misma TxID o DNS no conf.  |
| DHCP_SPOOFING        | MEDIUM             | Múltiples ofertas DHCP para una TxID o servidor pirata  |
| DHCPV6_SPOOFING      | MEDIUM             | Ofertas DHCPv6 en conflicto o MAC no clasificada        |
| LLMNR_SPOOFING       | MEDIUM             | Respuestas contradictorias en puerto 5355               |
| NBNS_SPOOFING        | MEDIUM             | Respuestas contradictorias de nombres NetBIOS           |
| MDNS_SPOOFING        | MEDIUM             | Respuestas contradictorias en puerto 5353 (multicast)   |
| NDP_SPOOFING         | MEDIUM             | Router Advertisements ICMPv6 (134) de MAC no autorizada |
+----------------------+--------------------+---------------------------------------------------------+
```

### 6.1 Detección ARP y Gateway Spoofing
* **Cotejo con Línea Base:** Si una trama ARP (`arp`) anuncia una asociación IP-MAC que contradice la entrada registrada en `trusted_baseline`, se genera inmediatamente una alerta. Si la IP corresponde al router (`device_type == "GATEWAY"`), se emite `GATEWAY_SPOOFING` con severidad `HIGH`. En caso contrario, se emite `ARP_SPOOFING` con severidad `MEDIUM`.
* **Inconsistencia de Cabeceras (Capa 2 vs. Capa 3):** Se verifica si la dirección MAC de origen del encabezado Ethernet (`eth.src`) difiere de la dirección MAC declarada en el cuerpo del paquete ARP (`arp.src.hw_mac`). Si difieren, se dispara `ARP_SPOOFING`, ya que es el patrón inequívoco de herramientas automatizadas de ataque (como *Ettercap*, *Bettercap* o *Arpspoof*).
* **Seguimiento Dinámico de Vecinos (`_arp_neighbors`):** Aunque una red no haya sido escaneada previamente (o al analizar un archivo `.pcap` externo), el detector mantiene una tabla dinámica en memoria. Si una IP que venía comunicándose con una MAC cambia repentinamente a otra en medio de la sesión, se detecta la suplantación dinámica de inmediato.

### 6.2 Detección de Ráfagas e Inundaciones (Burst & Multiple IPs)
* **`MULTIPLE_IPS_PER_MAC`:** El detector almacena un conjunto de las direcciones IP que cada MAC reclama mediante tramas ARP (`_arp_mac_ips`). Si una misma MAC intenta apropiarse de 2 o más direcciones IP diferentes (y no está autorizada explícitamente en la línea base con multihoming), se dispara la alerta. Si alguna de las IPs afectadas es el Gateway, la severidad se escala a `HIGH`.
* **`ARP_BURST_UNSOLICITED`:** Se implementa una ventana deslizante de tiempo (`ARP_BURST_WINDOW_SECONDS = 10.0`). Si una dirección MAC emite 10 o más respuestas ARP gratuitas o no solicitadas (`arp.opcode == "2"`) en menos de 10 segundos, se alerta sobre una ráfaga masiva de envenenamiento.

### 6.3 Detección de Suplantación IP y MAC
* **`IP_SPOOFING`:** Cuando circula tráfico no ARP (TCP, UDP, ICMP) cuya IP de origen afirma ser un equipo de la línea base, pero llega encapsulado con una MAC Ethernet distinta, se genera la alerta. Asimismo, si un paquete se dirige al Gateway declarando una IP de origen de una subred completamente ajena a la LAN observada, se clasifica como IP Spoofing.
* **`MAC_SPOOFING`:** Si una MAC registrada previamente para un equipo legítimo aparece de repente originando tráfico con una IP no asociada, se genera una señal de advertencia para descartar multihoming o alertar sobre suplantación física de NIC.

### 6.4 Detección de Servidores DHCP/DHCPv6 no Autorizados (Rogue DHCP)
* **Conflicto de Transacción:** El detector almacena en `_dhcp_offers` las ofertas DHCP (*Offer / ACK*, tipos 2 y 5) indexadas por su ID de transacción de 32 bits (`BOOTP Transaction ID`). Si dos servidores DHCP distintos responden a la misma solicitud de un cliente, se genera la alerta `DHCP_SPOOFING`.
* **Servidor No Autorizado:** Si en la línea base se han clasificado servidores con el rol `DHCP_SERVER`, cualquier oferta DHCP proveniente de una IP o MAC que no figure en dicha lista es alertada al instante.
* **DHCPv6:** Aplica la misma correlación sobre mensajes de anuncio/respuesta DHCPv6 (tipos 2 y 7), validando la MAC del servidor físico emisor.

### 6.5 Detección de Suplantación DNS y Envenenamiento de Caché
* **Carrera de Respuestas (Cache Poisoning):** El detector almacena las respuestas DNS en `_dns_answers` indexadas por la tupla `(dns_id, dns_query, ip_dst)`. Si llegan dos respuestas con resoluciones IP diferentes para la misma consulta e identificador de transacción dentro del tiempo de vida del estado (`STATE_TTL_SECONDS = 300`), se detecta un ataque de envenenamiento DNS (`DNS_SPOOFING`).
* **Resolver No Autorizado:** Si existen servidores clasificados como `DNS_SERVER`, cualquier respuesta DNS convencional que proceda de una IP no listada es reportada para revisión.
* **Independencia del Orden de Registros:** La función auxiliar `_normalize_dns_answers()` ordena y desduplica alfabéticamente las respuestas de una consulta DNS antes de comparar, evitando falsos positivos cuando un balanceador de carga o CDN legítimo devuelve los mismos registros en orden distinto.

### 6.6 Detección en Resolución de Nombres Locales (LLMNR, NBNS, mDNS)
* Se extraen los puertos UDP (5355 para LLMNR, 5353 para mDNS, 137 para NBNS).
* Si una consulta de resolución de nombres locales recibe respuestas contradictorias de múltiples equipos de la red, el sistema genera las alertas `LLMNR_SPOOFING`, `MDNS_SPOOFING` o `NBNS_SPOOFING`, frustrando ataques de herramientas como *Responder*.

### 6.7 Detección de Anuncios IPv6 / NDP no Autorizados (Rogue RA)
* **Router Advertisements (ICMPv6 tipo 134):** En redes IPv6, un atacante puede enviar paquetes RA falsos para proclamarse router por defecto. ARPShield verifica si la MAC emisora del RA corresponde al Gateway legítimo. Si no pertenece a un router clasificado, genera `NDP_SPOOFING`.
* **Neighbor Advertisements (ICMPv6 tipo 136):** Equivalente a ARP en IPv6. Si dos anuncios para la misma IP IPv6 destino reportan MACs contradictorias, se alerta la suplantación de vecino.

### 6.8 Algoritmo de Atribución Correcta de la MAC Atacante
En ataques de suplantación en red local, el atacante siempre responde primero para ganar la carrera, y el servidor legítimo responde milisegundos después.
El método auxiliar:
```python
def _select_attacker_mac(previous_mac: str, current_mac: str, trusted_macs: set[str]) -> str:
    if current_mac in trusted_macs and previous_mac and previous_mac not in trusted_macs:
        return previous_mac
    return current_mac or previous_mac
```
Garantiza que si el atacante respondió primero (`previous_mac`) y el servidor legítimo respondió segundo (`current_mac` presente en `trusted_macs`), **el sistema señala inequívocamente a la MAC del atacante como responsable**, eliminando falsas acusaciones contra los servidores reales.

---

## 7. Modelo de Datos y Persistencia (SQLite)

La persistencia de ARPShield se gestiona en [`src/arpshield/database.py`](file:///c:/Users/David/Desktop/RepoDelCoso/ARPShield/src/arpshield/database.py). El archivo SQLite reside en `%LOCALAPPDATA%\ARPShield\arpshield.db`.

### 7.1 Esquema Relacional DDL (SQL Script)

```sql
-- 1. Tabla de Dispositivos Confiables (Línea Base)
CREATE TABLE IF NOT EXISTS trusted_baseline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    mac_address TEXT NOT NULL,
    device_type TEXT CHECK(device_type IN (
        'GATEWAY', 'DNS_SERVER', 'DHCP_SERVER', 'KNOWN_HOST', 'OTHER'
    )) NOT NULL,
    hostname TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. Tabla del Catálogo OUI de Fabricantes
CREATE TABLE IF NOT EXISTS oui_catalog (
    mac_prefix TEXT PRIMARY KEY,
    vendor_name TEXT NOT NULL
);

-- 3. Tabla de Incidentes y Alertas de Seguridad
CREATE TABLE IF NOT EXISTS security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc DATETIME DEFAULT CURRENT_TIMESTAMP,
    alert_type TEXT CHECK(alert_type IN (
        'GATEWAY_SPOOFING', 'MULTIPLE_IPS_PER_MAC', 'ARP_BURST_UNSOLICITED',
        'DNS_SPOOFING', 'ARP_SPOOFING', 'IP_SPOOFING', 'MAC_SPOOFING',
        'DHCP_SPOOFING', 'DHCPV6_SPOOFING', 'LLMNR_SPOOFING',
        'NBNS_SPOOFING', 'MDNS_SPOOFING', 'NDP_SPOOFING'
    )) NOT NULL,
    severity TEXT CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) NOT NULL,
    attacker_mac TEXT NOT NULL,
    spoofed_ip TEXT NOT NULL,
    packet_count INTEGER DEFAULT 1,
    evidence_summary TEXT NOT NULL,
    evidence_details TEXT NOT NULL DEFAULT '{}',
    mitigation_applied INTEGER DEFAULT 0
);

-- 4. Tabla de Auditoría y Eventos del Sistema
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    description TEXT NOT NULL,
    user_context TEXT NOT NULL
);

-- Índices de Alto Rendimiento
CREATE INDEX IF NOT EXISTS idx_baseline_ip ON trusted_baseline(ip_address);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_alerts_attacker ON security_alerts(attacker_mac);
```

### 7.2 Diccionario de Datos Detallado

#### Tabla `trusted_baseline`
| Columna | Tipo | Nulo | Restricciones / Descripción |
| :--- | :--- | :--- | :--- |
| `id` | INTEGER | NO | Identificador único autoincremental (Clave Primaria). |
| `ip_address` | TEXT | NO | Dirección IPv4 del host. Única (`UNIQUE`). Validada por Regex. |
| `mac_address` | TEXT | NO | Dirección MAC física normalizada en mayúsculas (`XX:XX:XX:XX:XX:XX`). |
| `device_type` | TEXT | NO | Rol en red: `GATEWAY`, `DNS_SERVER`, `DHCP_SERVER`, `KNOWN_HOST`, `OTHER`. |
| `hostname` | TEXT | SÍ | Nombre de red o alias personalizado asignado por el usuario (máx. 120 caracteres). |
| `created_at` | DATETIME | NO | Marca de tiempo UTC de creación del registro. |
| `updated_at` | DATETIME | NO | Marca de tiempo UTC de la última modificación. |

#### Tabla `security_alerts`
| Columna | Tipo | Nulo | Restricciones / Descripción |
| :--- | :--- | :--- | :--- |
| `id` | INTEGER | NO | Identificador único del incidente (Clave Primaria). |
| `timestamp_utc` | DATETIME | NO | Marca de tiempo UTC en que se detectó la suplantación. |
| `alert_type` | TEXT | NO | Tipo de ataque (una de las 13 categorías del `CHECK`). |
| `severity` | TEXT | NO | Impacto: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. |
| `attacker_mac` | TEXT | NO | Dirección MAC física identificada como origen del ataque. |
| `spoofed_ip` | TEXT | NO | Dirección IP que el atacante pretendía suplantar o usurpar. |
| `packet_count` | INTEGER | NO | Número de paquetes observados asociados a la señal. |
| `evidence_summary` | TEXT | NO | Descripción explicativa estructurada del incidente. |
| `evidence_details` | TEXT | NO | Objeto JSON con los 33 campos decodificados del paquete. |
| `mitigation_applied`| INTEGER | NO | `0` = No mitigado; `1` = Entrada estática aplicada vía `netsh`. |

### 7.3 Estructura Forense JSON (`evidence_details`)
Cada alerta registrada almacena en `evidence_details` la evidencia exacta del paquete procesado:
```json
{
  "capture_source": "Captura en vivo (TShark)",
  "frame.time": "Nov 16, 2026 15:20:10.123456000",
  "frame.number": "42",
  "frame.protocols": "eth:ethertype:arp",
  "eth.src": "02:00:00:00:00:99",
  "eth.dst": "ff:ff:ff:ff:ff:ff",
  "arp.opcode": "2",
  "arp.src.proto_ipv4": "192.168.1.1",
  "arp.src.hw_mac": "02:00:00:00:00:99",
  "arp.dst.proto_ipv4": "192.168.1.64",
  "arp.dst.hw_mac": "b2:64:d3:c3:b0:41",
  "ip.src": "",
  "ip.dst": "",
  "dns.qry.name": "",
  "dns.flags.response": ""
}
```

---

## 8. Marco de Seguridad Normativa y Modelado de Amenazas STRIDE

### 8.1 Matriz de Trazabilidad Normativa (ASVS, NIST, ISO)

| Estándar | Cláusula | Requisito Operativo | Implementación Real en ARPShield |
| :--- | :--- | :--- | :--- |
| **OWASP ASVS** | V5.1.1 | Parametrización segura de subprocesos | Llamadas a `tshark`, `arp` y `netsh` usan listas estructuradas con `shell=False`. Prohibida la concatenación de strings. |
| **OWASP ASVS** | V5.1.4 | Prevención de Denegación de Servicio (DoS) | Buffer acotado a 500 filas en tabla visual, inserción por lotes e hilos desacoplados con `QProcess`. |
| **OWASP ASVS** | V7.1.1 / V7.4.1 | Manejo controlado de excepciones | Diálogos amigables de error (`QMessageBox`); se suprimen trazas de error (*stack traces*) y rutas de sistema al usuario. |
| **OWASP ASVS** | V7.4.1 | Principio de minimización de datos | Solo se leen y almacenan cabeceras de red L2/L3/L4. No se inspecciona ni almacena payload de capa 7. |
| **NIST SSDF** | PW.1.1 | Principio de Mínimo Privilegio | La aplicación opera en espacio de usuario estándar. No requiere privilegios de Administrador para monitorear. |
| **ISO/IEC 27033-1**| Cl. 9.3 | Trazabilidad y auditoría de eventos | Registro cronológico inmutable de incidentes y auditoría de cambios en tablas SQLite indexadas. |
| **ISO/IEC 27033-3**| Cl. 7.2 | Control Anti-Spoofing en tiempo real | Motor heurístico de 13 reglas contrastando tramas en tránsito contra la línea base autorizada. |

### 8.2 Matriz de Modelado de Amenazas STRIDE Aplicada

1. **Spoofing (Suplantación):**
   * *Amenaza:* Un atacante envenena la caché ARP del equipo para interceptar comunicaciones.
   * *Mitigación:* Comparación inmediata contra `trusted_baseline` y detección de cabeceras contradictorias (`eth.src != arp.src.hw_mac`).
2. **Tampering (Manipulación):**
   * *Amenaza:* Modificación del archivo de base de datos para introducir MACs maliciosas como confiables.
   * *Mitigación:* Almacenamiento en `%LOCALAPPDATA%` con permisos NTFS restringidos al usuario de Windows y confirmación previa obligatoria al escanear.
3. **Repudiation (Repudio):**
   * *Amenaza:* Un atacante niega haber realizado escaneos o generado tráfico anómalo.
   * *Mitigación:* Registro forense inalterable con marcas de tiempo UTC, dirección física MAC, IP y número de trama en `security_alerts` y `audit_logs`.
4. **Information Disclosure (Fuga de Información):**
   * *Amenaza:* Exposición de credenciales o mensajes confidenciales de usuarios que circulan por la red.
   * *Mitigación:* Descarte intencional de cargas útiles (*payloads*); el analizador solo extrae metadatos de encabezado.
5. **Denial of Service (Denegación de Servicio):**
   * *Amenaza:* Una ráfaga de millones de paquetes satura la memoria del proceso de Python y bloquea la interfaz.
   * *Mitigación:* Limitación de 500 filas en memoria de la tabla, descarte en lote de paquetes antiguos (`removeRow`) y delegación de captura a `tshark.exe` desacoplado.
6. **Elevation of Privilege (Elevación de Privilegios):**
   * *Amenaza:* Un atacante inyecta comandos del sistema a través de nombres de dispositivos o argumentos de consola.
   * *Mitigación:* Validación previa exhaustiva con expresiones regulares estrictas (`REGEX_IPV4` y `REGEX_MAC`) antes de cualquier llamada a subprocesos.

### 8.3 Sustento Técnico con Vulnerabilidades Históricas NIST NVD
* **CVE-1999-0667 (CVSS 10.0 HIGH):** Vulnerabilidad estructural del estándar ARP que permite a cualquier host suplantar respuestas. Justifica la existencia de ARPShield.
* **CVE-2008-1447 (CVSS 6.8 MEDIUM):** Ataque Kaminsky de envenenamiento de caché DNS por falta de entropía en IDs de transacción. Justifica la regla `DNS_SPOOFING`.
* **CVE-2019-11189 (CVSS 7.5 HIGH):** Evasión de controles de red mediante respuestas ARP gratuitas no solicitadas. Justifica la regla `ARP_BURST_UNSOLICITED`.
* **CVE-2026-3959 (CVSS 5.3 MEDIUM):** Vulnerabilidad de inyección de comandos en herramientas CLI de TShark. Justifica la parametrización estricta con `shell=False`.

---

## 9. Plan de Pruebas, Verificación y Aseguramiento de Calidad (QA)

### 9.1 Suite de Pruebas Unitarias Automatizadas (58 Tests)
El proyecto cuenta con una cobertura integral de pruebas unitarias en `tests/` que validan cada componente de forma aislada:
* `test_database.py` (14 pruebas): Creación de tablas, migraciones de restricciones, agregaciones del dashboard, conteo de dispositivos por sesión, deduplicación de alertas y descarte de direcciones Multicast/Broadcast al escanear.
* `test_detection.py` (31 pruebas): Validación de las 13 reglas heurísticas de spoofing, tolerancia al orden de respuestas DNS, desempate de atacante en carreras de red, detección dinámica sin línea base previa, detección de respuestas gratuitas no solicitadas y control de TTL en consultas.
* `test_traffic_viewer.py` (9 pruebas): Mapeo de los 33 campos analíticos, decodificación de protocolos DHCP/NBNS/mDNS, detección de adaptadores físicos por GUID, exclusión de interfaces virtuales y acotación de buffers de memoria.
* `test_main_window.py` (3 pruebas): Filtrado dinámico de dispositivos confiables por IP, MAC y alias sin distinguir mayúsculas.
* `test_dashboard.py` (1 prueba): Serialización, conversión a hora de Colombia (UTC-5) y formato JSON del modal de detalles forenses.

**Ejecución de la suite:**
```powershell
python -m unittest discover -s tests -v
```
**Resultado esperado:**
```text
Ran 58 tests in 1.932s
OK
```

---

### 9.2 Pruebas de Laboratorio con Archivos PCAP Sintéticos
En la carpeta [`captures/`](file:///c:/Users/David/Desktop/RepoDelCoso/ARPShield/captures) se incluyen escenarios reales pre-grabados:
1. **`arp_spoof.pcap`:** Cárgalo desde la pestaña Tráfico (*Abrir PCAP*). Se detecta inmediatamente como `ARP_SPOOFING` (1 alerta).
2. **`dns_spoof.pcap`:** Se detecta como `DNS_SPOOFING` al encontrar respuestas contradictorias para `example.test` (1 alerta).
3. **`dhcp_spoof.pcap`:** Se detecta como `DHCP_SPOOFING` al recibir ofertas simultáneas del servidor legítimo y un servidor falso (1 alerta).
4. **`ip_spoof.pcap`:** Se detecta como `IP_SPOOFING` al observar tráfico saliente con IP externa anómala desde la MAC atacante (1 alerta).
5. **`baseline.pcap`:** Tráfico normal legítimo de router. **Pasa limpio con 0 alertas**, demostrando ausencia de falsos positivos.

---

### 9.3 Pruebas de Penetración en Vivo con Kali Linux y VirtualBox
Para probar ARPShield en vivo en una red real utilizando una máquina virtual de **Kali Linux**:

#### Paso 1: Configurar la Red en VirtualBox
1. Apaga la máquina virtual de Kali Linux.
2. Abre la configuración de la VM $\rightarrow$ **Red** $\rightarrow$ **Adaptador 1**.
3. En *Conectado a*, selecciona **"Adaptador puente" (Bridged Adapter)** y elige la tarjeta Wi-Fi o Ethernet de tu máquina anfitriona de Windows.
4. En *Avanzadas*, cambia **Modo promiscuo** a **"Permitir todo"**.
5. Enciende Kali Linux. Ejecuta `ip a` en Kali para verificar que recibió una IP de la misma subred de tu Windows (ejemplo: Windows `192.168.1.64` y Kali `192.168.1.80`).

#### Paso 2: Iniciar Monitoreo en ARPShield (Windows)
1. Inicia ARPShield: `python main.py`.
2. Presiona el botón superior **"Escanear"** para asegurar que el Gateway de tu casa esté identificado.
3. Ve a la pestaña **◎ Tráfico**, selecciona tu adaptador físico y haz clic en **"Iniciar captura"**.

#### Paso 3: Ejecutar los 5 Ataques desde Kali Linux (como root)

* **Prueba 1 — ARP Poisoning:**
  ```bash
  sudo arpspoof -i eth0 -t <IP_WINDOWS> <IP_ROUTER>
  ```
  *Resultado:* ARPShield genera alertas de **`GATEWAY_SPOOFING`** o **`ARP_SPOOFING`** en tiempo real señalando la MAC de Kali.
* **Prueba 2 — Ráfaga Masiva ARP:**
  ```bash
  sudo arping -c 25 -I eth0 <IP_WINDOWS>
  ```
  *Resultado:* ARPShield dispara **`ARP_BURST_UNSOLICITED`** tras superar el umbral de 10 paquetes en 10 segundos.
* **Prueba 3 — DNS Spoofing:**
  ```bash
  sudo dnschef --fakeip 10.10.10.10 --fakedomains example.com --interface <IP_KALI>
  ```
  *(En Windows haz: `nslookup example.com <IP_KALI>`)*.  
  *Resultado:* ARPShield detecta la respuesta y genera **`DNS_SPOOFING`**.
* **Prueba 4 — Rogue DHCP Server:**
  ```bash
  sudo yersinia dhcp -a -c
  ```
  *Resultado:* Se genera **`DHCP_SPOOFING`** por oferta de servidor no clasificado.
* **Prueba 5 — Envenenamiento LLMNR/mDNS:**
  ```bash
  sudo responder -I eth0 -v
  ```
  *(En Windows haz: `ping equipo-inexistente-xyz`)*.  
  *Resultado:* ARPShield detecta la respuesta de Kali y genera **`LLMNR_SPOOFING`** o **`NBNS_SPOOFING`**.

---

## 10. Conclusiones, Cautelas Operativas y Roadmap Futuro

### 10.1 Consideraciones en Redes Conmutadas (Switches y Wi-Fi)
ARPShield opera con la visibilidad del adaptador de red local. En switches gestionados corporativos, el tráfico unicast entre otros hosts no llega a la tarjeta de red del usuario. Para monitorizar un segmento completo, se recomienda ubicar un equipo con ARPShield conectado a un **puerto espejo (SPAN / Mirror Port)** o a la salida de un **Network TAP pasivo**.

### 10.2 Plan de Mitigación Activa mediante `netsh`
El diseño arquitectónico contempla la remediación automática del ataque ARP fijando la entrada estática en la tabla de vecinos de Windows:
```cmd
netsh interface ipv4 add neighbors "Ethernet" "192.168.1.1" "50-BB-9F-06-CE-FC"
```
Actualmente, el botón de mitigación en la interfaz informa los requisitos de privilegios de Administrador (UAC). En el roadmap de la versión 3.0 se integrará la ejecución segura de esta orden con reversión automática a modo dinámico (`netsh interface ipv4 delete neighbors`) al cerrar sesión.

### 10.3 Recomendaciones para el Administrador de Red
1. **Verificar antes de confiar:** La línea base se alimenta del primer escaneo. Asegúrate de escanear la red en un momento de operación normal antes de conectar dispositivos desconocidos.
2. **Nombrar los activos críticos:** Asigna roles y nombres en la pestaña *Ajustes* al Router, Servidores DNS y DHCP locales para que el motor aplique las reglas de máxima severidad.
3. **Complementariedad defensiva:** ARPShield constituye una excelente primera línea de defensa (*Capa de Detección e IDS*), que debe complementarse con buenas prácticas de red corporativa como inspección dinámica de ARP (*DAI*), *DHCP Snooping* e implementación de *DNS over HTTPS/TLS* (DoH/DoT).

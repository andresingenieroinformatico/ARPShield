# ARPShield - Guía de Desarrollo y Entorno de Trabajo

## 1. Entorno de Desarrollo y Dependencias

### Requisitos del Sistema Operativo:
- **Windows 10 / 11** (Requerido para la integración nativa con `netsh` y la captura de tramas en NICs locales).
- Privilegios de administrador para la instalación de controladores de red (Npcap) y para fijar entradas ARP estáticas.
- Compatibilidad con drivers de red administrados para habilitar captura promiscua de nivel 2 en entornos controlados.

### Dependencias Principales de Python:
- **Python:** Version 3.10+
- **PySide6:** `6.6.0` (Interfaz gráfica y concurrencia con `QThread`).
- **Scapy:** `2.8.0` (Captura e inspección de tramas ARP/DNS).
- **PyShark:** `0.6.0` (Análisis forense de archivos PCAP vía TShark).
- **pysqlcipher3:** `1.2.0` (Persistencia de base de datos local).
- **SQLAlchemy** (opcional para abstracción de acceso a datos y pruebas de persistencia)
- **pytest** (para pruebas unitarias y validación del motor de detección)
- **matplotlib / pandas** (opcional, para dashboard y reportes de tendencias de incidentes)

### Dependencias del Sistema y Herramientas de Red:
- **Npcap**: captura de paquetes ARP/DNS y soporte dedrivers de red sin necesidad de cambiar el hardware.
- **TShark / Wireshark**: visualización de tráfico capturado en tiempo real o desde PCAPs forenses. `tshark.exe` debe estar en `PATH` o instalado en `C:\Program Files\Wireshark`. Si se modifica `PATH` mientras VS Code está abierto, reiniciar VS Code para que la aplicación herede la variable actualizada.
- **netsh**: manejo de entradas ARP locales y mitigación del ataque.
- **Windows SDK / PowerShell**: para la ejecución segura de scripts y manejo de permisos UAC.
- **SQLite / SQLCipher**: almacenamiento local de líneas base, alertas y auditoría.
- **OpenSSL / certificados locales** (opcional para proteger transporte de datos o integridad de artefactos)

### Requisitos de Rendimiento y Hardware:
- Al menos 8 GB de RAM para análisis en tiempo real y revisión de pcap con tráfico moderado.
- Procesador de 4 núcleos para soporte de hilos de captura y análisis concurrente.
- Disco SSD recomendado para almacenamiento operativo de registros y evidencia.
- Conexión local de red y acceso a la interfaz LAN para validación de pruebas de laboratorio.

### Componentes de Infraestructura Adicionales Requeridos
- **Dashboard de Monitoreo**: panel central con métricas, incidentes activos, estado de la línea base y alertas.
- **Visualizador de Tráfico**: vista de captura en tiempo real con filtros por IP, MAC, protocolo y origen/destino.
- **Storage y Forense**: persistencia centralizada de evidencia, PCAP y reportes de auditoría.
- **Motor de Correlación**: combinación de señales ARP, DNS, inventario MAC/IP y contexto de red.
- **Controlador de Mitigación**: acciones automáticas o manuales para restaurar la red o aislar el tráfico sospechoso.
- **Gestor de Eventos**: cola de eventos y sistema de notificación para sincronizar UI, alertas y logs.

---

## 2. Distribución de Tareas del Equipo (Roles)

| Integrante | Rol | Responsabilidades Clave |
|---|---|---|
| **Andres Ferney Garcia Ramirez** (C.C. 1005564075) | Líder Técnico & Desarrollador Principal | Arquitectura general en Python/PySide6, motor de captura Scapy, llamadas seguras al SO (`netsh`) e integración con SQLite. |
| **Juan David Rico Aldana** (C.C. 1096801885) | Responsable de Seguridad & Documentador | Co-arquitectura, auditoría de código seguro, verificación de controles ASVS/NIST/ISO, mantenimiento del informe técnico y evidencias. |

---

## 3. Estrategia de Asistencia con IA (Antigravity AI Workspace)

El proyecto utiliza el entorno **Antigravity** orquestando diferentes modelos de IA ajustados a la complejidad de cada tarea:

```
+-------------------------------------------------------------------------+
|                        Antigravity AI Engine                            |
+-------------------------------------------------------------------------+
       |                  |                   |                  |
       v                  v                   v                  v
+--------------+  +---------------+  +------------------+  +--------------+
| Gemini Flash |  | Claude Sonnet |  |   Claude Opus    |  |    Codex     |
| (PySide6 UI, |  | (Motor Red,   |  | (Arquitectura,   |  | (Refactor,   |
|  Layouts)    |  |  SQLite, IP)  |  |  Vulnerab. STRIDE|  |  Fix Bugs)   |
+--------------+  +---------------+  +------------------+  +--------------+
```

1. **Gemini Flash (v3.8):** Utilizado para tareas rápidas y ligeras: maquetación de pantallas con PySide6, organización estructural del código y generación de pruebas unitarias básicas.
2. **Claude Sonnet (v4.6):** Modelo principal para lógica de negocio: captura y correlación de paquetes de red, validaciones Regex y persistencia en SQLite.
3. **Claude Opus (v4.6):** Auditor de arquitectura, revisiones de seguridad según el modelo STRIDE y validación de los controles normativos.
4. **Codex:** Soporte directo en escritura, refactorización y resolución puntual de excepciones de código durante la compilación.

---

## 4. Guía de Invocación Segura de Subprocesos (`subprocess`)

Queda estrictamente prohibido el uso de `shell=True` o concatenación de strings al ejecutar comandos en el sistema.

### Ejemplo de Implementación Correcta (ASVS V5.1.1 & V5.2.2):

```python
import re
import subprocess
from typing import Tuple

# Expresiones regulares estrictas
REGEX_IPV4 = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
REGEX_MAC = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"

def set_static_arp_entry(interface_name: str, ip_address: str, mac_address: str) -> Tuple[bool, str]:
    """
    Fija una entrada ARP estática en Windows utilizando netsh de forma segura.
    """
    # 1. Validación estricta de formato antes de invocar subproceso
    if not re.match(REGEX_IPV4, ip_address):
        raise ValueError(f"Formato de dirección IP inválido: {ip_address}")
    if not re.match(REGEX_MAC, mac_address):
        raise ValueError(f"Formato de dirección MAC inválido: {mac_address}")

    # 2. Construcción de lista de argumentos (shell=False)
    command = [
        "netsh",
        "interface",
        "ipv4",
        "add",
        "neighbors",
        interface_name,
        ip_address,
        mac_address
    ]

    try:
        # Invocación estructurada evitando command injection
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=False,
            check=True
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        # Retorno de error controlado sin exponenciación de trazas internas
        return False, f"Error al modificar tabla ARP: {e.stderr.strip()}"
```

---

## 5. Entorno de Pruebas y Simulación en Laboratorio

Para validar las alertas de suplantación sin comprometer redes de producción:
1. Utilizar un entorno virtualizado aislado (ej. VirtualBox / VMware) con al menos dos máquinas virtuales en red interna.
2. Ejecutar herramientas de laboratorio (como `arpspoof` o `ettercap`) en el equipo atacante de simulación.
3. Verificar que ARPShield detecte la discrepancia en Capa 2, registre el incidente en `security_alerts` y emita la notificación en el panel de monitoreo.
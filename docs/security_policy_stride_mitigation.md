# ARPShield - Políticas de Seguridad Normativa y Mitigación STRIDE

## 1. Cumplimiento Normativo (ASVS, NIST SSDF, ISO/IEC 27033)

Toda implementación en el código fuente debe cumplir estrictamente con los siguientes controles de seguridad:

| Estándar / Norma | Cláusula / Control | Requisito Operativo | Aplicación en ARPShield |
|---|---|---|---|
| **OWASP ASVS** | V5.1.1 | Parametrización estricta de llamadas al SO | Al invocar `netsh` o `tshark`, emplear arreglos/listas de argumentos estructurados sin concatenar cadenas directamente en la consola (`shell=False`). |
| **OWASP ASVS** | V7.1.1 & V7.4.1 | Manejo centralizado y controlado de errores | Capturar excepciones de red/archivos en PySide6 mostrando mensajes comprensibles al usuario. Queda prohibida la exposición de stack traces de Python o rutas internas. |
| **NIST SSDF** | PW.1.1 | Principio de Mínimo Privilegio | ARPShield opera con permisos estándar de usuario para análisis e inspección. Solamente solicita elevación UAC al aplicar la mitigación en la tabla ARP de Windows. |
| **ISO/IEC 27033-1**| Cláusula 9.3 | Trazabilidad y auditoría de eventos de red | Registrar cronológicamente en SQLite/SQLCipher cada alerta (MAC atacante, IP suplantada, timestamp UTC, conteo de paquetes y resultado de mitigación). |
| **ISO/IEC 27033-3**| Cláusula 7.2 | Control contra suplantación de identidad (Anti-Spoofing) | Implementación del motor de correlación en tiempo real cotejando tramas ARP recibidas contra la línea base autorizada. |
| **OWASP ASVS** | V8.3 / V8.3.1 | Cifrado en reposo y protección de archivos | Proteger el archivo de base de datos `.db` mediante permisos NTFS restringidos al usuario ejecutor y validación de hash SHA-256 en el inicio. |
| **OWASP ASVS** | V9.1 | Cifrado en tránsito para órdenes remotas | El envío de órdenes de contención a APIs externas de laboratorio (si aplican) se realizará mediante TLS 1.3. |

---

## 2. Matriz de Modelado de Amenazas STRIDE

### 1. Denial of Service (DoS)
* **Activo Afectado:** Módulo de captura y procesamiento de paquetes (TShark / Scapy).
* **Amenaza:** Un atacante emite ráfagas masivas de tramas ARP malformadas para saturar el hilo de captura en Python y agotar la memoria disponible.
* **Control Mitigador (ASVS V5.1.4):** 
  - Ejecución de la captura en un hilo secundario en segundo plano (`QThread`).
  - Implementación de un buffer circular limitado a máximo 1.000 paquetes.
  - Descarte inmediato de tramas con longitudes anómalas o malformadas antes del procesamiento extensivo.

### 2. Elevation of Privilege (EoP)
* **Activo Afectado:** Subproceso de ejecución de comandos del sistema operativo (`netsh`).
* **Amenaza:** Inyección de argumentos maliciosos en la consola cuando ARPShield invoca `netsh` con privilegios de Administrador para modificar la tabla ARP.
* **Control Mitigador (ASVS V5.2.2):**
  - Invocación estricta de subprocesos mediante listas de argumentos directas: `subprocess.run(["netsh", "interface", "ipv4", "add", "neighbors", ...], shell=False)`.
  - Validaciones sintácticas y semánticas estrictas de las entradas de dirección IP y MAC mediante Expresiones Regulares antes de solicitar elevación UAC.

### 3. Tampering (Alteración de Datos)
* **Activo Afectado:** Base de datos SQLite local (tabla de confianza IP-MAC).
* **Amenaza:** Un proceso no autorizado en la máquina cliente altera el archivo de base de datos para registrar la MAC del atacante como puerta de enlace legítima.
* **Control Mitigador (ASVS V8.3.1):**
  - Asignación de permisos del sistema de archivos NTFS restringidos exclusivamente al usuario ejecutor.
  - Verificación de la integridad del archivo mediante el cálculo e inspección de firma de hash SHA-256 en la inicialización.

### 4. Information Disclosure (Fuga de Información)
* **Activo Afectado:** Registros de eventos (logs), base de datos y archivos PCAP temporales.
* **Amenaza:** Almacenamiento accidental de cargas útiles privadas (payloads) de los usuarios o exposición de rutas internas y trazas de depuración de Python en mensajes de error.
* **Control Mitigador (ASVS V7.4.1):**
  - Filtrado estricto a nivel de captura para extraer únicamente cabeceras de Capa 2 (Ethernet/ARP) y Capa 3 (IP/DNS), descartando cualquier payload de Capa 7.
  - Manejador global de excepciones en PySide6 que suprime stack traces exponiendo mensajes informativos genéricos.

---

## 3. Reglas de Validación de Entradas (Regex)

Antes de pasar cualquier parámetro a subprocesos o consultas SQL, se deben validar contra las siguientes reglas estrictas:

* **Dirección IPv4:**
  `^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`
* **Dirección MAC:**
  `^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`
* **Ruta de archivo PCAP:**
  Verificar existencia física en disco con API de Python (`os.path.isfile()`) y asegurar la extensión estricta `.pcap` o `.pcapng`.
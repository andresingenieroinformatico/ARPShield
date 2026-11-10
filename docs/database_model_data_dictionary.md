# ARPShield - Modelo de Base de Datos y Diccionario de Datos

## 1. Descripción de Persistencia
ARPShield utiliza **SQLite** (con la opción de cifrado **SQLCipher** mediante `pysqlcipher3`) para la persistencia local de datos de red, alertas, inventario OUI y logs de auditoría. El archivo de base de datos se almacena localmente en la ruta de ejecución protegida por el sistema de archivos NTFS.

---

## 2. Esquema Relacional DDL (SQL Script)

```sql
-- Tabla: trusted_baseline (Línea base autorizada IP-MAC)
CREATE TABLE IF NOT EXISTS trusted_baseline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    mac_address TEXT NOT NULL,
    device_type TEXT CHECK(device_type IN ('GATEWAY', 'DNS_SERVER', 'DHCP_SERVER', 'KNOWN_HOST', 'OTHER')),
    hostname TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Tabla: oui_catalog (Catálogo de fabricantes OUI)
CREATE TABLE IF NOT EXISTS oui_catalog (
    mac_prefix TEXT PRIMARY KEY, -- Ej: '00:50:56'
    vendor_name TEXT NOT NULL
);

-- Tabla: security_alerts (Registro de incidentes de seguridad)
CREATE TABLE IF NOT EXISTS security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc DATETIME DEFAULT CURRENT_TIMESTAMP,
    alert_type TEXT CHECK(alert_type IN (
        'GATEWAY_SPOOFING', 'MULTIPLE_IPS_PER_MAC', 'ARP_BURST_UNSOLICITED',
        'DNS_SPOOFING', 'ARP_SPOOFING', 'IP_SPOOFING', 'MAC_SPOOFING',
        'DHCP_SPOOFING', 'DHCPV6_SPOOFING', 'LLMNR_SPOOFING',
        'NBNS_SPOOFING', 'MDNS_SPOOFING', 'NDP_SPOOFING'
    )),
    severity TEXT CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    attacker_mac TEXT NOT NULL,
    spoofed_ip TEXT NOT NULL,
    packet_count INTEGER DEFAULT 1,
    evidence_summary TEXT NOT NULL,
    mitigation_applied INTEGER DEFAULT 0 -- 0: No aplicada, 1: Estática netsh aplicada
);

-- Tabla: audit_logs (Trazabilidad y auditoría de eventos del sistema)
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    description TEXT NOT NULL,
    user_context TEXT NOT NULL
);

-- Índices de optimización de consulta
CREATE INDEX IF NOT EXISTS idx_baseline_ip ON trusted_baseline(ip_address);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_alerts_attacker ON security_alerts(attacker_mac);
```

---

## 3. Diccionario de Datos

### Tabla: `trusted_baseline`
| Campo | Tipo de Dato | Nulo | Descripción / Reglas |
|---|---|---|---|
| `id` | INTEGER | NO | Identificador único autoincremental (Clave Primaria). |
| `ip_address` | TEXT | NO | Dirección IPv4 del dispositivo autorizadas (Única). Validada por Regex IPv4. |
| `mac_address` | TEXT | NO | Dirección física MAC legítima asociada. Formato `XX:XX:XX:XX:XX:XX`. |
| `device_type` | TEXT | NO | Rol verificado en la red: `GATEWAY`, `DNS_SERVER`, `DHCP_SERVER`, `KNOWN_HOST`, `OTHER`. Se configura desde Ajustes y se usa como referencia para detectar suplantación. |
| `hostname` | TEXT | SÍ | Nombre de host o resolución NetBIOS/mDNS si está disponible. |
| `created_at` | DATETIME | NO | Marca de tiempo de registro inicial (UTC). |
| `updated_at` | DATETIME | NO | Última modificación de la entrada. |

### Tabla: `security_alerts`
| Campo | Tipo de Dato | Nulo | Descripción / Reglas |
|---|---|---|---|
| `id` | INTEGER | NO | Identificador único del incidente. |
| `timestamp_utc` | DATETIME | NO | Timestamp UTC preciso del momento del ataque/detección. |
| `alert_type` | TEXT | NO | Clasificación: `GATEWAY_SPOOFING`, `MULTIPLE_IPS_PER_MAC`, `ARP_BURST_UNSOLICITED`, `DNS_SPOOFING`, `ARP_SPOOFING`, `IP_SPOOFING`, `MAC_SPOOFING`, `DHCP_SPOOFING`, `DHCPV6_SPOOFING`, `LLMNR_SPOOFING`, `NBNS_SPOOFING`, `MDNS_SPOOFING` o `NDP_SPOOFING`. |
| `severity` | TEXT | NO | Nivel de impacto: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. |
| `attacker_mac` | TEXT | NO | Dirección MAC identificada como origen de la suplantación. |
| `spoofed_ip` | TEXT | NO | Dirección IP objetivo de la suplantación (ej. IP del router). |
| `packet_count` | INTEGER | NO | Número total de tramas maliciosas detectadas en la ráfaga. |
| `evidence_summary` | TEXT | NO | Detalle forense estructurado (ej. "MAC XX:XX pretendía ser Gateway 192.168.1.1"). |
| `mitigation_applied`| INTEGER | NO | Indicador binario (0 = Inactivo, 1 = Entrada estática aplicada vía `netsh`). |

---

## 4. Control de Integridad y Hash SHA-256

Para cumplir con el estándar **OWASP ASVS V8.3.1**:
1. Al cerrar correctamente la aplicación, el sistema genera la suma de comprobación SHA-256 del archivo `.db` y la registra en un archivo de firmas de integridad protegido.
2. Al iniciar, ARPShield recalcula el hash SHA-256 de la base de datos local.
3. Si la firma difiere, la aplicación entra en modo de alerta, advirtiendo al usuario sobre una posible alteración no autorizada de la línea base antes de cargar los datos en memoria.
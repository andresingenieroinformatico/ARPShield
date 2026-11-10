# ARPShield

ARPShield es una prueba de concepto de un IDS/IPS local orientado a detectar suplantación ARP y envenenamiento DNS en redes LAN pequeñas. Este proyecto se basa en la documentación de arquitectura y seguridad del repositorio y constituye una base inicial para el desarrollo funcional.

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

## Uso en equipos con recursos limitados

La interfaz limita el historial visible a los últimos 500 paquetes y 100 alertas, actualiza la tabla de paquetes por lotes y consulta estadísticas agregadas para el dashboard. El panel se actualiza cada 15 segundos solo cuando está visible. Estos límites reducen el consumo de memoria y CPU cuando hay historial extenso; no limitan los registros que ya están guardados en SQLite.

En equipos con 4 GB de RAM, se recomienda cerrar aplicaciones pesadas durante la captura y mantener el filtro de tráfico acotado (por defecto, `arp or dns`). La captura sigue dependiendo de TShark/Wireshark y del sistema operativo, por lo que el consumo total varía según el tráfico y los programas abiertos.

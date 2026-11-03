# Análisis de vulnerabilidades NVD y relevancia para ARPShield

**Fecha de consulta:** 3 de noviembre de 2026  
**Fuentes:** [NVD - búsqueda de vulnerabilidades](https://nvd.nist.gov/vuln/search?resultType=records), [API de NVD 2.0: búsqueda «ARP spoofing»](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=ARP%20spoofing) y [catálogo CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

## Alcance e interpretación

La búsqueda por la expresión **«ARP spoofing»** en NVD devolvió registros asociados a suplantación ARP, envenenamiento de caché, respuestas ARP no solicitadas y ataques de intermediario. Se seleccionan abajo cinco registros por su relación con el propósito de ARPShield; la selección no es un inventario exhaustivo de todos los CVE que podrían afectar a los productos instalados en una red.

**Estos CVE no identifican vulnerabilidades del código de ARPShield.** Describen fallas en otros productos o el riesgo inherente del protocolo ARP. Se usan como evidencia de amenazas que ARPShield pretende ayudar a observar. La indicación KEV se verificó contra la versión del catálogo CISA disponible para esta consulta (publicada el **30 de octubre de 2026**). «No aparece» significa únicamente que el CVE no figura en ese catálogo consultado; no demuestra que nunca haya sido explotado.

## Registros relevantes

| Identificador | Información sobre CISA KEV | Fecha de publicación NVD | CNA / fuente | Descripción y relación con ARPShield |
|---|---|---|---|---|
| [CVE-1999-0667](https://nvd.nist.gov/vuln/detail/CVE-1999-0667) | No aparece en el catálogo consultado. | 1997-09-19 | `cve@mitre.org` | NVD describe que un host puede falsificar respuestas ARP y envenenar la caché ARP para suplantar direcciones IP o causar denegación de servicio. Es el caso directamente relacionado con la detección de cambios IP-MAC que persigue ARPShield. |
| [CVE-2018-17195](https://nvd.nist.gov/vuln/detail/CVE-2018-17195) | No aparece en el catálogo consultado. | 2018-12-19 | `security@apache.org` | En Apache NiFi, una combinación de ARP spoofing y ataque de intermediario podía contribuir a un CSRF bajo condiciones específicas. Ilustra cómo la manipulación de tráfico local puede habilitar ataques contra aplicaciones; detectar ARP no corrige la falla CORS de la aplicación. |
| [CVE-2019-11189](https://nvd.nist.gov/vuln/detail/CVE-2019-11189) | No aparece en el catálogo consultado. | 2020-02-20 | `cve@mitre.org` | En ONOS 2.0 y anteriores, una respuesta ARP gratuita manipulada podía provocar la eliminación de reglas de denegación y facilitar la evasión del control de acceso. Es relevante para detectar anuncios ARP anómalos; la corrección debe aplicarse también en ONOS. |
| [CVE-2021-32575](https://nvd.nist.gov/vuln/detail/CVE-2021-32575) | No aparece en el catálogo consultado. | 2021-06-17 | `cve@mitre.org` | HashiCorp Nomad hasta 1.0.4 permitía ARP spoofing entre tareas en modo de red bridge. NVD indica correcciones en 0.12.12, 1.0.5 y 1.1.0 RC1. Ejemplifica el riesgo en redes virtualizadas, que una inspección de la tabla ARP del equipo no necesariamente cubre. |
| [CVE-2025-52890](https://nvd.nist.gov/vuln/detail/CVE-2025-52890) | No aparece en el catálogo consultado. | 2025-06-25 | `security-advisories@github.com` | En Incus 6.12 y 6.13, ciertas reglas nftables para dispositivos conectados a un bridge podían eludir parcialmente filtros MAC/IP y permitir suplantar otra VM o contenedor mediante ARP. La prevención requiere corregir y verificar la configuración del bridge; ARPShield no sustituye esos controles. |

> **Nota de fecha:** para CVE-1999-0667 se conserva la fecha de publicación que devuelve NVD, aunque sea anterior al año del identificador.

## Mitigación y estado real en ARPShield

El proyecto es un prototipo local. Según el código disponible, [`ThreatMonitor`](../src/arpshield/monitor.py) ejecuta `arp -a`, valida direcciones IP/MAC y puede comparar los resultados con una línea base para generar una alerta si cambia la MAC observada. Las alertas se guardan en SQLite mediante [`DatabaseManager`](../src/arpshield/database.py). La ejecución de `arp` usa argumentos separados y `shell=False`.

| Riesgo representado | Mitigación que ARPShield puede aportar | Estado y límites |
|---|---|---|
| Envenenamiento ARP y cambio de la relación IP-MAC (CVE-1999-0667) | Comparar las direcciones observadas con una línea base confiable, alertar ante cambios y conservar evidencia para investigación. Complementar con aislamiento de red y, cuando proceda, entradas ARP estáticas aplicadas de forma controlada. | **Parcial.** El prototipo consulta la tabla ARP del sistema y compara cambios; no inspecciona de forma continua cada trama ARP. La línea base se obtiene de esa misma tabla, por lo que podría estar contaminada antes de establecerse. |
| Respuestas ARP gratuitas que afectan políticas de acceso (CVE-2019-11189) | En una implementación completa, inspeccionar anuncios ARP no solicitados, correlacionarlos con la línea base y alertar sobre cambios. | **Pendiente.** El monitor actual no analiza paquetes ARP en tiempo real; además, ARPShield no repara las reglas o la lógica de ONOS. Debe actualizarse/configurarse el producto afectado. |
| Suplantación dentro de bridges virtuales (CVE-2021-32575 y CVE-2025-52890) | Aportar visibilidad local y evidencia si la interfaz supervisada observa el cambio, y permitir que el operador investigue el segmento implicado. | **Cobertura limitada.** Consultar `arp -a` en un equipo no garantiza visibilidad entre tareas, contenedores, máquinas virtuales o bridges. La actualización del hipervisor/orquestador y sus filtros es la mitigación primaria. |
| Ataque de intermediario que habilita fallas de aplicación (CVE-2018-17195) | Ayudar a detectar una posible anomalía ARP como señal de alerta temprana. | **No sustituye** la corrección de CORS, el uso de HTTPS ni las actualizaciones de Apache NiFi. La detección de ARP por sí sola no evita CSRF ni demuestra que haya ocurrido un ataque de aplicación. |

### Funciones aún no implementadas

- La documentación plantea captura de ARP/DNS con Scapy, detección de respuestas no solicitadas, detección de suplantación DNS y fijación de entradas mediante `netsh`; sin embargo, esas capacidades no deben presentarse como controles ya operativos.
- El monitor consultado no captura paquetes ARP/DNS ni implementa detección DNS; el tipo `DNS_SPOOFING` en el esquema de alertas no equivale a una detección funcional.
- En [`main_window.py`](../src/arpshield/ui/main_window.py), `apply_mitigation()` actualmente solo informa que la mitigación requiere validar el gateway y permisos administrativos. No aplica una entrada estática ni bloquea tráfico.
- Por tanto, en su estado actual, ARPShield debe considerarse una herramienta de **detección básica y registro**, no un IPS que garantice prevenir o contener los CVE anteriores.

## Por qué es importante ARPShield

La confianza implícita de ARP permite que un atacante en el mismo segmento intente asociar la IP de una víctima o del gateway a una MAC bajo su control. Si tiene éxito, puede redirigir o interrumpir tráfico y preparar ataques de intermediario. Los CVE seleccionados muestran que este vector puede interactuar con controles de acceso, redes virtualizadas y aplicaciones, no solo con la conectividad del equipo.

Un monitor local como ARPShield puede aportar valor al:

1. **Hacer visibles cambios IP-MAC** que de otro modo podrían pasar inadvertidos.
2. **Centralizar alertas y evidencia local** para facilitar diagnóstico y respuesta.
3. **Reducir el tiempo de detección** cuando se complete la captura continua y la correlación con una línea base confiable.
4. **Complementar**, sin reemplazar, las actualizaciones, controles de bridge, segmentación, HTTPS y protecciones de los productos afectados.

Para que ese valor sea confiable, las siguientes mejoras son prioritarias: obtener o aprobar la línea base desde una fuente confiable independiente de la caché ARP observada; implementar captura y análisis de ARP/DNS con controles contra saturación; registrar la procedencia y el resultado de cada alerta; y añadir mitigación explícita, validada, reversible y con privilegios mínimos. La mitigación automática no debería activarse antes de proteger la línea base frente a envenenamiento y de probar cómo evitar falsos positivos y pérdida de conectividad.

## Referencias

- [NVD - búsqueda de registros](https://nvd.nist.gov/vuln/search?resultType=records)
- [NVD API 2.0 - resultados por «ARP spoofing»](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=ARP%20spoofing)
- [CISA - catálogo KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA - datos JSON del catálogo KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- Documentación del proyecto: [política de seguridad y mitigación](./security_policy_stride_mitigation.md) y [arquitectura técnica](./system_architecture_technical_design.md).

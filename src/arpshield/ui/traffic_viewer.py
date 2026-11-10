from __future__ import annotations

<<<<<<< HEAD
from collections import deque
=======
import json
>>>>>>> 898312d13b0cf96c1706855d245871643442861a
import os
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

<<<<<<< HEAD
<<<<<<< HEAD
if TYPE_CHECKING:
=======
=======
from ..detection import CAPTURE_FIELDS

>>>>>>> 1fc77c61331b7cfe33e18e96de74b7c08cd541b9
try:
>>>>>>> 4551bfa7299551eff2751d0ecb43c9b37412521b
    from PySide6.QtCore import QProcess, QTimer, Qt
    from PySide6.QtGui import QColor
    from PySide6.QtWidgets import (
        QComboBox,
        QFileDialog,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QPushButton,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )
<<<<<<< HEAD
    _PYSIDE6_AVAILABLE = True
else:
    try:
        from PySide6.QtCore import QProcess, QTimer, Qt
        from PySide6.QtGui import QColor
        from PySide6.QtWidgets import (
            QComboBox,
            QFileDialog,
            QHBoxLayout,
            QHeaderView,
            QLabel,
            QLineEdit,
            QPushButton,
            QTableWidget,
            QTableWidgetItem,
            QVBoxLayout,
            QWidget,
        )
        _PYSIDE6_AVAILABLE = True
    except ModuleNotFoundError:  # pragma: no cover
        _PYSIDE6_AVAILABLE = False
        QWidget = object


FIELD_COUNT = 17
# Límite de buffer circular alineado con OWASP ASVS V5.1.4 (STRIDE #1 - Mitigación DoS)
MAX_PACKET_ROWS = 1000
UI_FLUSH_INTERVAL_MS = 100
=======
except ModuleNotFoundError:  # pragma: no cover
    QProcess = QTimer = Qt = None
    QColor = None
    QComboBox = QFileDialog = QHBoxLayout = QHeaderView = QLabel = QLineEdit = QPushButton = None
    QTableWidget = QTableWidgetItem = QVBoxLayout = QWidget = None


FIELD_COUNT = 17
MAX_PACKET_ROWS = 500
PACKET_BATCH_SIZE = 50
>>>>>>> 4551bfa7299551eff2751d0ecb43c9b37412521b
PACKET_COLUMNS = ["Hora", "N.º", "Protocolo", "IP origen", "IP destino", "MAC origen", "MAC destino", "Información"]
DEFAULT_CAPTURE_FILTER = "arp or dns or dhcp or dhcpv6 or bootp or llmnr or nbns or mdns or icmpv6"
UNSUPPORTED_EXTCAP_INTERFACES = {
    "ciscodump",
    "etwdump",
    "randpkt",
    "sshdump",
    "udpdump",
    "wifidump",
}


def find_tshark() -> str | None:
    """Find TShark on PATH or in standard Wireshark installation locations."""
    executable = shutil.which("tshark") or shutil.which("tshark.exe")
    if executable:
        return executable

    candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark" / "tshark.exe",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Wireshark" / "tshark.exe",
        Path(os.environ.get("ProgramW6432", r"C:\Program Files")) / "Wireshark" / "tshark.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def parse_interfaces(output: str) -> list[tuple[str, str]]:
    interfaces: list[tuple[str, str]] = []
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\.\s+(.+?)\s*$", line)
        if match:
            interfaces.append((match.group(1), match.group(2)))
    return interfaces


def capture_interface_target(interface_name: str) -> str | None:
    name = interface_name.strip()
    if not name:
        return None
    target = name.split(maxsplit=1)[0]
    if target.casefold() in UNSUPPORTED_EXTCAP_INTERFACES:
        return None
    return target


def parse_physical_adapters(output: str) -> dict[str, dict[str, str]]:
    if not output.strip():
        return {}
    payload = json.loads(output)
    if isinstance(payload, dict):
        payload = [payload]
    adapters: dict[str, dict[str, str]] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        guid = str(item.get("InterfaceGuid", "")).strip("{}").casefold()
        name = str(item.get("Name", "")).strip()
        if guid and name:
            adapters[guid] = {
                "name": name,
                "status": str(item.get("Status", "Unknown")),
            }
    return adapters


def windows_physical_adapters() -> dict[str, dict[str, str]]:
    if os.name != "nt":
        return {}
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetAdapter -Physical | "
            "Select-Object Name, Status, InterfaceGuid | ConvertTo-Json -Compress",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        details = result.stderr.strip() or "Get-NetAdapter terminó con error."
        raise RuntimeError(f"No se pudieron consultar los adaptadores físicos: {details}")
    try:
        return parse_physical_adapters(result.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise RuntimeError("Windows devolvió una lista de adaptadores físicos no válida.") from exc


def interface_guid(capture_target: str) -> str | None:
    match = re.search(r"\{([0-9a-fA-F-]{36})\}", capture_target)
    return match.group(1).casefold() if match else None


def packet_fields_to_row(line: str) -> list[str] | None:
    fields = line.rstrip("\r\n").split("\t")
    if len(fields) < FIELD_COUNT:
        fields.extend([""] * (FIELD_COUNT - len(fields)))
    elif len(fields) > FIELD_COUNT:
        fields = fields[:FIELD_COUNT]

    timestamp, number, protocols, eth_src, eth_dst, arp_opcode, arp_src_ip, arp_src_mac, arp_dst_ip, arp_dst_mac, dns_query, dns_response, dns_a, ip_src, ip_dst, ipv6_src, ipv6_dst = fields
    if not any(fields):
        return None

    protocol_names = protocols.split(":")
    protocol = next(
        (name.upper() for name in reversed(protocol_names) if name in {"arp", "dns", "tcp", "udp", "icmp", "icmpv6", "http", "tls"}),
        protocol_names[-1].upper() if protocol_names and protocol_names[-1] else "OTRO",
    )
    source_ip = ip_src or ipv6_src or arp_src_ip or "—"
    destination_ip = ip_dst or ipv6_dst or arp_dst_ip or "—"
    source_mac = eth_src or arp_src_mac or "—"
    destination_mac = eth_dst or arp_dst_mac or "—"

    details = []
    if arp_opcode:
        operation = {"1": "Solicitud ARP", "2": "Respuesta ARP"}.get(arp_opcode, f"ARP op. {arp_opcode}")
        details.append(operation)
        if arp_src_ip and arp_dst_ip:
            details.append(f"{arp_src_ip} → {arp_dst_ip}")
    if dns_query:
        details.append(f"Consulta DNS: {dns_query}")
    elif dns_response:
        details.append("Respuesta DNS")
    if dns_a:
        details.append(f"A: {dns_a}")

    return [
        timestamp or "—",
        number or "—",
        protocol,
        source_ip,
        destination_ip,
        source_mac,
        destination_mac,
        " | ".join(details) or protocol,
    ]


class TrafficViewerPanel(QWidget):
    def __init__(self, monitor=None):
        if not _PYSIDE6_AVAILABLE:
            raise ModuleNotFoundError("PySide6 no está instalado. Ejecuta: python -m pip install -r requirements.txt")
<<<<<<< HEAD
        super().__init__()
        self.monitor = monitor
        self.tshark_path: str | None = None
        self._mode = "idle"
        self._stdout_buffer = ""
        # Buffer circular en memoria (capacidad máxima: 1.000 paquetes, OWASP ASVS V5.1.4)
        self._pending_rows: deque[list[str]] = deque(maxlen=MAX_PACKET_ROWS)
        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(UI_FLUSH_INTERVAL_MS)
        self._flush_timer.timeout.connect(self._flush_pending_packets)
=======
else:
    class TrafficViewerPanel(QWidget):
        def __init__(self, monitor=None):
            super().__init__()
            self.monitor = monitor
            self.tshark_path: str | None = None
            self._mode = "idle"
            self._capture_source = "TShark"
            self._stdout_buffer = ""
            self._pending_rows: list[list[str]] = []
            self._detected_alert_count = 0
            self._detection_persistence_error = False
            self._capture_stderr = ""
            self._captured_record_count = 0
            self.process = QProcess(self)
            self.process.readyReadStandardOutput.connect(self._read_output)
            self.process.readyReadStandardError.connect(self._read_error)
            self.process.finished.connect(self._process_finished)
            self.process.errorOccurred.connect(self._process_error)
            self._flush_timer = QTimer(self)
            self._flush_timer.setInterval(200)
            self._flush_timer.timeout.connect(self._flush_pending_rows)
<<<<<<< HEAD
>>>>>>> 4551bfa7299551eff2751d0ecb43c9b37412521b
=======
            self._capture_watchdog = QTimer(self)
            self._capture_watchdog.setInterval(5000)
            self._capture_watchdog.timeout.connect(self._report_no_packets)
>>>>>>> 898312d13b0cf96c1706855d245871643442861a

<<<<<<< HEAD
        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self._read_output)
        self.process.readyReadStandardError.connect(self._read_error)
        self.process.finished.connect(self._process_finished)
        self.process.errorOccurred.connect(self._process_error)
=======
            layout = QVBoxLayout(self)
            layout.setContentsMargins(22, 18, 22, 18)
            layout.setSpacing(12)
            controls = QHBoxLayout()
            controls.setSpacing(9)
            self.interface_combo = QComboBox()
            self.filter_input = QLineEdit(DEFAULT_CAPTURE_FILTER)
            self.filter_input.setPlaceholderText("Filtro Wireshark (ej. arp or dns)")
            self.refresh_button = QPushButton("Detectar interfaces")
            self.start_button = QPushButton("Iniciar captura")
            self.stop_button = QPushButton("Detener")
            self.open_capture_button = QPushButton("Abrir PCAP")
            self.stop_button.setEnabled(False)
            self.start_button.setObjectName("primaryAction")
>>>>>>> 1fc77c61331b7cfe33e18e96de74b7c08cd541b9

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(12)
        controls = QHBoxLayout()
        controls.setSpacing(9)
        self.interface_combo = QComboBox()
        self.filter_input = QLineEdit("arp or dns")
        self.filter_input.setPlaceholderText("Filtro de visualización (ej. arp or dns)")
        self.refresh_button = QPushButton("Detectar interfaces")
        self.start_button = QPushButton("Iniciar captura")
        self.stop_button = QPushButton("Detener")
        self.open_capture_button = QPushButton("Abrir PCAP")
        self.stop_button.setEnabled(False)
        self.start_button.setObjectName("primaryAction")

        self.refresh_button.clicked.connect(self.refresh_interfaces)
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.open_capture_button.clicked.connect(self.load_capture_file)

        controls.addWidget(QLabel("Interfaz"))
        controls.addWidget(self.interface_combo, 3)
        controls.addWidget(QLabel("Filtro"))
        controls.addWidget(self.filter_input, 3)
        controls.addWidget(self.refresh_button)
        controls.addWidget(self.start_button)
        controls.addWidget(self.stop_button)
        controls.addWidget(self.open_capture_button)

        self.status_label = QLabel("Preparando TShark...")
        self.status_label.setStyleSheet("color: #a0a4b8; padding: 2px 0;")

        self.packet_table = QTableWidget(0, len(PACKET_COLUMNS))
        self.packet_table.setHorizontalHeaderLabels(PACKET_COLUMNS)
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.setShowGrid(True)
        self.packet_table.setWordWrap(False)
        self.packet_table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.packet_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.packet_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.verticalHeader().setDefaultSectionSize(30)
        self.packet_table.horizontalHeader().setMinimumSectionSize(64)
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        # Evita ResizeToContents para prevenir recálculos O(N^2) en el hilo de UI ante ráfagas ARP/DNS
        for column in range(0, 7):
            self.packet_table.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
        self.packet_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        self.packet_table.setColumnWidth(0, 215)
        self.packet_table.setColumnWidth(1, 68)
        self.packet_table.setColumnWidth(2, 85)
        self.packet_table.setColumnWidth(3, 125)
        self.packet_table.setColumnWidth(4, 125)
        self.packet_table.setColumnWidth(5, 145)
        self.packet_table.setColumnWidth(6, 145)
        self.packet_table.setStyleSheet("""
            QTableWidget {
                background: #222436;
                alternate-background-color: #26283b;
                color: #f4f5fb;
                gridline-color: #383a50;
                border: 1px solid #34364b;
                border-radius: 7px;
                selection-background-color: #28547a;
            }
            QHeaderView::section {
                background: #1d1f30;
                color: #c3c6d5;
                padding: 9px 7px;
                border: 1px solid #34364b;
                font-weight: 600;
            }
            QTableCornerButton::section { background: #1d1f30; border: 1px solid #34364b; }
        """)

        layout.addLayout(controls)
        layout.addWidget(self.status_label)
        layout.addWidget(self.packet_table, 1)
        self.refresh_interfaces()

<<<<<<< HEAD
    def refresh_interfaces(self) -> None:
        self.tshark_path = find_tshark()
        self.interface_combo.clear()
        if not self.tshark_path:
            self.status_label.setText(
                "TShark no aparece en PATH ni en las rutas habituales de Wireshark. "
                "Reinicia VS Code si acabas de modificar PATH."
=======
            try:
                result = subprocess.run(
                    [self.tshark_path, "-D"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    shell=False,
                    check=False,
                    timeout=15,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                self.status_label.setText(f"No se pudo consultar TShark: {exc}")
                self.start_button.setEnabled(False)
                return

            interfaces = parse_interfaces(result.stdout)
            if result.returncode != 0:
                details = result.stderr.strip() or result.stdout.strip() or "TShark terminó con error."
                self.status_label.setText(f"Error al consultar interfaces (código {result.returncode}): {details}")
                self.start_button.setEnabled(False)
                return

            try:
                physical_adapters = windows_physical_adapters()
            except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
                self.status_label.setText(f"No se pudieron verificar los adaptadores físicos de Windows: {exc}")
                self.start_button.setEnabled(False)
                return

            for interface_id, name in interfaces:
                target = capture_interface_target(name)
                if target:
                    guid = interface_guid(target)
                    adapter = physical_adapters.get(guid or "")
                    if os.name == "nt" and not adapter:
                        continue
                    if adapter:
                        status = adapter["status"]
                        label = f"{interface_id}. {adapter['name']} · {status} · {name}"
                        self.interface_combo.addItem(label, target)
                        self.interface_combo.setItemData(
                            self.interface_combo.count() - 1,
                            status,
                            Qt.ItemDataRole.UserRole + 1,
                        )
                    else:
                        self.interface_combo.addItem(f"{interface_id}. {name}", target)
            self.start_button.setEnabled(self.interface_combo.count() > 0)
            if self.interface_combo.count():
                self.status_label.setText(
                    f"TShark listo: {self.interface_combo.count()} adaptadores físicos disponibles. "
                    "Selecciona el que está conectado a la red."
                )
            else:
                self.status_label.setText(
                    "No se encontró un adaptador físico asociado a Npcap. Comprueba que Ethernet/Wi-Fi "
                    "esté habilitado, tenga controlador y aparezca en la lista de interfaces de TShark."
                )

        def start_capture(self) -> None:
            if self.process.state() != QProcess.ProcessState.NotRunning:
                return
            if not self.tshark_path or self.interface_combo.currentIndex() < 0:
                self.status_label.setText("Selecciona una interfaz de captura válida.")
                return

            interface_name = self.interface_combo.currentData()
            if not interface_name:
                self.status_label.setText("La interfaz seleccionada no es una fuente de captura local.")
                return
            adapter_status = self.interface_combo.currentData(Qt.ItemDataRole.UserRole + 1)
            if adapter_status and adapter_status.casefold() != "up":
                self.status_label.setText(
                    f"El adaptador seleccionado está {adapter_status}; conéctalo a la red antes de capturar."
                )
                return
            display_filter = self.filter_input.text().strip() or DEFAULT_CAPTURE_FILTER
            arguments = self._live_capture_arguments(interface_name, display_filter)
            self._mode = "live"
            self._capture_source = "Captura en vivo (TShark)"
            self._stdout_buffer = ""
            self._pending_rows.clear()
            self._detected_alert_count = 0
            self._detection_persistence_error = False
            self._capture_stderr = ""
            self._captured_record_count = 0
            self.packet_table.setRowCount(0)
            self._set_running(True)
            self.status_label.setText(
                f"Capturando en {self.interface_combo.currentText()} · filtro: {display_filter}. "
                "Se observa el tráfico visible para este adaptador."
            )
            self.process.start(self.tshark_path, arguments)

        @classmethod
        def _live_capture_arguments(cls, interface_name: str, display_filter: str) -> list[str]:
            return ["-i", interface_name, *cls._packet_arguments(display_filter)]

        @staticmethod
        def _packet_arguments(display_filter: str) -> list[str]:
            arguments = ["-l", "-n"]
            if display_filter:
                arguments.extend(["-Y", display_filter])
            arguments.extend(["-T", "fields", "-E", "separator=\t", "-E", "occurrence=a"])
            for field in CAPTURE_FIELDS:
                arguments.extend(["-e", field])
            return arguments

        def stop_capture(self) -> None:
            if self.process.state() != QProcess.ProcessState.NotRunning:
                self.process.terminate()
                if not self.process.waitForFinished(1500):
                    self.process.kill()
                self._read_output()
                self._set_running(False)
                self.status_label.setText(
                    f"Captura detenida · {self.packet_table.rowCount()} paquetes visibles."
                    f"{self._detection_warning()}"
                )

        def load_capture_file(self) -> None:
            path, _ = QFileDialog.getOpenFileName(
                self,
                "Seleccionar captura PCAP",
                str(Path.home()),
                "Capturas de red (*.pcap *.pcapng)",
>>>>>>> 4551bfa7299551eff2751d0ecb43c9b37412521b
            )
            self.start_button.setEnabled(False)
            return

<<<<<<< HEAD
<<<<<<< HEAD
        try:
            result = subprocess.run(
                [self.tshark_path, "-D"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                check=False,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.status_label.setText(f"No se pudo consultar TShark: {exc}")
            self.start_button.setEnabled(False)
            return

        interfaces = parse_interfaces(result.stdout)
        if result.returncode != 0:
            details = result.stderr.strip() or result.stdout.strip() or "TShark terminó con error."
            self.status_label.setText(f"Error al consultar interfaces (código {result.returncode}): {details}")
            self.start_button.setEnabled(False)
            return

        for interface_id, name in interfaces:
            self.interface_combo.addItem(f"{interface_id}. {name}", interface_id)
        self.start_button.setEnabled(bool(interfaces))
        if interfaces:
            self.status_label.setText(f"TShark listo: {len(interfaces)} interfaces disponibles. Captura detenida.")
        else:
            self.status_label.setText("TShark está instalado, pero no hay interfaces de captura disponibles.")
=======
            display_filter = self.filter_input.text().strip() or "arp or dns"
=======
            display_filter = self.filter_input.text().strip() or DEFAULT_CAPTURE_FILTER
>>>>>>> 1fc77c61331b7cfe33e18e96de74b7c08cd541b9
            self._mode = "file"
            self._capture_source = "Archivo PCAP/PCAPNG"
            self._stdout_buffer = ""
            self._pending_rows.clear()
            self._detected_alert_count = 0
            self._detection_persistence_error = False
            self._capture_stderr = ""
            self._captured_record_count = 0
            self.packet_table.setRowCount(0)
            fields = self._packet_arguments(display_filter)
            fields = fields[fields.index("-T") :]
            self._set_running(True)
            self.status_label.setText(f"Analizando {Path(path).name} · filtro: {display_filter}")
            self.process.start(self.tshark_path, ["-n", "-r", path, "-Y", display_filter, *fields])

        def _read_output(self) -> None:
            text = bytes(self.process.readAllStandardOutput()).decode("utf-8", errors="replace")
            if not text:
                return
            self._stdout_buffer += text
            lines = self._stdout_buffer.splitlines(keepends=True)
            self._stdout_buffer = ""
            if lines and not lines[-1].endswith(("\n", "\r")):
                self._stdout_buffer = lines.pop()
            for line in lines:
                if self._mode == "live":
                    self._captured_record_count += 1
                self._analyze_capture_record(line)
                row = packet_fields_to_row(line)
                if row:
                    self._pending_rows.append(row)
                    if len(self._pending_rows) >= PACKET_BATCH_SIZE:
                        self._flush_pending_rows()

        def _analyze_capture_record(self, line: str) -> None:
            if not self.monitor or self._detection_persistence_error:
                return
            try:
                alerts = self.monitor.analyze_capture_record(
                    line,
                    capture_source=self._capture_source,
                )
            except (OSError, sqlite3.Error) as exc:
                self._detection_persistence_error = True
                self.status_label.setText(f"Error guardando alertas de detección: {exc}")
                return
            self._detected_alert_count += len(alerts)
            if alerts:
                self.status_label.setText(
                    f"Posible spoofing detectado: {self._detected_alert_count} alerta(s) en esta captura."
                )

        def _flush_pending_rows(self) -> None:
            if not self._pending_rows:
                return

            rows = self._pending_rows
            self._pending_rows = []
            excess = self.packet_table.rowCount() + len(rows) - MAX_PACKET_ROWS
            self.packet_table.setUpdatesEnabled(False)
            for _ in range(max(0, excess)):
                self.packet_table.removeRow(0)

            first_row = self.packet_table.rowCount()
            self.packet_table.setRowCount(first_row + len(rows))
            protocol_colors = {"ARP": "#f39c12", "DNS": "#a45bb5"}
            for row_offset, values in enumerate(rows):
                row_index = first_row + row_offset
                for column, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    item.setToolTip(value)
                    if column == 2:
                        item.setForeground(QColor(protocol_colors.get(value, "#f4f5fb")))
                    self.packet_table.setItem(row_index, column, item)
            self.packet_table.setUpdatesEnabled(True)
            self.packet_table.scrollToBottom()
>>>>>>> 4551bfa7299551eff2751d0ecb43c9b37412521b

<<<<<<< HEAD
    @staticmethod
    def _live_capture_filter(display_filter: str) -> str | None:
        """Mapea filtros comunes de visualización a filtros BPF de captura (Npcap) para descartar tráfico pesado en kernel."""
        normalized = re.sub(r"\s+", " ", display_filter.strip().lower())
        bpf_map = {
            "arp or dns": "arp or port 53",
            "dns or arp": "arp or port 53",
            "arp": "arp",
            "dns": "port 53",
        }
        return bpf_map.get(normalized)
=======
        def _read_error(self) -> None:
            text = bytes(self.process.readAllStandardError()).decode("utf-8", errors="replace").strip()
            if text:
                self._capture_stderr = f"{self._capture_stderr}\n{text}".strip()[-2000:]
>>>>>>> 898312d13b0cf96c1706855d245871643442861a

    def start_capture(self) -> None:
        if self.process.state() != QProcess.ProcessState.NotRunning:
            return
        if not self.tshark_path or self.interface_combo.currentIndex() < 0:
            self.status_label.setText("Selecciona una interfaz de captura válida.")
            return

        interface_id = self.interface_combo.currentData()
        display_filter = self.filter_input.text().strip() or "arp or dns"
        arguments = self._packet_arguments(display_filter)
        capture_args = ["-i", str(interface_id)]
        bpf_filter = self._live_capture_filter(display_filter)
        if bpf_filter:
            capture_args.extend(["-f", bpf_filter])
        arguments[2:2] = capture_args
        self._mode = "live"
        self._stdout_buffer = ""
        self._pending_rows.clear()
        self.packet_table.setRowCount(0)
        self._set_running(True)
        self._flush_timer.start()
        self.status_label.setText(f"Capturando en {self.interface_combo.currentText()} · filtro: {display_filter}")
        self.process.start(self.tshark_path, arguments)

    @staticmethod
    def _packet_arguments(display_filter: str) -> list[str]:
        fields = [
            "frame.time",
            "frame.number",
            "frame.protocols",
            "eth.src",
            "eth.dst",
            "arp.opcode",
            "arp.src.proto_ipv4",
            "arp.src.hw_mac",
            "arp.dst.proto_ipv4",
            "arp.dst.hw_mac",
            "dns.qry.name",
            "dns.flags.response",
            "dns.a",
            "ip.src",
            "ip.dst",
            "ipv6.src",
            "ipv6.dst",
        ]
        arguments = ["-l", "-n"]
        if display_filter:
            arguments.extend(["-Y", display_filter])
        arguments.extend(["-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"])
        for field in fields:
            arguments.extend(["-e", field])
        return arguments

    def stop_capture(self) -> None:
        if self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.terminate()
            if not self.process.waitForFinished(1500):
                self.process.kill()
            self._read_output()
<<<<<<< HEAD
            self._flush_pending_packets()
            self._flush_timer.stop()
=======
            self._read_error()
            if self._stdout_buffer:
                self._analyze_capture_record(self._stdout_buffer)
                row = packet_fields_to_row(self._stdout_buffer)
                if row:
                    self._pending_rows.append(row)
                self._stdout_buffer = ""
>>>>>>> 4551bfa7299551eff2751d0ecb43c9b37412521b
            self._set_running(False)
<<<<<<< HEAD
            self.status_label.setText(f"Captura detenida · {self.packet_table.rowCount()} paquetes visibles.")
=======
            if exit_code:
                details = self._capture_stderr[-1000:]
                self.status_label.setText(
                    f"TShark terminó con código {exit_code}; revisa la interfaz, Npcap y el filtro."
                    f"{self._detection_warning()}"
                    + (f"\n{details}" if details else "")
                )
            elif self._mode == "file":
                self.status_label.setText(
                    f"PCAP analizado · {self.packet_table.rowCount()} paquetes visibles · "
                    f"{self._detected_alert_count} posible(s) spoofing.{self._detection_warning()}"
                )
            elif self._mode == "live":
                self.status_label.setText(
                    f"Captura finalizada · {self.packet_table.rowCount()} paquetes visibles · "
                    f"{self._detected_alert_count} posible(s) spoofing.{self._detection_warning()}"
                )

        def _detection_warning(self) -> str:
            if self._detection_persistence_error:
                return " | Alertas incompletas: se detuvo el análisis porque falló su almacenamiento."
            return ""
>>>>>>> 1fc77c61331b7cfe33e18e96de74b7c08cd541b9

    def load_capture_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Seleccionar captura PCAP",
            str(Path.home()),
            "Capturas de red (*.pcap *.pcapng)",
        )
        if not path:
            return
        if self.process.state() != QProcess.ProcessState.NotRunning:
            self.status_label.setText("Detén la captura en vivo antes de abrir un PCAP.")
            return
        if not self.tshark_path:
            self.refresh_interfaces()
        if not self.tshark_path:
            return

<<<<<<< HEAD
<<<<<<< HEAD
        display_filter = self.filter_input.text().strip() or "arp or dns"
        self._mode = "file"
        self._stdout_buffer = ""
        self._pending_rows.clear()
        self.packet_table.setRowCount(0)
        fields = self._packet_arguments(display_filter)
        fields = fields[fields.index("-T") :]
        self._set_running(True)
        self._flush_timer.start()
        self.status_label.setText(f"Analizando {Path(path).name} · filtro: {display_filter}")
        self.process.start(self.tshark_path, ["-n", "-r", path, "-Y", display_filter, *fields])

    def _read_output(self) -> None:
        raw_bytes = bytes(self.process.readAllStandardOutput().data())
        text = raw_bytes.decode("utf-8", errors="replace")
        if not text:
            return
        self._stdout_buffer += text
        lines = self._stdout_buffer.splitlines(keepends=True)
        self._stdout_buffer = ""
        if lines and not lines[-1].endswith(("\n", "\r")):
            self._stdout_buffer = lines.pop()
        for line in lines:
            row = packet_fields_to_row(line)
            if row:
                self._pending_rows.append(row)

    def _flush_pending_packets(self) -> None:
        if not self._pending_rows:
            return
        batch = list(self._pending_rows)
        self._pending_rows.clear()

        self.packet_table.setUpdatesEnabled(False)
        try:
            if len(batch) >= MAX_PACKET_ROWS:
                batch = batch[-MAX_PACKET_ROWS:]
                self.packet_table.setRowCount(0)
            else:
                overflow = (self.packet_table.rowCount() + len(batch)) - MAX_PACKET_ROWS
                for _ in range(max(0, overflow)):
                    self.packet_table.removeRow(0)

            for values in batch:
                self._insert_packet_row(values)
        finally:
            self.packet_table.setUpdatesEnabled(True)

        self.packet_table.scrollToBottom()

    def _insert_packet_row(self, values: list[str]) -> None:
        row_index = self.packet_table.rowCount()
        self.packet_table.insertRow(row_index)
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setToolTip(value)
            if column == 2:
                protocol_colors = {"ARP": "#f39c12", "DNS": "#a45bb5"}
                item.setForeground(QColor(protocol_colors.get(value, "#f4f5fb")))
            self.packet_table.setItem(row_index, column, item)

    def _append_packet(self, values: list[str]) -> None:
        self._pending_rows.append(values)
        self._flush_pending_packets()

    def _read_error(self) -> None:
        raw_bytes = bytes(self.process.readAllStandardError().data())
        text = raw_bytes.decode("utf-8", errors="replace").strip()
        if text:
            self.status_label.setText(f"TShark: {text[-400:]}")

    def _process_finished(self, exit_code: int, _exit_status) -> None:
        self._read_output()
        self._read_error()
        if self._stdout_buffer:
            row = packet_fields_to_row(self._stdout_buffer)
            if row:
                self._pending_rows.append(row)
            self._stdout_buffer = ""
        self._flush_pending_packets()
        self._flush_timer.stop()
        self._set_running(False)
        if exit_code:
            self.status_label.setText(f"TShark terminó con código {exit_code}; revisa los permisos o el filtro.")
        elif self._mode == "file":
            self.status_label.setText(f"PCAP analizado · {self.packet_table.rowCount()} paquetes visibles.")
        elif self._mode == "live":
            self.status_label.setText(f"Captura finalizada · {self.packet_table.rowCount()} paquetes visibles.")

    def _process_error(self, _error) -> None:
        self._flush_timer.stop()
        self._set_running(False)
        self.status_label.setText(f"No se pudo iniciar TShark: {self.process.errorString()}")

    def _set_running(self, running: bool) -> None:
        self.refresh_button.setEnabled(not running)
        self.start_button.setEnabled(not running and self.interface_combo.count() > 0)
        self.stop_button.setEnabled(running and self._mode == "live")
        self.open_capture_button.setEnabled(not running)
=======
=======
        def _report_no_packets(self) -> None:
            if (
                self._mode == "live"
                and self.process.state() != QProcess.ProcessState.NotRunning
                and self._captured_record_count == 0
            ):
                self.status_label.setText(
                    "Captura activa, pero no llegan paquetes que coincidan con el filtro. "
                    "Comprueba la interfaz física conectada y el filtro. Para ver tráfico de otros "
                    "equipos en una LAN conmutada necesitas un puerto espejo/TAP."
                )

>>>>>>> 898312d13b0cf96c1706855d245871643442861a
        def _set_running(self, running: bool) -> None:
            if running:
                self._flush_timer.start()
                if self._mode == "live":
                    self._capture_watchdog.start()
            else:
                self._flush_timer.stop()
                self._capture_watchdog.stop()
                self._flush_pending_rows()
            self.refresh_button.setEnabled(not running)
            self.start_button.setEnabled(not running and self.interface_combo.count() > 0)
            self.stop_button.setEnabled(running and self._mode == "live")
            self.open_capture_button.setEnabled(not running)
>>>>>>> 4551bfa7299551eff2751d0ecb43c9b37412521b

from __future__ import annotations

import os
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path

from ..detection import CAPTURE_FIELDS

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
except ModuleNotFoundError:  # pragma: no cover
    QProcess = QTimer = Qt = None
    QColor = None
    QComboBox = QFileDialog = QHBoxLayout = QHeaderView = QLabel = QLineEdit = QPushButton = None
    QTableWidget = QTableWidgetItem = QVBoxLayout = QWidget = None


FIELD_COUNT = 17
MAX_PACKET_ROWS = 500
PACKET_BATCH_SIZE = 50
PACKET_COLUMNS = ["Hora", "N.º", "Protocolo", "IP origen", "IP destino", "MAC origen", "MAC destino", "Información"]
DEFAULT_CAPTURE_FILTER = "arp or dns or dhcp or dhcpv6 or bootp or llmnr or nbns or mdns or icmpv6"


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


if QWidget is None:
    class TrafficViewerPanel:
        def __init__(self, monitor=None):
            raise ModuleNotFoundError("PySide6 no está instalado. Ejecuta: python -m pip install -r requirements.txt")
else:
    class TrafficViewerPanel(QWidget):
        def __init__(self, monitor=None):
            super().__init__()
            self.monitor = monitor
            self.tshark_path: str | None = None
            self._mode = "idle"
            self._stdout_buffer = ""
            self._pending_rows: list[list[str]] = []
            self._detected_alert_count = 0
            self._detection_persistence_error = False
            self.process = QProcess(self)
            self.process.readyReadStandardOutput.connect(self._read_output)
            self.process.readyReadStandardError.connect(self._read_error)
            self.process.finished.connect(self._process_finished)
            self.process.errorOccurred.connect(self._process_error)
            self._flush_timer = QTimer(self)
            self._flush_timer.setInterval(200)
            self._flush_timer.timeout.connect(self._flush_pending_rows)

            layout = QVBoxLayout(self)
            layout.setContentsMargins(22, 18, 22, 18)
            layout.setSpacing(12)
            controls = QHBoxLayout()
            controls.setSpacing(9)
            self.interface_combo = QComboBox()
            self.filter_input = QLineEdit(DEFAULT_CAPTURE_FILTER)
            self.filter_input.setPlaceholderText("Filtro de captura (ej. arp or dns)")
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
            self.packet_table.horizontalHeader().setMinimumSectionSize(72)
            self.packet_table.horizontalHeader().setStretchLastSection(True)
            self.packet_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            self.packet_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            self.packet_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            for column in range(3, 7):
                self.packet_table.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
            self.packet_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
            self.packet_table.setColumnWidth(3, 120)
            self.packet_table.setColumnWidth(4, 120)
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

        def refresh_interfaces(self) -> None:
            self.tshark_path = find_tshark()
            self.interface_combo.clear()
            if not self.tshark_path:
                self.status_label.setText(
                    "TShark no aparece en PATH ni en las rutas habituales de Wireshark. "
                    "Reinicia VS Code si acabas de modificar PATH."
                )
                self.start_button.setEnabled(False)
                return

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

        def start_capture(self) -> None:
            if self.process.state() != QProcess.ProcessState.NotRunning:
                return
            if not self.tshark_path or self.interface_combo.currentIndex() < 0:
                self.status_label.setText("Selecciona una interfaz de captura válida.")
                return

            interface_id = self.interface_combo.currentData()
            display_filter = self.filter_input.text().strip() or DEFAULT_CAPTURE_FILTER
            arguments = self._packet_arguments(display_filter)
            arguments[2:2] = ["-i", str(interface_id)]
            self._mode = "live"
            self._stdout_buffer = ""
            self._pending_rows.clear()
            self._detected_alert_count = 0
            self._detection_persistence_error = False
            self.packet_table.setRowCount(0)
            self._set_running(True)
            self.status_label.setText(f"Capturando en {self.interface_combo.currentText()} · filtro: {display_filter}")
            self.process.start(self.tshark_path, arguments)

        @staticmethod
        def _packet_arguments(display_filter: str) -> list[str]:
            arguments = ["-l", "-n"]
            if display_filter:
                arguments.extend(["-Y", display_filter])
            arguments.extend(["-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"])
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

            display_filter = self.filter_input.text().strip() or DEFAULT_CAPTURE_FILTER
            self._mode = "file"
            self._stdout_buffer = ""
            self._pending_rows.clear()
            self._detected_alert_count = 0
            self._detection_persistence_error = False
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
                alerts = self.monitor.analyze_capture_record(line)
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

        def _read_error(self) -> None:
            text = bytes(self.process.readAllStandardError()).decode("utf-8", errors="replace").strip()
            if text:
                self.status_label.setText(f"TShark: {text[-400:]}")

        def _process_finished(self, exit_code: int, _exit_status) -> None:
            self._read_output()
            self._read_error()
            if self._stdout_buffer:
                self._analyze_capture_record(self._stdout_buffer)
                row = packet_fields_to_row(self._stdout_buffer)
                if row:
                    self._pending_rows.append(row)
                self._stdout_buffer = ""
            self._set_running(False)
            if exit_code:
                self.status_label.setText(
                    f"TShark terminó con código {exit_code}; revisa los permisos o el filtro."
                    f"{self._detection_warning()}"
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

        def _process_error(self, _error) -> None:
            self._set_running(False)
            self.status_label.setText(f"No se pudo iniciar TShark: {self.process.errorString()}")

        def _set_running(self, running: bool) -> None:
            if running:
                self._flush_timer.start()
            else:
                self._flush_timer.stop()
                self._flush_pending_rows()
            self.refresh_button.setEnabled(not running)
            self.start_button.setEnabled(not running and self.interface_combo.count() > 0)
            self.stop_button.setEnabled(running and self._mode == "live")
            self.open_capture_button.setEnabled(not running)

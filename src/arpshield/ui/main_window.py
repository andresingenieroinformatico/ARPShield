from __future__ import annotations

<<<<<<< HEAD
from typing import TYPE_CHECKING
=======
import sqlite3
>>>>>>> 1fc77c61331b7cfe33e18e96de74b7c08cd541b9

from ..monitor import ThreatMonitor
from .dashboard import BACKGROUND, MUTED, PANEL, TEXT, DashboardPanel
from .traffic_viewer import TrafficViewerPanel, find_tshark

if TYPE_CHECKING:
    from PySide6.QtCore import QTimer, Qt
    from PySide6.QtWidgets import (
        QApplication,
        QComboBox,
        QFrame,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QStackedWidget,
        QVBoxLayout,
        QWidget,
    )
<<<<<<< HEAD
    _PYSIDE6_AVAILABLE = True
=======
except ModuleNotFoundError:  # pragma: no cover - dependency message handled at runtime
    QApplication = None
    QLabel = QWidget = QMainWindow = QMessageBox = QPushButton = QHBoxLayout = QVBoxLayout = None
    QFrame = QLineEdit = QStackedWidget = QTimer = QComboBox = None
    Qt = None


if QApplication is None:
    class MainWindow:
        def __init__(self, monitor: ThreatMonitor):
            raise ModuleNotFoundError("PySide6 no está instalado. Ejecuta: python -m pip install -r requirements.txt")
>>>>>>> 1fc77c61331b7cfe33e18e96de74b7c08cd541b9
else:
    try:
        from PySide6.QtCore import QTimer, Qt
        from PySide6.QtWidgets import (
            QApplication,
            QFrame,
            QHBoxLayout,
            QLabel,
            QLineEdit,
            QMainWindow,
            QMessageBox,
            QPushButton,
            QStackedWidget,
            QVBoxLayout,
            QWidget,
        )
        _PYSIDE6_AVAILABLE = True
    except ModuleNotFoundError:  # pragma: no cover - dependency message handled at runtime
        _PYSIDE6_AVAILABLE = False
        QMainWindow = object


class MainWindow(QMainWindow):
    def __init__(self, monitor: ThreatMonitor):
        if not _PYSIDE6_AVAILABLE:
            raise ModuleNotFoundError("PySide6 no está instalado. Ejecuta: python -m pip install -r requirements.txt")
        super().__init__()
        self.monitor = monitor
        self.setWindowTitle("ARPShield")
        self.resize(1240, 820)
        self.setMinimumSize(900, 620)
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{ background: {BACKGROUND}; color: {TEXT}; font-family: "Segoe UI"; }}
            QFrame#sidebar {{ background: #1d1f30; border-right: 1px solid #2a2c3e; }}
            QFrame#topbar {{ background: {BACKGROUND}; border-bottom: 1px solid #292b3d; }}
            QPushButton {{ color: {MUTED}; background: transparent; border: 0; border-radius: 6px; padding: 10px 12px; text-align: left; }}
            QPushButton:hover {{ background: #292b3e; color: {TEXT}; }}
            QPushButton#primaryAction {{ color: white; background: #258ad0; padding: 8px 12px; }}
            QPushButton#primaryAction:hover {{ background: #3498db; }}
            QLineEdit {{ background: #222436; color: {TEXT}; border: 1px solid #303246; border-radius: 6px; padding: 8px 10px; }}
        """)

        root = QWidget(self)
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(205)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(12, 14, 12, 14)
        sidebar_layout.setSpacing(8)

        brand = QLabel("◆  ARPShield")
        brand.setStyleSheet("font-size: 19px; font-weight: 700; color: #ffffff; padding: 7px 8px 22px 8px;")
        sidebar_layout.addWidget(brand)

        self.dashboard_nav = self._nav_button("◈   Dashboard", "dashboard")
        self.traffic_nav = self._nav_button("◎   Tráfico", "traffic")
        self.settings_nav = self._nav_button("⚙   Ajustes", "settings")
        sidebar_layout.addWidget(self.dashboard_nav)
        sidebar_layout.addWidget(self.traffic_nav)
        sidebar_layout.addStretch(1)
        sidebar_layout.addWidget(self.settings_nav)

        user_block = QLabel("●   Monitor local\n      ARPShield")
        user_block.setStyleSheet(f"color: {TEXT}; background: #242638; border-radius: 8px; padding: 12px 8px;")
        sidebar_layout.addWidget(user_block)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        topbar = QFrame()
        topbar.setObjectName("topbar")
        topbar.setFixedHeight(72)
        topbar_layout = QHBoxLayout(topbar)
        topbar_layout.setContentsMargins(24, 10, 22, 10)

        self.breadcrumb_label = QLabel("Dashboard  /  Resumen")
        self.breadcrumb_label.setStyleSheet(f"color: {MUTED}; font-size: 12px;")
        topbar_layout.addWidget(self.breadcrumb_label)
        topbar_layout.addStretch()

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Buscar en alertas...")
        self.search_input.setFixedWidth(220)
        self.search_input.textChanged.connect(self._filter_dashboard_alerts)
        topbar_layout.addWidget(self.search_input)

        self.status_label = QLabel("●  Monitoreo local")
        self.status_label.setStyleSheet("color: #25c878; padding: 0 10px;")
        topbar_layout.addWidget(self.status_label)

        self.scan_button = QPushButton("Escanear")
        self.scan_button.setObjectName("primaryAction")
        self.scan_button.clicked.connect(self.scan_network)
        topbar_layout.addWidget(self.scan_button)

        self.refresh_alerts_button = QPushButton("Verificar")
        self.refresh_alerts_button.clicked.connect(self.check_alerts)
        topbar_layout.addWidget(self.refresh_alerts_button)

        self.pages = QStackedWidget()
        self.dashboard_widget = DashboardPanel(monitor)
        self.traffic_widget = TrafficViewerPanel(monitor)
        self.settings_widget = self._build_settings_page()
        self.pages.addWidget(self.dashboard_widget)
        self.pages.addWidget(self.traffic_widget)
        self.pages.addWidget(self.settings_widget)

        content_layout.addWidget(topbar)
        content_layout.addWidget(self.pages, 1)

<<<<<<< HEAD
        root_layout.addWidget(sidebar)
        root_layout.addWidget(content, 1)
        self.setCentralWidget(root)

        self.dashboard_nav.clicked.connect(lambda: self._show_page(0, "Dashboard  /  Resumen"))
        self.traffic_nav.clicked.connect(lambda: self._show_page(1, "Monitor de red  /  Tráfico"))
        self.settings_nav.clicked.connect(lambda: self._show_page(2, "ARPShield  /  Ajustes"))
        self._show_page(0, "Dashboard  /  Resumen")
=======
            self.refresh_timer = QTimer(self)
            self.refresh_timer.setInterval(15000)
            self.refresh_timer.timeout.connect(self._refresh_visible_dashboard)
            self.refresh_timer.start()

        def _refresh_visible_dashboard(self) -> None:
            if self.pages.currentIndex() == 0:
                self.dashboard_widget.refresh()

        def _nav_button(self, text: str, page_name: str) -> QPushButton:
            button = QPushButton(text)
            button.setProperty("pageName", page_name)
            button.setMinimumHeight(44)
            return button
>>>>>>> 4551bfa7299551eff2751d0ecb43c9b37412521b

        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(5000)
        self.refresh_timer.timeout.connect(self.dashboard_widget.refresh)
        self.refresh_timer.start()

    def _nav_button(self, text: str, page_name: str) -> QPushButton:
        button = QPushButton(text)
        button.setProperty("pageName", page_name)
        button.setMinimumHeight(44)
        return button

    def _build_settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 26, 28, 26)
        title = QLabel("Configuración del monitor")
        title.setStyleSheet("font-size: 20px; font-weight: 700;")
        tshark_path = find_tshark() or "No detectado"
        details = QLabel(
            f"TShark: {tshark_path}\n"
            f"Base de datos: {self.monitor.database.db_path}\n\n"
            "La captura se ejecuta en el equipo local. La selección de interfaz y los filtros "
            "se configuran desde la pestaña Tráfico."
        )
        details.setWordWrap(True)
        details.setStyleSheet(f"color: {MUTED}; background: {PANEL}; padding: 18px; border-radius: 10px;")
        layout.addWidget(title)
        layout.addWidget(details)
        layout.addStretch()
        return page

    def _show_page(self, index: int, breadcrumb: str) -> None:
        self.pages.setCurrentIndex(index)
        self.breadcrumb_label.setText(breadcrumb)
        for button in (self.dashboard_nav, self.traffic_nav, self.settings_nav):
            button.setStyleSheet("")
        active_button = (self.dashboard_nav, self.traffic_nav, self.settings_nav)[index]
        active_button.setStyleSheet("background: #292b3e; color: #3498db; border-left: 3px solid #3498db;")

    def _filter_dashboard_alerts(self, query: str) -> None:
        needle = query.casefold().strip()
        table = self.dashboard_widget.alert_table
        for row in range(table.rowCount()):
            visible = not needle or any(
                (cell := table.item(row, column)) is not None and needle in cell.text().casefold()
                for column in range(table.columnCount())
            )
<<<<<<< HEAD
            table.setRowHidden(row, not visible)

<<<<<<< HEAD
    def scan_network(self) -> None:
        try:
            entries = self.monitor.refresh_baseline()
        except OSError as exc:
            QMessageBox.critical(self, "Error de escaneo", f"No se pudo actualizar la línea base:\n{exc}")
            return
        self.dashboard_widget.refresh()
        self.status_label.setText(f"●  {len(entries)} dispositivos en línea base")
=======
=======
            details.setWordWrap(True)
            details.setStyleSheet(f"color: {MUTED}; background: {PANEL}; padding: 18px; border-radius: 10px;")
            layout.addWidget(title)
            layout.addWidget(details)

            trusted_title = QLabel("Clasificar dispositivos de confianza")
            trusted_title.setStyleSheet("font-size: 15px; font-weight: 700;")
            trusted_description = QLabel(
                "Escanea la red primero y verifica de forma independiente la IP/MAC antes de asignar un rol. "
                "Los roles Gateway, DNS y DHCP alimentan las referencias de los detectores."
            )
            trusted_description.setWordWrap(True)
            trusted_description.setStyleSheet(f"color: {MUTED};")
            self.trusted_device_combo = QComboBox()
            self.trusted_role_combo = QComboBox()
            for role, label in (
                ("GATEWAY", "Gateway"),
                ("DNS_SERVER", "Servidor DNS"),
                ("DHCP_SERVER", "Servidor DHCP/DHCPv6"),
                ("KNOWN_HOST", "Equipo conocido"),
                ("OTHER", "Otro"),
            ):
                self.trusted_role_combo.addItem(label, role)
            self.save_trusted_role_button = QPushButton("Guardar rol confiable")
            self.save_trusted_role_button.setEnabled(False)
            self.save_trusted_role_button.clicked.connect(self._save_trusted_role)
            self.trusted_device_combo.currentIndexChanged.connect(self._select_trusted_device_role)
            self._refresh_trusted_devices()

            role_layout = QHBoxLayout()
            role_layout.addWidget(self.trusted_device_combo, 3)
            role_layout.addWidget(self.trusted_role_combo, 2)
            role_layout.addWidget(self.save_trusted_role_button)
            layout.addWidget(trusted_title)
            layout.addWidget(trusted_description)
            layout.addLayout(role_layout)
            layout.addStretch()
            return page

        def _refresh_trusted_devices(self) -> None:
            entries = self.monitor.database.list_baseline()
            self.trusted_device_combo.clear()
            for entry in entries:
                label = f"{entry['ip_address']}  ·  {entry['mac_address']}"
                self.trusted_device_combo.addItem(label, entry)
            self.save_trusted_role_button.setEnabled(bool(entries))
            self._select_trusted_device_role()

        def _select_trusted_device_role(self, *_args) -> None:
            entry = self.trusted_device_combo.currentData()
            if not entry:
                return
            role_index = self.trusted_role_combo.findData(entry["device_type"])
            if role_index >= 0:
                self.trusted_role_combo.setCurrentIndex(role_index)

        def _save_trusted_role(self) -> None:
            entry = self.trusted_device_combo.currentData()
            role = self.trusted_role_combo.currentData()
            if not entry or not role:
                return
            role_label = self.trusted_role_combo.currentText()
            try:
                self.monitor.database.set_baseline_device_type(entry["ip_address"], role)
                self.monitor.reload_baseline()
            except (OSError, sqlite3.Error, ValueError) as exc:
                QMessageBox.warning(self, "Línea base", f"No se pudo guardar el rol: {exc}")
                return
            self._refresh_trusted_devices()
            self._refresh_visible_dashboard()
            self.status_label.setText(f"●  Rol {role_label} guardado para {entry['ip_address']}")

>>>>>>> 1fc77c61331b7cfe33e18e96de74b7c08cd541b9
        def _show_page(self, index: int, breadcrumb: str) -> None:
            self.pages.setCurrentIndex(index)
            self.breadcrumb_label.setText(breadcrumb)
            if index == 0:
                self.dashboard_widget.refresh()
            for button in (self.dashboard_nav, self.traffic_nav, self.settings_nav):
                button.setStyleSheet("")
            active_button = (self.dashboard_nav, self.traffic_nav, self.settings_nav)[index]
            active_button.setStyleSheet("background: #292b3e; color: #3498db; border-left: 3px solid #3498db;")
>>>>>>> 4551bfa7299551eff2751d0ecb43c9b37412521b

    def check_alerts(self) -> None:
        try:
            alerts = self.monitor.check_for_anomalies()
        except OSError as exc:
            QMessageBox.critical(self, "Error de monitoreo", f"No se pudo comprobar la red:\n{exc}")
            return
        self.dashboard_widget.refresh()
        if alerts:
            self.status_label.setText(f"●  {len(alerts)} anomalías detectadas")
            QMessageBox.information(self, "ARPShield", f"Se registraron {len(alerts)} alertas de posible suplantación ARP.")
        else:
            self.status_label.setText("●  No se detectaron anomalías")

<<<<<<< HEAD
    def apply_mitigation(self) -> None:
        self.status_label.setText("●  Mitigación requiere validar el gateway y permisos administrativos")
=======
        def scan_network(self) -> None:
            try:
                entries = self.monitor.refresh_baseline()
                self._refresh_trusted_devices()
            except (OSError, sqlite3.Error) as exc:
                QMessageBox.critical(self, "Error de escaneo", f"No se pudo actualizar la línea base:\n{exc}")
                return
            self._refresh_visible_dashboard()
            self.status_label.setText(f"●  {len(entries)} dispositivos en línea base")

        def check_alerts(self) -> None:
            try:
                alerts = self.monitor.check_for_anomalies()
            except (OSError, sqlite3.Error) as exc:
                QMessageBox.critical(self, "Error de monitoreo", f"No se pudo comprobar la red:\n{exc}")
                return
            self._refresh_visible_dashboard()
            if alerts:
                self.status_label.setText(f"●  {len(alerts)} anomalías detectadas")
                QMessageBox.information(
                    self,
                    "ARPShield",
                    f"Se registraron {len(alerts)} alertas por cambios sospechosos en la tabla ARP.",
                )
            else:
                self.status_label.setText("●  No se detectaron anomalías")

        def apply_mitigation(self) -> None:
            self.status_label.setText("●  Mitigación requiere validar el gateway y permisos administrativos")
>>>>>>> 4551bfa7299551eff2751d0ecb43c9b37412521b

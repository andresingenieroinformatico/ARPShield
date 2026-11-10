from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

try:
    from PySide6.QtCore import QPointF, QRectF, Qt
    from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen, QPolygonF
    from PySide6.QtWidgets import (
        QFrame,
        QGridLayout,
        QHeaderView,
        QLabel,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )
except ModuleNotFoundError:  # pragma: no cover
    Qt = QPointF = QRectF = QColor = QFont = QPainter = QPainterPath = QPen = QPolygonF = None
    QFrame = QGridLayout = QHeaderView = QLabel = QTableWidget = QTableWidgetItem = QVBoxLayout = QWidget = None


BACKGROUND = "#171827"
PANEL = "#222436"
PANEL_ALT = "#26283b"
TEXT = "#f4f5fb"
MUTED = "#a0a4b8"
BLUE = "#3498db"
GREEN = "#25c878"
ORANGE = "#f39c12"
RED = "#e74c3c"
PURPLE = "#a45bb5"


class TrendChart(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.labels: list[str] = []
        self.values: list[int] = []
        self.setMinimumHeight(190)

    def set_data(self, labels: list[str], values: list[int]) -> None:
        self.labels = labels
        self.values = values
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor(PANEL))

        left, right, top, bottom = 38.0, 14.0, 14.0, 28.0
        chart = QRectF(left, top, max(1.0, self.width() - left - right), max(1.0, self.height() - top - bottom))
        max_value = max(self.values, default=1)
        max_value = max(max_value, 4)

        painter.setFont(QFont("Segoe UI", 8))
        for step in range(5):
            ratio = step / 4
            y = chart.bottom() - chart.height() * ratio
            painter.setPen(QPen(QColor("#34364b"), 1))
            painter.drawLine(QPointF(chart.left(), y), QPointF(chart.right(), y))
            painter.setPen(QColor(MUTED))
            painter.drawText(QRectF(0, y - 8, left - 7, 16), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, str(round(max_value * ratio)))

        if not self.values:
            painter.setPen(QColor(MUTED))
            painter.drawText(chart, Qt.AlignmentFlag.AlignCenter, "Aún no hay alertas para graficar")
            return

        count = len(self.values)
        points = []
        for index, value in enumerate(self.values):
            x = chart.left() + chart.width() * (index / max(count - 1, 1))
            y = chart.bottom() - chart.height() * (value / max_value)
            points.append(QPointF(x, y))

        area = QPainterPath()
        area.moveTo(QPointF(points[0].x(), chart.bottom()))
        for point in points:
            area.lineTo(point)
        area.lineTo(QPointF(points[-1].x(), chart.bottom()))
        area.closeSubpath()
        painter.fillPath(area, QColor(52, 152, 219, 35))

        line = QPainterPath()
        line.moveTo(points[0])
        for point in points[1:]:
            line.lineTo(point)
        painter.setPen(QPen(QColor(BLUE), 2.5))
        painter.drawPath(line)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(BLUE))
        for point in points:
            painter.drawEllipse(point, 3.2, 3.2)

        painter.setPen(QColor(MUTED))
        label_count = len(self.labels)
        for index, label in enumerate(self.labels):
            x = chart.left() + chart.width() * (index / max(label_count - 1, 1))
            painter.drawText(QRectF(x - 24, chart.bottom() + 6, 48, 18), Qt.AlignmentFlag.AlignHCenter, label)


class TypeBreakdown(QWidget):
    COLORS = [BLUE, GREEN, ORANGE, RED, PURPLE]

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.categories: list[tuple[str, int, str]] = []
        self.setMinimumHeight(190)

    def set_data(self, categories: list[tuple[str, int, str]]) -> None:
        self.categories = categories
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor(PANEL))

        total = sum(value for _name, value, _color in self.categories)
        center = QPointF(self.width() * 0.34, self.height() * 0.52)
        diameter = min(138.0, self.height() - 34.0)
        ring = QRectF(center.x() - diameter / 2, center.y() - diameter / 2, diameter, diameter)

        if total == 0:
            painter.setPen(QPen(QColor("#383a4f"), 18))
            painter.drawEllipse(ring.adjusted(10, 10, -10, -10))
        else:
            start_angle = 90 * 16
            for name, value, color in self.categories:
                span = round(360 * 16 * value / total)
                painter.setPen(QPen(QColor(color), 18))
                painter.drawArc(ring.adjusted(10, 10, -10, -10), start_angle, -span)
                start_angle -= span

        painter.setPen(QColor(TEXT))
        painter.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        painter.drawText(QRectF(center.x() - 42, center.y() - 15, 84, 26), Qt.AlignmentFlag.AlignCenter, f"{total}")
        painter.setFont(QFont("Segoe UI", 8))
        painter.setPen(QColor(MUTED))
        painter.drawText(QRectF(center.x() - 36, center.y() + 8, 72, 18), Qt.AlignmentFlag.AlignCenter, "Alertas")

        legend_x = self.width() * 0.61
        legend_y = 32.0
        painter.setFont(QFont("Segoe UI", 8))
        for name, value, color in self.categories:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(color))
            painter.drawRoundedRect(QRectF(legend_x, legend_y + 3, 10, 10), 3, 3)
            painter.setPen(QColor(MUTED))
            painter.drawText(QRectF(legend_x + 17, legend_y - 1, self.width() - legend_x - 20, 17), Qt.AlignmentFlag.AlignLeft, name)
            painter.setPen(QColor(TEXT))
            painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
            percent = round(value * 100 / total) if total else 0
            painter.drawText(QRectF(legend_x + 17, legend_y + 14, self.width() - legend_x - 20, 16), Qt.AlignmentFlag.AlignLeft, f"{value} ({percent}%)")
            painter.setFont(QFont("Segoe UI", 8))
            legend_y += 35


class DashboardPanel(QWidget):
    RECENT_ALERT_LIMIT = 100
    TREND_DAYS = 12

    def __init__(self, monitor: Any):
        super().__init__()
        self.monitor = monitor
        self.setObjectName("dashboardPanel")
        self.setStyleSheet(f"""
            QWidget#dashboardPanel {{ background: {BACKGROUND}; color: {TEXT}; }}
            QFrame#metricCard, QFrame#chartCard, QFrame#tableCard {{
                background: {PANEL}; border: 1px solid #2c2e42; border-radius: 12px;
            }}
        """)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(22, 18, 22, 18)
        main_layout.setSpacing(16)

        self.cards_layout = QGridLayout()
        self.cards_layout.setHorizontalSpacing(16)
        self.cards_layout.setVerticalSpacing(12)
        self.total_devices_label = QLabel("0")
        self.alerts_label = QLabel("0")
        self.high_severity_label = QLabel("0")
        self.baseline_label = QLabel("0")
        cards = [
            ("DISPOSITIVOS DETECTADOS", self.total_devices_label, BLUE, "◉"),
            ("ALERTAS REGISTRADAS", self.alerts_label, GREEN, "★"),
            ("RIESGO ALTO / CRÍTICO", self.high_severity_label, ORANGE, "◎"),
            ("ENTRADAS DE CONFIANZA", self.baseline_label, RED, "◆"),
        ]
        for column, (title, value, color, icon) in enumerate(cards):
            self.cards_layout.addWidget(self._build_metric_card(title, value, color, icon), 0, column)
            self.cards_layout.setColumnStretch(column, 1)

        self.trend_chart = TrendChart()
        self.type_chart = TypeBreakdown()
        self.trend_card = self._build_chart_card("Tendencia de alertas", self.trend_chart)
        self.types_card = self._build_chart_card("Clasificación de incidentes", self.type_chart)

        charts_layout = QGridLayout()
        charts_layout.setHorizontalSpacing(16)
        charts_layout.addWidget(self.trend_card, 0, 0, 1, 3)
        charts_layout.addWidget(self.types_card, 0, 3, 1, 2)
        for column in range(5):
            charts_layout.setColumnStretch(column, 3 if column < 3 else 2)

        table_frame = QFrame()
        table_frame.setObjectName("tableCard")
        table_layout = QVBoxLayout(table_frame)
        table_layout.setContentsMargins(18, 15, 18, 12)
        table_title = QLabel("Alertas recientes")
        table_title.setStyleSheet(f"font-size: 15px; font-weight: 700; color: {TEXT};")
        self.alert_table = QTableWidget(0, 6)
        self.alert_table.setHorizontalHeaderLabels(["Fecha y hora", "Tipo", "Severidad", "IP afectada", "MAC observada", "Evidencia"])
        self.alert_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.alert_table.verticalHeader().setVisible(False)
        self.alert_table.setAlternatingRowColors(True)
        self.alert_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.alert_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.alert_table.setMinimumHeight(150)
        self.alert_table.setStyleSheet(f"""
            QTableWidget {{ background: {PANEL}; alternate-background-color: {PANEL_ALT}; color: {TEXT}; gridline-color: #303246; border: 0; }}
            QHeaderView::section {{ background: {PANEL}; color: {MUTED}; padding: 9px; border: 0; border-bottom: 1px solid #34364b; font-weight: 600; }}
        """)
        table_layout.addWidget(table_title)
        table_layout.addWidget(self.alert_table)

        main_layout.addLayout(self.cards_layout)
        main_layout.addLayout(charts_layout, 1)
        main_layout.addWidget(table_frame, 1)
        self.refresh()

    @staticmethod
    def _build_metric_card(title: str, value_label: QLabel, color: str, icon: str) -> QFrame:
        card = QFrame()
        card.setObjectName("metricCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(17, 14, 17, 13)
        icon_label = QLabel(icon)
        icon_label.setFixedSize(38, 38)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setStyleSheet(f"background: {color}; color: white; border-radius: 19px; font-size: 17px; font-weight: 700;")
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {MUTED}; font-size: 9px; font-weight: 600;")
        value_label.setStyleSheet(f"color: {TEXT}; font-size: 24px; font-weight: 700;")
        layout.addWidget(icon_label)
        layout.addSpacing(3)
        layout.addWidget(value_label)
        layout.addWidget(title_label)
        return card

    @staticmethod
    def _build_chart_card(title: str, chart: QWidget) -> QFrame:
        card = QFrame()
        card.setObjectName("chartCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(17, 14, 17, 12)
        heading = QLabel(title)
        heading.setStyleSheet(f"font-size: 14px; font-weight: 700; color: {TEXT};")
        layout.addWidget(heading)
        layout.addWidget(chart, 1)
        return card

    def refresh(self) -> None:
        snapshot = self.monitor.database.dashboard_snapshot(
            recent_limit=self.RECENT_ALERT_LIMIT,
            trend_days=self.TREND_DAYS,
        )

        self.total_devices_label.setText(str(snapshot["baseline_count"]))
        self.alerts_label.setText(str(snapshot["alert_count"]))
        self.high_severity_label.setText(str(snapshot["high_severity_count"]))
        self.baseline_label.setText(str(snapshot["baseline_count"]))

        today = datetime.now(timezone.utc).date()
        dates = [today - timedelta(days=offset) for offset in range(self.TREND_DAYS - 1, -1, -1)]
        self.trend_chart.set_data(
            [date.strftime("%d %b") for date in dates],
            [snapshot["daily_counts"].get(date.isoformat(), 0) for date in dates],
        )

        type_names = {
            "GATEWAY_SPOOFING": "Suplantación gateway",
            "MULTIPLE_IPS_PER_MAC": "Múltiples IP por MAC",
            "ARP_BURST_UNSOLICITED": "Ráfaga ARP",
            "DNS_SPOOFING": "Suplantación DNS",
        }
        colors = TypeBreakdown.COLORS
        categories = [
            (type_names.get(name, name), count, colors[index % len(colors)])
            for index, (name, count) in enumerate(
                sorted(snapshot["alert_type_counts"], key=lambda item: item[1], reverse=True)[:5]
            )
            if count
        ]
        self.type_chart.set_data(categories)

        alerts = snapshot["recent_alerts"]
        self.alert_table.setRowCount(len(alerts))
        self.alert_table.setUpdatesEnabled(False)
        for row_index, alert in enumerate(alerts):
            values = [
                str(alert.get("timestamp_utc", "--")),
                str(alert.get("alert_type", "--")).replace("_", " ").title(),
                str(alert.get("severity", "LOW")),
                str(alert.get("spoofed_ip", "--")),
                str(alert.get("attacker_mac", "--")),
                str(alert.get("evidence_summary", "--")),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 2:
                    severity_colors = {"LOW": GREEN, "MEDIUM": ORANGE, "HIGH": RED, "CRITICAL": RED}
                    item.setForeground(QColor(severity_colors.get(value, MUTED)))
                self.alert_table.setItem(row_index, column, item)
        self.alert_table.setUpdatesEnabled(True)

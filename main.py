from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arpshield.config import AppSettings
from arpshield.database import DatabaseManager
from arpshield.monitor import ThreatMonitor


def main() -> int:
    try:
        from PySide6.QtWidgets import QApplication, QMessageBox
    except (ImportError, OSError) as exc:  # pragma: no cover - runtime dependency message
        raise SystemExit(
            "No se pudo cargar PySide6. Activa el entorno virtual del proyecto e instala los requisitos con: "
            "python -m pip install -r requirements.txt"
        ) from exc

    from arpshield.ui.main_window import MainWindow
    from arpshield.ui.traffic_viewer import find_tshark

    app = QApplication(sys.argv)
    app.setApplicationName("ARPShield")

    tshark_path = find_tshark()
    settings = AppSettings()

    database = DatabaseManager(settings.db_path)
    database.initialize()

    monitor = ThreatMonitor(database)

    window = MainWindow(monitor)
    window.show()

    # Si TShark no fue detectado, muestra una alerta controlada en la UI (ASVS V7.1.1)
    if not tshark_path:
        QMessageBox.warning(
            window,
            "TShark no detectado",
            "No se localizó el ejecutable de TShark en el PATH ni en 'C:\\Program Files\\Wireshark'.\n\n"
            "El monitoreo pasivo en tiempo real y el análisis PCAP no estarán disponibles hasta reiniciar la aplicación."
        )

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
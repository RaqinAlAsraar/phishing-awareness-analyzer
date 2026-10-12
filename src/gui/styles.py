"""
Dark theme stylesheet for PyQt6 GUI.
Clean, modern card-like aesthetic matching cybersecurity tools.
"""

DARK_THEME_QSS = """
QMainWindow {
    background-color: #0f172a;
    color: #f8fafc;
}

QWidget {
    background-color: #0f172a;
    color: #f8fafc;
    font-family: 'Segoe UI', -apple-system, Roboto, sans-serif;
    font-size: 13px;
}

QTabWidget::pane {
    border: 1px solid #334155;
    background-color: #1e293b;
    border-radius: 8px;
}

QTabBar::tab {
    background-color: #1e293b;
    color: #94a3b8;
    padding: 10px 18px;
    margin-right: 4px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: 600;
}

QTabBar::tab:selected {
    background-color: #3b82f6;
    color: #ffffff;
}

QTabBar::tab:hover:!selected {
    background-color: #334155;
    color: #f8fafc;
}

QGroupBox {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    margin-top: 18px;
    padding: 16px;
    font-weight: 600;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    color: #38bdf8;
}

QPushButton {
    background-color: #3b82f6;
    color: #ffffff;
    font-weight: 600;
    padding: 8px 16px;
    border-radius: 6px;
    border: none;
}

QPushButton:hover {
    background-color: #2563eb;
}

QPushButton:pressed {
    background-color: #1d4ed8;
}

QPushButton.secondary {
    background-color: #334155;
    color: #f8fafc;
}

QPushButton.secondary:hover {
    background-color: #475569;
}

QLineEdit, QPlainTextEdit, QComboBox {
    background-color: #0f172a;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 8px 10px;
    color: #f8fafc;
    selection-background-color: #3b82f6;
}

QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
    border: 1px solid #3b82f6;
}

QTableWidget {
    background-color: #0f172a;
    border: 1px solid #334155;
    border-radius: 6px;
    gridline-color: #1e293b;
    color: #f8fafc;
}

QHeaderView::section {
    background-color: #1e293b;
    color: #94a3b8;
    padding: 6px 10px;
    border: 1px solid #334155;
    font-weight: 600;
}

QTableWidget::item:selected {
    background-color: #3b82f6;
    color: #ffffff;
}

QScrollBar:vertical {
    border: none;
    background: #0f172a;
    width: 10px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background: #334155;
    min-height: 20px;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background: #475569;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
"""

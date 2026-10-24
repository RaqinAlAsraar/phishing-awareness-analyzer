"""
PyQt6 Dark Theme stylesheet based on pallete.jpg.
Primary colors: Rich Black (#021a1a), Dark Green (#032221), Caribbean Green (#00df81),
Mountain Meadow (#2cc295), Anti-Flash White (#f1f7f6), Basil (#0b453a), Pine (#06302b).
"""

DARK_THEME_QSS = """
QMainWindow {
    background-color: #021a1a;
    color: #f1f7f6;
}

QWidget {
    background-color: #021a1a;
    color: #f1f7f6;
    font-family: 'Axiforma', 'Segoe UI', -apple-system, Roboto, sans-serif;
    font-size: 13px;
}

QTabWidget::pane {
    border: 1px solid #0b453a;
    background-color: #032221;
    border-radius: 8px;
}

QTabBar::tab {
    background-color: #06302b;
    color: #aacbc4;
    padding: 9px 16px;
    margin-right: 4px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: 600;
}

QTabBar::tab:selected {
    background-color: #00df81;
    color: #021a1a;
    font-weight: 700;
}

QTabBar::tab:hover:!selected {
    background-color: #0b453a;
    color: #f1f7f6;
}

QGroupBox {
    background-color: #032221;
    border: 1px solid #0b453a;
    border-radius: 10px;
    margin-top: 18px;
    padding: 16px;
    font-weight: 600;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    color: #2cc295;
}

QPushButton {
    background-color: #00df81;
    color: #021a1a;
    font-weight: 700;
    padding: 8px 16px;
    border-radius: 6px;
    border: none;
}

QPushButton:hover {
    background-color: #2cc295;
}

QPushButton:pressed {
    background-color: #03624c;
    color: #ffffff;
}

QPushButton.secondary {
    background-color: #06302b;
    color: #f1f7f6;
    border: 1px solid #0b453a;
}

QPushButton.secondary:hover {
    background-color: #0b453a;
    border-color: #17876d;
}

QLineEdit, QPlainTextEdit, QComboBox {
    background-color: #042422;
    border: 1px solid #0b453a;
    border-radius: 6px;
    padding: 8px 10px;
    color: #f1f7f6;
    selection-background-color: #00df81;
    selection-color: #021a1a;
}

QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
    border: 1px solid #00df81;
}

QTableWidget {
    background-color: #021a1a;
    border: 1px solid #0b453a;
    border-radius: 6px;
    gridline-color: #06302b;
    color: #f1f7f6;
}

QHeaderView::section {
    background-color: #06302b;
    color: #aacbc4;
    padding: 6px 10px;
    border: 1px solid #0b453a;
    font-weight: 600;
}

QTableWidget::item:selected {
    background-color: #03624c;
    color: #ffffff;
}

QScrollBar:vertical {
    border: none;
    background: #021a1a;
    width: 10px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background: #0b453a;
    min-height: 20px;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background: #17876d;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
"""

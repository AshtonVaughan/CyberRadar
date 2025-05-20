import sys
import webbrowser
import feedparser
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QMessageBox, QHBoxLayout, QLineEdit, QComboBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPalette, QColor

GOOGLE_QUERIES = [
    "cybersecurity", "cyber security", "infosec", "data breach", "ransomware", "malware", "cyberattack", "hacking",
    "CVE", "APT", "exploit", "zero-day", "security breach", "vulnerability", "phishing", "DDoS", "cybercrime",
    "hacktivism", "threat intelligence", "bug bounty", "breach", "incident response", "penetration testing",
    "vulnerability disclosure", "CISO", "firewall", "SIEM", "SOC", "threat actor", "cyber espionage",
    "patch tuesday", "encryption", "cyber defense", "cyber risk", "IoT security", "supply chain attack", "social engineering",
    "credential stuffing", "cyber insurance", "cyber warfare", "ICS security", "critical infrastructure", "botnet",
    "zero trust", "MITRE ATT&CK", "cyber policy", "cyber regulation", "CERT", "infosec research", "rootkit", "keylogger"
]
GOOGLE_NEWS_RSS = [
    f"https://news.google.com/rss/search?q={q.replace(' ', '+')}&hl=en-US&gl=US&ceid=US:en"
    for q in GOOGLE_QUERIES
]
SECURITY_RSS_FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.securityweek.com/feed/",
    "https://threatpost.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://nakedsecurity.sophos.com/feed/",
    "https://www.schneier.com/blog/atom.xml",
    "https://krebsonsecurity.com/feed/",
    "https://cisomag.eccouncil.org/feed/",
    "https://www.cyberscoop.com/feed/",
    "https://www.bankinfosecurity.com/rss.xml",
    "https://www.infosecurity-magazine.com/rss/news/",
    "https://www.zdnet.com/topic/security/rss.xml",
    "https://securityaffairs.com/feed",
    "https://blog.talosintelligence.com/rss/"
]
ALL_FEEDS = GOOGLE_NEWS_RSS + SECURITY_RSS_FEEDS

def set_dark_theme(app):
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.ColorRole.Window, QColor(30, 34, 45))
    dark_palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
    dark_palette.setColor(QPalette.ColorRole.Base, QColor(22, 25, 33))
    dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(37, 41, 52))
    dark_palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
    dark_palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.black)
    dark_palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
    dark_palette.setColor(QPalette.ColorRole.Button, QColor(50, 54, 65))
    dark_palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
    dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(44, 115, 210))
    dark_palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.white)
    app.setPalette(dark_palette)
    app.setStyleSheet("""
        QLabel, QLineEdit, QComboBox, QPushButton {
            font-family: 'Segoe UI', 'Arial', sans-serif;
            font-size: 16px;
        }
        QListWidget {
            font-size: 16px;
            alternate-background-color: #252936;
            background: #1e222d;
            color: #fff;
        }
        QPushButton {
            padding: 8px 18px;
            background: #234178;
            border: none;
            color: #fff;
            border-radius: 7px;
        }
        QPushButton:pressed {
            background: #3767b0;
        }
        QLineEdit, QComboBox {
            background: #252936;
            border-radius: 5px;
            padding: 6px 9px;
            color: #fff;
            border: 1px solid #314268;
        }
        QListWidget::item:selected {
            background: #2a82da;
            color: #fff;
        }
    """)

def fetch_from_rss(url):
    try:
        feed = feedparser.parse(url)
        news_list = []
        for entry in feed.entries:
            title = entry.title
            link = entry.link
            source = entry.get("source", {}).get("title", "") or feed.feed.get('title', 'Various')
            summary = entry.summary if 'summary' in entry else entry.get('description', '')
            published = entry.get('published', '')
            news_list.append({
                "source": source,
                "title": title,
                "url": link,
                "summary": summary,
                "published": published
            })
        return news_list
    except Exception:
        return []

def fetch_all_news_fast(limit=500):
    seen_links = set()
    results = []

    def handle_news(news):
        for item in news:
            if item['url'] not in seen_links:
                seen_links.add(item['url'])
                results.append(item)
                if len(results) >= limit:
                    return True
        return False

    with ThreadPoolExecutor(max_workers=32) as executor:
        future_to_url = {executor.submit(fetch_from_rss, url): url for url in ALL_FEEDS}
        for future in as_completed(future_to_url):
            try:
                news = future.result()
                if handle_news(news):
                    break
            except Exception:
                pass
    return results

class NewsApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberRadar – Real-Time Cybersecurity News & Search")
        self.setGeometry(100, 60, 1300, 800)
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        title = QLabel("🛡️ CyberRadar – Real-Time Cybersecurity News & Search")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 32px; font-weight: bold; margin-bottom: 18px; color: #37a5fc;")
        self.layout.addWidget(title)

        # Controls
        control_layout = QHBoxLayout()
        self.refresh_button = QPushButton("🔄 Refresh")
        self.refresh_button.clicked.connect(self.fetch_and_show_news)
        control_layout.addWidget(self.refresh_button)

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search: e.g. ransomware, CVE-2024, Microsoft...")
        self.search_box.textChanged.connect(self.filter_news)
        control_layout.addWidget(self.search_box)

        self.source_filter = QComboBox()
        self.source_filter.addItem("All")
        self.source_filter.currentTextChanged.connect(self.filter_news)
        control_layout.addWidget(self.source_filter)

        self.layout.addLayout(control_layout)

        # News list
        self.news_list = QListWidget()
        self.news_list.setStyleSheet("alternate-background-color: #242734; background: #181a23;")
        self.news_list.setAlternatingRowColors(True)
        self.layout.addWidget(self.news_list)

        # Status
        self.status = QLabel("Welcome to CyberRadar! Click 'Refresh' for the latest global cybersecurity news.")
        self.status.setStyleSheet("color: #88aaff; font-size:15px;")
        self.layout.addWidget(self.status)

        # Data
        self.articles = []
        self.filtered_articles = []
        self.news_list.itemClicked.connect(self.open_article)

        self.fetch_and_show_news()

    def fetch_and_show_news(self):
        self.status.setText("Fetching latest cybersecurity news... Please wait.")
        self.refresh_button.setEnabled(False)
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        def fetch_thread():
            news = fetch_all_news_fast(limit=700)
            self.articles = news[:700]
            self.filtered_articles = self.articles
            self.show_news(self.articles)
            self.update_source_filter()
            self.status.setText(f"Fetched {len(self.articles)} headlines. Use search or source filter.")
            self.refresh_button.setEnabled(True)
            QApplication.restoreOverrideCursor()
        import threading
        threading.Thread(target=fetch_thread, daemon=True).start()

    def show_news(self, articles):
        self.news_list.clear()
        for i, item in enumerate(articles):
            published = f" | {item['published'][:16]}" if item['published'] else ""
            entry = f"{item['title']}  |  Source: {item['source']}{published}"
            list_item = QListWidgetItem(entry)
            if item['summary']:
                list_item.setToolTip(item['summary'])
            self.news_list.addItem(list_item)

    def open_article(self, item):
        idx = self.news_list.currentRow()
        url = self.filtered_articles[idx]['url']
        if url:
            webbrowser.open(url)
        else:
            QMessageBox.warning(self, "No URL", "No URL found for this article.")

    def filter_news(self):
        keyword = self.search_box.text().strip().lower()
        source = self.source_filter.currentText()
        if not keyword and (source == "All" or not source):
            self.filtered_articles = self.articles
        else:
            filtered = self.articles
            if keyword:
                filtered = [a for a in filtered if keyword in a['title'].lower() or keyword in a['summary'].lower()]
            if source != "All":
                filtered = [a for a in filtered if a['source'] == source]
            self.filtered_articles = filtered
        self.show_news(self.filtered_articles)
        self.status.setText(f"Showing {len(self.filtered_articles)} results (Filter: '{keyword}', Source: {source})")

    def update_source_filter(self):
        sources = ["All"] + sorted(set([a["source"] for a in self.articles if a["source"]]))
        current = self.source_filter.currentText()
        self.source_filter.blockSignals(True)
        self.source_filter.clear()
        self.source_filter.addItems(sources)
        if current in sources:
            self.source_filter.setCurrentText(current)
        self.source_filter.blockSignals(False)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    set_dark_theme(app)
    window = NewsApp()
    window.show()
    sys.exit(app.exec())

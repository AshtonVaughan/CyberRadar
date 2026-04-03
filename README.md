> **Archived** - This project is no longer maintained. It's preserved here as a record of a past build. What it led to: a much deeper interest in security tooling that eventually became [ProjectTriage](https://github.com/AshtonVaughan/ProjectTriage).

---

# CyberRadar

**Real-time cybersecurity news aggregator and local archive**

CyberRadar pulls from dozens of security RSS feeds and Google News queries, deduplicates stories, and archives everything to a local SQLite database. The PyQt6 interface lets you search and filter your full history of cyber news instantly.

Built in 2024 as a personal threat intel dashboard.

---

## Features

- Continuous background fetching across 15+ security feeds and Google News
- Instant search by keyword, source, and date
- Local SQLite archive - your own private history of the cyber news landscape
- No duplicates - deduplication runs on every fetch cycle
- Click any headline to open the full story in your browser
- Cross-platform PyQt6 interface

---

## Getting Started

### Requirements

- Python 3.8+
- PyQt6, feedparser, requests

```bash
pip install PyQt6 feedparser requests
```

### Run

```bash
git clone https://github.com/AshtonVaughan/CyberRadar.git
cd CyberRadar
python main.py
```

The app starts fetching immediately. All articles are stored in a local `cyberradar.db` SQLite file in the project directory.

---

## License

MIT

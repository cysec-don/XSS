# SpectreLab - XSS Playground

> An intentionally vulnerable web application for learning Cross-Site Scripting (XSS) through hands-on practice — with **5 difficulty levels**, **database reset**, **progress tracking**, and **social media sharing**.

**Author:** Cysec Don ([cysecdon@gmail.com](mailto:cysecdon@gmail.com))

---

## ⚠️ DISCLAIMER

**This application is INTENTIONALLY VULNERABLE.** It is designed for educational purposes only. DO NOT deploy this application on a public-facing server or any network accessible by unauthorized users. Use only in isolated, local environments for security training and research.

---

## What's New in v2.0

### 👻 Renamed to SpectreLab

The lab is now **SpectreLab** — because XSS attacks are like ghosts: invisible, persistent, and they haunt your application. New ghost-themed branding with a 👻 logo.

### 🎚️ 5 Difficulty Levels Per XSS Type

Every vulnerability type has 5 progressive difficulty levels:

| Level | Name | What It Means |
|-------|------|---------------|
| **L1** | 😊 Easy | No filtering. Raw injection. Just type and win. |
| **L2** | 🤔 Medium | Basic keyword/tag blocking. Find an alternative vector. |
| **L3** | 😰 Hard | Multiple filters applied. Think outside the attribute. |
| **L4** | 🔥 Expert | Aggressive sanitization or context-switching. Exploit edge cases. |
| **L5** | 💀 Insane | Full CSP + strict sanitization. Only advanced bypasses work. |

### 🗑️ Database Reset

Reset button in the navbar clears all comments and profiles instantly.

### 📤 Share Progress to Social Media

Beat a level? Share your achievement directly to:
- **X (Twitter)** — Tweet your conquest
- **LinkedIn** — Show your cybersecurity skills to your network
- **Facebook** — Share with friends
- **Reddit** — Post to r/cybersecurity or r/netsec
- **WhatsApp** — Share to your study group
- **Telegram** — Send to your infosec channel
- **Copy Link** — Copy your progress text to clipboard

### 🏆 Progress Dashboard

A dedicated `/progress` page shows:
- Overall completion bar (0/15 levels)
- Per-type breakdown with level status
- Quick-share buttons for each level
- Reset progress option

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
git clone https://github.com/cysec-don/XSS.git
cd XSS
docker compose up -d

# SpectreLab is now running at http://localhost:3001
```

### Option 2: Node.js (Local)

```bash
git clone https://github.com/cysec-don/XSS.git
cd XSS
npm install
npm start
```

---

## Application Structure

```
XSS/
├── server.js              # Express server with levels + social sharing
├── package.json           # Node.js project config
├── public/
│   └── css/
│       └── style.css      # Dark theme + level UI + share buttons
├── Dockerfile             # Docker build (renamed to spectrelab)
├── docker-compose.yml     # Docker Compose deployment
├── .dockerignore
├── .gitignore
├── LICENSE
└── README.md
```

---

## Difficulty Levels — Detailed Breakdown

### 🔍 Reflected XSS (Search Page)

| Level | Name | Defense | How to Bypass |
|-------|------|---------|---------------|
| L1 | 😊 Easy | No filtering | `<script>alert(1)</script>` |
| L2 | 🤔 Medium | "script" keyword blocked | `<img src=x onerror=alert(1)>` |
| L3 | 😰 Hard | All `on*` event handlers stripped | `<a href="javascript:alert(1)">` or `<iframe srcdoc>` |
| L4 | 🔥 Expert | Angle brackets encoded; input also in JS string | Break out of JS string: `';alert(1);//` |
| L5 | 💀 Insane | CSP + encoded brackets + JS escaped | JSONP endpoint: `/api/callback?cb=alert//` |

### 💬 Stored XSS (Comments Page)

| Level | Name | Defense | How to Bypass |
|-------|------|---------|---------------|
| L1 | 😊 Easy | No sanitization | `<script>alert(1)</script>` |
| L2 | 🤔 Medium | `<script>` stripped | `<img onerror=...>` |
| L3 | 😰 Hard | `<script>` + `on*` stripped | `<iframe srcdoc='...'>` |
| L4 | 🔥 Expert | DOMPurify-lite | `<svg onload=...>` |
| L5 | 💀 Insane | Full DOMPurify + CSP | mXSS / script gadgets |

### 🎯 DOM-Based XSS (Profile Page)

| Level | Name | Defense | How to Bypass |
|-------|------|---------|---------------|
| L1 | 😊 Easy | `innerHTML` — no filter | `#<img src=x onerror=...>` |
| L2 | 🤔 Medium | Script + on* stripped before innerHTML | `#<a href="javascript:...">` |
| L3 | 😰 Hard | Angle brackets encoded (broken SVG exception) | `#<svg onload=...>` |
| L4 | 🔥 Expert | `textContent` + `eval(calc:...)` | `#calc:alert(1)` |
| L5 | 💀 Insane | CSP + textContent + postMessage no origin check | Send postMessage from another origin |

---

## Social Media Sharing

### How It Works

1. Beat a level by successfully executing an XSS payload
2. Click **"✅ Mark Completed"** in the level selector
3. Click **"📤 Share Progress"** to reveal social media buttons
4. Choose your platform — a pre-filled post opens with your achievement
5. Alternatively, visit the **🏆 Progress** page to see all your completions and share from there

### Share Text Format

```
🔍 SpectreLab | I conquered Reflected XSS Level 3: Hard! 🚀

Can you beat it? 👉 https://github.com/cysec-don/XSS

#SpectreLab #XSS #Cybersecurity #InfoSec #WebSecurity #EthicalHacking
```

### Supported Platforms

| Platform | Share Method | Hashtag Support |
|----------|-------------|-----------------|
| X (Twitter) | Intent URL with pre-filled text | ✅ |
| LinkedIn | Share-offsite URL with summary | ✅ |
| Facebook | Sharer dialog with quote | ✅ |
| Reddit | Submit with title | ✅ |
| WhatsApp | wa.me with pre-filled text | ✅ |
| Telegram | t.me share URL with text | ✅ |
| Copy Link | Clipboard API with toast notification | ✅ |

---

## Progress Tracking

Progress is tracked in your browser's localStorage (no server-side tracking). This means:

- Your progress persists across page refreshes
- Progress is per-browser (not per-account)
- Clear your browser data to reset progress
- Or use the "Reset Progress" button on the Progress page

---

## Vulnerable Pages

| Page | URL | XSS Type |
|------|-----|----------|
| Search | `/?level=1` | Reflected XSS |
| Comments | `/comments?level=1` | Stored XSS |
| Profile | `/profile/user1?level=1` | DOM-Based XSS |
| Admin | `/admin` | Privilege Escalation |
| Progress | `/progress` | Progress Dashboard |

---

## Technical Details

### Ports

| Service | Port |
|---------|------|
| SpectreLab | 3001 |
| BeEF (optional) | 3000 |

### Special Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/reset` | POST — Clear all data |
| `/progress` | Progress dashboard |
| `/api/callback?cb=FN` | JSONP endpoint (Reflected L5) |
| `/dom-widget.html` | Widget iframe (DOM L5) |

---

## Troubleshooting

### Port already in use
```bash
PORT=8080 npm start
# Or: docker run -d -p 8080:3001 --name spectrelab spectrelab-xss
```

### Progress not showing
Progress uses localStorage. Make sure your browser allows it and you're not in private/incognito mode.

---

## License

MIT License — See [LICENSE](LICENSE) for details.

---

## Author

**Cysec Don**
Email: [cysecdon@gmail.com](mailto:cysecdon@gmail.com)
GitHub: [https://github.com/cysec-don](https://github.com/cysec-don)

---

*Like a spectre, XSS is invisible until it strikes. Learn to see it coming.*

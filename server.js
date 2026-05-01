/**
 * VulnLab - Intentionally Vulnerable XSS Playground
 * Author: Cysec Don (cysecdon@gmail.com)
 *
 * ⚠️  WARNING: This application is INTENTIONALLY VULNERABLE.
 *    DO NOT deploy this on a public-facing server.
 *    This is for educational purposes ONLY.
 */

const express = require('express');
const app = express();
const path = require('path');

// VULNERABLE: No security headers - no CSP, no X-Content-Type-Options, etc.
// In production, these should be set to harden the application.

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// In-memory data store (resets on server restart)
const comments = [];
const profiles = {
  admin: { name: 'Admin', bio: 'System Administrator', role: 'admin' },
  user1: { name: 'Alice', bio: 'Normal user', role: 'user' }
};

// =============================================
//  ROUTES
// =============================================

// --- HOME / SEARCH PAGE (Reflected XSS) ---
app.get('/', (req, res) => {
  const query = req.query.q || '';
  // VULNERABLE: query is inserted directly into HTML without encoding
  res.send(renderSearchPage(query));
});

// --- COMMENTS PAGE (Stored XSS) ---
app.get('/comments', (req, res) => {
  res.send(renderCommentsPage());
});

app.post('/comments', (req, res) => {
  // VULNERABLE: No input validation or sanitization
  comments.push({
    author: req.body.author || 'Anonymous',
    text: req.body.text,
    date: new Date().toLocaleString()
  });
  res.redirect('/comments');
});

// --- PROFILE PAGE (Stored + DOM XSS) ---
app.get('/profile/:username', (req, res) => {
  const profile = profiles[req.params.username] || profiles.user1;
  // VULNERABLE: Profile bio is reflected without encoding (Stored XSS via bio update)
  res.send(renderProfilePage(profile, req.params.username));
});

// --- UPDATE PROFILE (enables Stored XSS via bio) ---
app.post('/profile/:username', (req, res) => {
  const profile = profiles[req.params.username];
  if (profile) {
    // VULNERABLE: Bio is updated without any sanitization
    profile.bio = req.body.bio || profile.bio;
    profile.name = req.body.name || profile.name;
  }
  res.redirect('/profile/' + req.params.username);
});

// --- ADMIN DASHBOARD (Privilege Escalation via XSS) ---
app.get('/admin', (req, res) => {
  // VULNERABLE: Admin dashboard displays user comments without encoding
  res.send(renderAdminPage());
});

// --- API ENDPOINT (for challenge mode - JSON response) ---
app.get('/api/search', (req, res) => {
  const query = req.query.q || '';
  // VULNERABLE: No Content-Type header enforcement, could be sniffed as HTML
  res.json({ query: query, results: ['Result 1', 'Result 2'] });
});

// =============================================
//  TEMPLATE RENDERERS
// =============================================

function renderLayout(title, content, extraHead = '') {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} - VulnLab</title>
  <link rel="stylesheet" href="/css/style.css">
  ${extraHead}
</head>
<body>
  <nav class="navbar">
    <div class="nav-brand">
      <span class="logo">&#9888;</span> VulnLab
    </div>
    <div class="nav-links">
      <a href="/">Search</a>
      <a href="/comments">Comments</a>
      <a href="/profile/user1">Profile</a>
      <a href="/admin">Admin</a>
    </div>
  </nav>
  <main class="container">
    ${content}
  </main>
  <footer class="footer">
    <p>VulnLab XSS Playground | For Educational Purposes Only | By Cysec Don</p>
  </footer>
</body>
</html>`;
}

function renderSearchPage(query) {
  // VULNERABLE: query is inserted directly into HTML without encoding
  // Exploit: ?q=<script>alert(document.cookie)</script>
  const content = `
    <div class="page-header">
      <h1>Search</h1>
      <p class="subtitle">Find anything... and maybe inject something too.</p>
    </div>
    <form class="search-form" method="GET" action="/">
      <input type="text" name="q" value="${query}" placeholder="Search for something..." class="search-input" autofocus>
      <button type="submit" class="btn btn-primary">Search</button>
    </form>
    <div class="search-results">
      ${query ? `
        <h2>Search results for: ${query}</h2>
        <p class="muted">No results found. But your query was rendered beautifully.</p>
      ` : `
        <p class="muted">Try searching for something... or try &lt;script&gt;alert(1)&lt;/script&gt;</p>
      `}
    </div>
    <div class="hint-box">
      <strong>Vulnerability:</strong> Reflected XSS &mdash;
      The search query is reflected in the HTML response without any encoding or sanitization.
      Try injecting HTML or JavaScript through the search parameter.
    </div>`;
  return renderLayout('Search', content);
}

function renderCommentsPage() {
  // VULNERABLE: Comment text and author are inserted without encoding
  // Exploit: Post a comment with <script>alert(1)</script>
  let commentHTML = comments.map(c =>
    // VULNERABLE LINE: c.text and c.author are NOT encoded
    `<div class="comment">
      <div class="comment-header">
        <strong>${c.author}</strong>
        <small>${c.date}</small>
      </div>
      <div class="comment-body">${c.text}</div>
    </div>`
  ).join('');

  if (comments.length === 0) {
    commentHTML = '<p class="muted">No comments yet. Be the first to inject something!</p>';
  }

  const content = `
    <div class="page-header">
      <h1>Comments</h1>
      <p class="subtitle">Share your thoughts... or your scripts.</p>
    </div>
    <div class="comment-form-card">
      <h3>Post a Comment</h3>
      <form class="comment-form" method="POST" action="/comments">
        <input type="text" name="author" placeholder="Your name" class="input-field">
        <textarea name="text" placeholder="Your comment (HTML is \"allowed\"...)" class="input-field textarea-field" rows="4"></textarea>
        <button type="submit" class="btn btn-primary">Post Comment</button>
      </form>
    </div>
    <div class="comments-list">
      <h3>All Comments</h3>
      ${commentHTML}
    </div>
    <div class="hint-box">
      <strong>Vulnerability:</strong> Stored XSS &mdash;
      Comments are stored in the database and displayed to all users without encoding.
      Any HTML/JavaScript you post will execute for every visitor who views the comments page.
    </div>`;
  return renderLayout('Comments', content);
}

function renderProfilePage(profile, username) {
  // VULNERABLE: Profile bio is inserted without encoding (Stored XSS)
  // Also VULNERABLE: JS reads URL hash and sets innerHTML (DOM XSS)
  // DOM XSS Exploit: /profile/user1#<img src=x onerror=alert(1)>
  const content = `
    <div class="page-header">
      <h1>Profile: ${profile.name}</h1>
      <p class="subtitle">@${username} &bull; Role: ${profile.role}</p>
    </div>
    <div class="profile-card">
      <div class="profile-avatar">${profile.name.charAt(0).toUpperCase()}</div>
      <div class="profile-info">
        <h2>${profile.name}</h2>
        <p class="profile-bio">${profile.bio}</p>
        <span class="badge badge-${profile.role}">${profile.role}</span>
      </div>
    </div>
    <div class="edit-profile-card">
      <h3>Edit Profile</h3>
      <form class="edit-form" method="POST" action="/profile/${username}">
        <label>Name</label>
        <input type="text" name="name" value="${profile.name}" class="input-field">
        <label>Bio</label>
        <textarea name="bio" class="input-field textarea-field" rows="3">${profile.bio}</textarea>
        <button type="submit" class="btn btn-primary">Update Profile</button>
      </form>
    </div>
    <div id="dynamic-content" class="dynamic-content"></div>
    <div class="hint-box">
      <strong>Vulnerability 1:</strong> Stored XSS &mdash;
      The bio field is stored and rendered without encoding. Inject HTML/JS through the bio field.
      <br>
      <strong>Vulnerability 2:</strong> DOM-Based XSS &mdash;
      The JavaScript on this page reads the URL hash fragment and sets it as innerHTML.
      Try: /profile/user1#&lt;img src=x onerror=alert(1)&gt;
    </div>
    <script>
      // VULNERABLE: DOM-based XSS via hash fragment
      // Source: window.location.hash (attacker-controllable)
      // Sink: innerHTML (allows HTML injection)
      var hash = window.location.hash.substring(1);
      if (hash) {
        document.getElementById('dynamic-content').innerHTML = decodeURIComponent(hash);
      }
    </script>`;
  return renderLayout('Profile', content);
}

function renderAdminPage() {
  // VULNERABLE: Admin dashboard displays user comments without encoding
  // This means Stored XSS in comments escalates to admin context
  let commentRows = comments.map(c =>
    // VULNERABLE LINE: c.text and c.author are NOT encoded
    `<tr>
      <td>${c.author}</td>
      <td>${c.text}</td>
      <td>${c.date}</td>
    </tr>`
  ).join('');

  if (comments.length === 0) {
    commentRows = '<tr><td colspan="3" class="muted">No comments in the system yet.</td></tr>';
  }

  const content = `
    <div class="page-header">
      <h1>Admin Dashboard</h1>
      <p class="subtitle">All your base are belong to... whoever injected that script.</p>
    </div>
    <div class="admin-stats">
      <div class="stat-card">
        <span class="stat-number">${comments.length}</span>
        <span class="stat-label">Comments</span>
      </div>
      <div class="stat-card">
        <span class="stat-number">2</span>
        <span class="stat-label">Users</span>
      </div>
      <div class="stat-card">
        <span class="stat-number">0</span>
        <span class="stat-label">Reports</span>
      </div>
    </div>
    <div class="secret-token">
      <!-- Hidden element with admin secret token -->
      <div id="admin-secret" style="display:none">ADMIN_SECRET_TOKEN_xyz789</div>
    </div>
    <div class="admin-table-card">
      <h3>User Comments</h3>
      <table class="admin-table">
        <thead>
          <tr>
            <th>Author</th>
            <th>Comment</th>
            <th>Date</th>
          </tr>
        </thead>
        <tbody>
          ${commentRows}
        </tbody>
      </table>
    </div>
    <div class="hint-box">
      <strong>Vulnerability:</strong> Privilege Escalation via Stored XSS &mdash;
      The admin dashboard displays user-submitted comments without encoding.
      A stored XSS payload injected via the comments page will execute in the admin's browser context,
      potentially allowing access to the hidden admin secret token.
    </div>`;
  return renderLayout('Admin', content);
}

// =============================================
//  START SERVER
// =============================================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════════════╗
  ║   VulnLab XSS Playground                    ║
  ║   Running on http://localhost:${PORT}           ║
  ║                                              ║
  ║   WARNING: This app is INTENTIONALLY         ║
  ║   VULNERABLE. Do NOT expose to the internet. ║
  ╚══════════════════════════════════════════════╝
  `);
});

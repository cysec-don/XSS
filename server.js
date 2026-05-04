/**
 * VulnLab - Intentionally Vulnerable XSS Playground
 * Author: Cysec Don (cysecdon@gmail.com)
 *
 * WARNING: This application is INTENTIONALLY VULNERABLE.
 *   DO NOT deploy this on a public-facing server.
 *   This is for educational purposes ONLY.
 */

const express = require('express');
const app = express();
const path = require('path');

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// =============================================
//  DATA STORE
// =============================================
const comments = [];
const defaultProfiles = {
  admin: { name: 'Admin', bio: 'System Administrator', role: 'admin' },
  user1: { name: 'Alice', bio: 'Normal user', role: 'user' }
};
const profiles = {
  admin: { name: 'Admin', bio: 'System Administrator', role: 'admin' },
  user1: { name: 'Alice', bio: 'Normal user', role: 'user' }
};

// =============================================
//  LEVEL DEFINITIONS
// =============================================
const LEVELS = {
  reflected: {
    1: { name: 'Easy',      icon: '\u{1F60A}', color: '#6ab282', desc: 'No filtering. Raw injection. Just type and win.' },
    2: { name: 'Medium',    icon: '\u{1F914}', color: '#c0a56f', desc: 'The word "script" is blocked (case-insensitive). Try something else.' },
    3: { name: 'Hard',      icon: '\u{1F630}', color: '#e08855', desc: 'All event handler attributes (on*) are stripped. Think outside the attribute.' },
    4: { name: 'Expert',    icon: '\u{1F525}', color: '#d45555', desc: 'Angle brackets are HTML-encoded, but your input also appears inside a JS string. Break out of context.' },
    5: { name: 'Insane',    icon: '\u{1F480}', color: '#b44fd4', desc: 'Strict CSP (script-src self), angle brackets encoded, JS context escaped. Only a CSP bypass with a trusted JSONP endpoint will save you.' }
  },
  stored: {
    1: { name: 'Easy',      icon: '\u{1F60A}', color: '#6ab282', desc: 'No sanitization. Store whatever you want. It will render for everyone.' },
    2: { name: 'Medium',    icon: '\u{1F914}', color: '#c0a56f', desc: '<script> tags are stripped. But there are other ways to execute JS...' },
    3: { name: 'Hard',      icon: '\u{1F630}', color: '#e08855', desc: 'All <script> and event handler on* attributes are stripped. Get creative with HTML elements.' },
    4: { name: 'Expert',    icon: '\u{1F525}', color: '#d45555', desc: 'DOMPurify-lite strips dangerous tags and attributes. But it misses some edge cases...' },
    5: { name: 'Insane',    icon: '\u{1F480}', color: '#b44fd4', desc: 'Full DOMPurify sanitization + CSP header. Only mutation XSS (mXSS) or script gadgets can bypass this.' }
  },
  dom: {
    1: { name: 'Easy',      icon: '\u{1F60A}', color: '#6ab282', desc: 'innerHTML with the hash fragment. Direct injection. No filter.' },
    2: { name: 'Medium',    icon: '\u{1F914}', color: '#c0a56f', desc: 'The hash is filtered: <script> and on* attributes are removed before innerHTML assignment.' },
    3: { name: 'Hard',      icon: '\u{1F630}', color: '#e08855', desc: 'The hash goes through a "sanitizer" that HTML-encodes angle brackets. But the sanitizer has a bug with SVG...' },
    4: { name: 'Expert',    icon: '\u{1F525}', color: '#d45555', desc: 'innerText is used instead of innerHTML. But there is also an eval() somewhere on the page that processes the hash...' },
    5: { name: 'Insane',    icon: '\u{1F480}', color: '#b44fd4', desc: 'Strict CSP + textContent + no eval. The only way in is through a trusted iframe that reads postMessage from the hash.' }
  }
};

function getLevelInfo(type, level) {
  level = parseInt(level) || 1;
  if (level < 1) level = 1;
  if (level > 5) level = 5;
  const info = LEVELS[type][level];
  return { level, ...info };
}

// =============================================
//  SANITIZATION / FILTER FUNCTIONS
// =============================================

// Strip <script> tags (case-insensitive, greedy)
function stripScriptTags(str) {
  return str.replace(/<script[\s\S]*?<\/script\s*>/gi, '');
}

// Strip all on* event handler attributes
function stripEventHandlers(str) {
  return str.replace(/\s+on\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]*)/gi, '');
}

// HTML-encode angle brackets
function encodeAngleBrackets(str) {
  return str.replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Escape for JS string context (single-quoted)
function escapeForJSString(str) {
  return str.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"');
}

// DOMPurify-lite: strip script, on* handlers, javascript: URLs, and dangerous tags
function domPurifyLite(str) {
  let s = str;
  // Strip script tags
  s = s.replace(/<script[\s\S]*?<\/script\s*>/gi, '');
  // Strip event handlers
  s = s.replace(/\s+on\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]*)/gi, '');
  // Strip javascript: URLs
  s = s.replace(/javascript\s*:/gi, '');
  // Strip dangerous tags: iframe, object, embed, form, base
  s = s.replace(/<\/?(iframe|object|embed|form|base)[^>]*>/gi, '');
  return s;
}

// Full DOMPurify simulation (very aggressive)
function domPurifyFull(str) {
  let s = domPurifyLite(str);
  // Also strip svg (mutation XSS vector)
  s = s.replace(/<\/?svg[^>]*>/gi, '');
  // Strip math tags
  s = s.replace(/<\/?math[^>]*>/gi, '');
  // Strip details/marquee
  s = s.replace(/<\/?(details|marquee|isindex)[^>]*>/gi, '');
  // Strip data: URLs
  s = s.replace(/data\s*:/gi, '');
  // Strip vbscript:
  s = s.replace(/vbscript\s*:/gi, '');
  return s;
}

// =============================================
//  ROUTES
// =============================================

// --- RESET DATABASE ---
app.post('/reset', (req, res) => {
  comments.length = 0;
  profiles.admin = { ...defaultProfiles.admin };
  profiles.user1 = { ...defaultProfiles.user1 };
  res.redirect(req.headers.referer || '/');
});

// --- HOME / SEARCH PAGE (Reflected XSS) ---
app.get('/', (req, res) => {
  const query = req.query.q || '';
  const level = parseInt(req.query.level) || 1;
  res.send(renderSearchPage(query, level));
});

// --- COMMENTS PAGE (Stored XSS) ---
app.get('/comments', (req, res) => {
  const level = parseInt(req.query.level) || 1;
  res.send(renderCommentsPage(level));
});

app.post('/comments', (req, res) => {
  const level = parseInt(req.body.level) || 1;
  let author = req.body.author || 'Anonymous';
  let text = req.body.text || '';

  // Apply stored XSS filters based on level
  switch (level) {
    case 2:
      text = stripScriptTags(text);
      author = stripScriptTags(author);
      break;
    case 3:
      text = stripScriptTags(text);
      text = stripEventHandlers(text);
      author = stripScriptTags(author);
      break;
    case 4:
      text = domPurifyLite(text);
      author = domPurifyLite(author);
      break;
    case 5:
      text = domPurifyFull(text);
      author = domPurifyFull(author);
      break;
  }

  comments.push({ author, text, date: new Date().toLocaleString(), level });
  res.redirect('/comments?level=' + level);
});

// --- PROFILE PAGE (DOM-Based XSS) ---
app.get('/profile/:username', (req, res) => {
  const profile = profiles[req.params.username] || profiles.user1;
  const level = parseInt(req.query.level) || 1;
  res.send(renderProfilePage(profile, req.params.username, level));
});

// --- UPDATE PROFILE (Stored XSS via bio) ---
app.post('/profile/:username', (req, res) => {
  const level = parseInt(req.body.level) || 1;
  const profile = profiles[req.params.username];
  if (profile) {
    profile.bio = req.body.bio || profile.bio;
    profile.name = req.body.name || profile.name;
  }
  res.redirect('/profile/' + req.params.username + '?level=' + level);
});

// --- ADMIN DASHBOARD ---
app.get('/admin', (req, res) => {
  res.send(renderAdminPage());
});

// --- JSONP ENDPOINT (for CSP bypass in reflected level 5) ---
app.get('/api/callback', (req, res) => {
  const cb = req.query.cb || 'callback';
  // VULNERABLE: JSONP endpoint allows arbitrary callback names
  // This is the "trusted" endpoint that CSP allows via 'self'
  res.type('application/javascript');
  res.send(`${cb}({data:"JSONP response",user:"guest"})`);
});

// --- API SEARCH ---
app.get('/api/search', (req, res) => {
  const query = req.query.q || '';
  res.json({ query: query, results: ['Result 1', 'Result 2'] });
});

// =============================================
//  LEVEL SELECTOR WIDGET
// =============================================
function renderLevelSelector(type, currentLevel) {
  currentLevel = parseInt(currentLevel) || 1;
  const baseUrls = {
    reflected: '/',
    stored: '/comments',
    dom: '/profile/user1'
  };
  const labels = {
    reflected: 'Reflected XSS',
    stored: 'Stored XSS',
    dom: 'DOM-Based XSS'
  };

  let buttons = '';
  for (let i = 1; i <= 5; i++) {
    const info = LEVELS[type][i];
    const active = i === currentLevel;
    buttons += `<a href="${baseUrls[type]}?level=${i}"
      class="level-btn ${active ? 'level-btn-active' : ''}"
      style="--level-color: ${info.color}">
      <span class="level-icon">${info.icon}</span>
      <span class="level-num">L${i}</span>
      <span class="level-name">${info.name}</span>
    </a>`;
  }

  const info = getLevelInfo(type, currentLevel);

  return `
    <div class="level-selector">
      <div class="level-header">
        <span class="level-type-label">${labels[type]}</span>
        <span class="level-current" style="color: ${info.color}">
          ${info.icon} Level ${info.level}: ${info.name}
        </span>
      </div>
      <div class="level-buttons">${buttons}</div>
      <div class="level-desc" style="border-color: ${info.color}30; background: ${info.color}08">
        <span class="level-desc-icon">${info.icon}</span>
        <span>${info.desc}</span>
      </div>
    </div>`;
}

// =============================================
//  RESET BUTTON WIDGET
// =============================================
function renderResetButton() {
  return `
    <form class="reset-form" method="POST" action="/reset"
      onsubmit="return confirm('Reset all data? Comments and profiles will be cleared.')">
      <button type="submit" class="btn btn-danger" title="Clear all comments and reset profiles">
        &#x1F5D1; Reset Database
      </button>
    </form>`;
}

// =============================================
//  TEMPLATE RENDERERS
// =============================================

function renderLayout(title, content, extraHead = '', extraHeaders = {}) {
  // Build CSP header if needed
  if (extraHeaders.csp) {
    // Don't actually set it — we embed it as a meta tag for demo purposes
  }

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
      <a href="/?level=1">Search</a>
      <a href="/comments?level=1">Comments</a>
      <a href="/profile/user1?level=1">Profile</a>
      <a href="/admin">Admin</a>
    </div>
    <div class="nav-actions">
      <form method="POST" action="/reset" onsubmit="return confirm('Reset all data?')">
        <button type="submit" class="btn btn-danger btn-sm" title="Reset Database">&#x1F5D1;</button>
      </form>
    </div>
  </nav>
  <main class="container">
    ${content}
  </main>
  <footer class="footer">
    <p>VulnLab XSS Playground | For Educational Purposes Only | By <a href="mailto:cysecdon@gmail.com">Cysec Don</a></p>
  </footer>
</body>
</html>`;
}

// ─── SEARCH PAGE (Reflected XSS) ───
function renderSearchPage(query, level) {
  const levelInfo = getLevelInfo('reflected', level);
  let displayQuery = query;
  let inputVal = query;
  let jsContext = '';
  let extraHead = '';
  let filterNote = '';

  switch (level) {
    case 1:
      // Easy: No filtering at all
      break;

    case 2:
      // Medium: "script" keyword blocked
      if (/script/i.test(query)) {
        displayQuery = query.replace(/script/gi, '<span class="blocked">BLOCKED</span>');
        inputVal = '';
        filterNote = 'The word "script" was filtered from your input.';
      }
      break;

    case 3:
      // Hard: All on* event handlers stripped from the reflected output
      displayQuery = stripEventHandlers(query);
      if (displayQuery !== query) {
        filterNote = 'Event handler attributes (on*) were stripped from your input.';
      }
      break;

    case 4:
      // Expert: Angle brackets encoded in HTML context, but also reflected in JS string
      displayQuery = encodeAngleBrackets(query);
      jsContext = escapeForJSString(query);
      break;

    case 5:
      // Insane: CSP header + angle brackets encoded + JS context escaped
      displayQuery = encodeAngleBrackets(query);
      jsContext = escapeForJSString(query);
      extraHead = '<meta http-equiv="Content-Security-Policy" content="script-src \'self\'; style-src \'self\' \'unsafe-inline\'">';
      break;
  }

  const levelSelector = renderLevelSelector('reflected', level);

  let resultsSection;
  if (query) {
    if (level === 4 || level === 5) {
      // Expert & Insane: Also reflect inside a JS string context
      resultsSection = `
        <h2>Search results for: ${displayQuery}</h2>
        <p class="muted">No results found. But your query was rendered beautifully.</p>
        <script>
          var searchData = '${jsContext}';
          console.log("Search data:", searchData);
        </script>`;
    } else {
      resultsSection = `
        <h2>Search results for: ${displayQuery}</h2>
        <p class="muted">No results found. But your query was rendered beautifully.</p>`;
    }
  } else {
    resultsSection = '<p class="muted">Try searching for something... or try &lt;script&gt;alert(1)&lt;/script&gt;</p>';
  }

  const content = `
    <div class="page-header">
      <h1>Search</h1>
      <p class="subtitle">Find anything... and maybe inject something too.</p>
    </div>
    ${levelSelector}
    ${renderResetButton()}
    <form class="search-form" method="GET" action="/">
      <input type="hidden" name="level" value="${level}">
      <input type="text" name="q" value="${inputVal}" placeholder="Search for something..." class="search-input" autofocus>
      <button type="submit" class="btn btn-primary">Search</button>
    </form>
    <div class="search-results">
      ${resultsSection}
      ${filterNote ? `<p class="filter-note">&#x26A0; ${filterNote}</p>` : ''}
    </div>
    <div class="hint-box">
      <strong>Level ${level}: ${levelInfo.name}</strong> &mdash; ${levelInfo.desc}
      ${level === 5 ? '<br><strong>Hint:</strong> There is a JSONP endpoint at <code>/api/callback?cb=FUNCTION_NAME</code>. It is served from the same origin, so CSP allows it.' : ''}
      ${level === 4 ? '<br><strong>Hint:</strong> Angle brackets are encoded in HTML, but your input also appears inside a JavaScript string. Can you break out of the string?' : ''}
      ${level === 3 ? '<br><strong>Hint:</strong> Event handlers are stripped, but what about HTML elements that execute JavaScript without an on* attribute?' : ''}
      ${level === 2 ? '<br><strong>Hint:</strong> The word "script" is blocked, but what about &lt;img&gt;, &lt;svg&gt;, or &lt;body&gt; tags?' : ''}
    </div>`;

  return renderLayout('Search', content, extraHead);
}

// ─── COMMENTS PAGE (Stored XSS) ───
function renderCommentsPage(level) {
  const levelInfo = getLevelInfo('stored', level);

  let commentHTML = comments.map(c => {
    let displayAuthor = c.author;
    let displayText = c.text;

    // Output-side filtering based on current viewing level
    // (Storage-side filtering already happened on POST)
    // For display, we show what was stored

    return `<div class="comment">
      <div class="comment-header">
        <strong>${displayAuthor}</strong>
        <small>${c.date}</small>
      </div>
      <div class="comment-body">${displayText}</div>
    </div>`;
  }).join('');

  if (comments.length === 0) {
    commentHTML = '<p class="muted">No comments yet. Be the first to inject something!</p>';
  }

  const levelSelector = renderLevelSelector('stored', level);

  let extraHead = '';
  if (level === 5) {
    extraHead = '<meta http-equiv="Content-Security-Policy" content="script-src \'self\'; style-src \'self\' \'unsafe-inline\'">';
  }

  const content = `
    <div class="page-header">
      <h1>Comments</h1>
      <p class="subtitle">Share your thoughts... or your scripts.</p>
    </div>
    ${levelSelector}
    ${renderResetButton()}
    <div class="comment-form-card">
      <h3>Post a Comment</h3>
      <form class="comment-form" method="POST" action="/comments">
        <input type="hidden" name="level" value="${level}">
        <input type="text" name="author" placeholder="Your name" class="input-field">
        <textarea name="text" placeholder="Your comment (HTML is &quot;allowed&quot;...)" class="input-field textarea-field" rows="4"></textarea>
        <button type="submit" class="btn btn-primary">Post Comment</button>
      </form>
    </div>
    <div class="comments-list">
      <h3>All Comments</h3>
      ${commentHTML}
    </div>
    <div class="hint-box">
      <strong>Level ${level}: ${levelInfo.name}</strong> &mdash; ${levelInfo.desc}
      ${level === 5 ? '<br><strong>Hint:</strong> Full DOMPurify + CSP. Try mutation XSS (mXSS) with &lt;math&gt; or &lt;svg&gt; namespace confusion, or look for a script gadget in the page\'s own JavaScript.' : ''}
      ${level === 4 ? '<br><strong>Hint:</strong> DOMPurify-lite misses &lt;svg&gt; with namespace tricks and &lt;details&gt; with ontoggle. Also try &lt;math&gt; tags.' : ''}
      ${level === 3 ? '<br><strong>Hint:</strong> Script tags and on* handlers are stripped. But what about &lt;a href="javascript:..."&gt; or &lt;embed&gt; or &lt;iframe srcdoc="..."&gt;?' : ''}
      ${level === 2 ? '<br><strong>Hint:</strong> &lt;script&gt; tags are removed, but &lt;img onerror&gt;, &lt;svg onload&gt;, and other event handlers still work.' : ''}
    </div>`;

  return renderLayout('Comments', content, extraHead);
}

// ─── PROFILE PAGE (DOM-Based XSS) ───
function renderProfilePage(profile, username, level) {
  const levelInfo = getLevelInfo('dom', level);

  const levelSelector = renderLevelSelector('dom', level);

  let domScript = '';
  let extraHead = '';
  let extraContent = '';

  switch (level) {
    case 1:
      // Easy: Direct innerHTML from hash
      domScript = `
        var hash = window.location.hash.substring(1);
        if (hash) {
          document.getElementById('dynamic-content').innerHTML = decodeURIComponent(hash);
        }`;
      break;

    case 2:
      // Medium: Filter script and on* before innerHTML
      domScript = `
        var hash = window.location.hash.substring(1);
        if (hash) {
          var filtered = decodeURIComponent(hash);
          filtered = filtered.replace(/<script[\\s\\S]*?<\\/script\\s*>/gi, '');
          filtered = filtered.replace(/\\s+on\\w+\\s*=\\s*("[^"]*"|'[^']*'|[^\\s>]*)/gi, '');
          document.getElementById('dynamic-content').innerHTML = filtered;
        }`;
      break;

    case 3:
      // Hard: "Sanitizer" encodes angle brackets, but has a bug with SVG
      // The bug: it encodes < and > BUT then processes SVG tags which can
      // re-introduce content via namespace parsing. Specifically, <svg> tags
      // are NOT encoded (intentional bug in the sanitizer).
      domScript = `
        var hash = window.location.hash.substring(1);
        if (hash) {
          var sanitized = decodeURIComponent(hash);
          // Bug: SVG tags are allowed through (developer thought SVG was safe)
          var parts = sanitized.split(/(<\\/?svg[^>]*>)/gi);
          var result = parts.map(function(part, i) {
            if (/<\\/?svg[^>]*>/i.test(part)) return part; // SVG allowed through (BUG)
            return part.replace(/</g, '&lt;').replace(/>/g, '&gt;');
          }).join('');
          document.getElementById('dynamic-content').innerHTML = result;
        }`;
      break;

    case 4:
      // Expert: textContent is used (safe), but there's also an eval() that
      // processes the hash if it starts with "calc:"
      domScript = `
        var hash = window.location.hash.substring(1);
        if (hash) {
          var decoded = decodeURIComponent(hash);
          // Safe: using textContent instead of innerHTML
          document.getElementById('dynamic-content').textContent = decoded;
          // VULNERABLE: Developer added a "calculator" feature that uses eval
          if (decoded.startsWith('calc:')) {
            try {
              var expr = decoded.substring(5);
              var calcResult = eval(expr);
              document.getElementById('calc-result').textContent = 'Result: ' + calcResult;
            } catch(e) {
              document.getElementById('calc-result').textContent = 'Error: ' + e.message;
            }
          }
        }`;
      extraContent = `<div id="calc-result" class="calc-result"></div>`;
      break;

    case 5:
      // Insane: CSP + textContent + no eval. Only postMessage through trusted iframe.
      // The page has an iframe that reads the hash and sends it via postMessage.
      // The parent listens and renders it with innerHTML (the vulnerability).
      extraHead = '<meta http-equiv="Content-Security-Policy" content="script-src \'self\'; style-src \'self\' \'unsafe-inline\'; frame-src \'self\'">';
      domScript = `
        // The page itself uses textContent (safe)
        var hash = window.location.hash.substring(1);
        if (hash) {
          document.getElementById('dynamic-content').textContent = decodeURIComponent(hash);
        }
        // VULNERABLE: Parent listens for postMessage from the embedded widget iframe
        // The iframe reads the hash and posts it - and the parent uses innerHTML
        window.addEventListener('message', function(e) {
          // Bug: No origin check! Any origin can send messages.
          if (e.data && e.data.type === 'widget-data') {
            document.getElementById('dynamic-content').innerHTML = e.data.content;
          }
        });`;
      // The iframe that reads the hash and posts it
      extraContent = `
        <iframe src="/dom-widget.html" class="widget-iframe" title="Dynamic Widget"></iframe>`;
      break;
  }

  const content = `
    <div class="page-header">
      <h1>Profile: ${profile.name}</h1>
      <p class="subtitle">@${username} &bull; Role: ${profile.role}</p>
    </div>
    ${levelSelector}
    ${renderResetButton()}
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
        <input type="hidden" name="level" value="${level}">
        <label>Name</label>
        <input type="text" name="name" value="${profile.name}" class="input-field">
        <label>Bio</label>
        <textarea name="bio" class="input-field textarea-field" rows="3">${profile.bio}</textarea>
        <button type="submit" class="btn btn-primary">Update Profile</button>
      </form>
    </div>
    <div id="dynamic-content" class="dynamic-content"></div>
    ${extraContent}
    <div class="hint-box">
      <strong>Level ${level}: ${levelInfo.name}</strong> &mdash; ${levelInfo.desc}
      ${level === 5 ? '<br><strong>Hint:</strong> The page uses textContent + CSP. But it listens for postMessage without checking origin. The embedded iframe reads the hash and posts it. Can you craft a URL that exploits the postMessage handler? Or open the page from another origin and send a message directly?' : ''}
      ${level === 4 ? '<br><strong>Hint:</strong> The page uses textContent (safe), but there is a "calculator" feature. If the hash starts with <code>calc:</code>, the rest is passed to eval(). Try: <code>#calc:alert(1)</code>' : ''}
      ${level === 3 ? '<br><strong>Hint:</strong> The sanitizer encodes angle brackets but lets &lt;svg&gt; tags through. SVG has its own namespace and can contain &lt;svg/onload=...&gt; or nested elements that execute JS.' : ''}
      ${level === 2 ? '<br><strong>Hint:</strong> Script and on* handlers are stripped. Try &lt;a href="javascript:..."&gt;, &lt;embed&gt;, or &lt;iframe srcdoc="..."&gt;.' : ''}
    </div>
    <script>
      ${domScript}
    </script>`;

  return renderLayout('Profile', content, extraHead);
}

// ─── DOM WIDGET IFRAME (for Level 5 DOM XSS) ───
// This iframe reads the parent's hash and sends it via postMessage
app.get('/dom-widget.html', (req, res) => {
  res.type('text/html');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <style>
    body { margin: 0; padding: 8px; background: #1a1a17; color: #6a6a64;
      font-family: monospace; font-size: 0.75rem; }
  </style>
</head>
<body>
  <div id="widget-content">Dynamic Widget: No data</div>
  <script>
    // Read the parent's hash and send it via postMessage
    try {
      var hash = window.parent.location.hash.substring(1);
      if (hash) {
        var decoded = decodeURIComponent(hash);
        document.getElementById('widget-content').textContent = 'Hash: ' + decoded;
        // VULNERABLE: Send the hash content to parent, which uses innerHTML
        window.parent.postMessage({
          type: 'widget-data',
          content: decoded
        }, '*'); // Bug: target origin is '*' instead of specific origin
      }
    } catch(e) {
      // Cross-origin: can't read parent hash, but can still receive messages
      document.getElementById('widget-content').textContent = 'Widget loaded (cross-origin)';
    }
  </script>
</body>
</html>`);
});

// ─── ADMIN DASHBOARD ───
function renderAdminPage() {
  let commentRows = comments.map(c =>
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
    ${renderResetButton()}
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
  +==============================================+
  |   VulnLab XSS Playground                     |
  |   Running on http://localhost:${PORT}            |
  |                                              |
  |   5 Difficulty Levels per XSS Type:          |
  |     L1: Easy    L2: Medium   L3: Hard        |
  |     L4: Expert  L5: Insane                   |
  |                                              |
  |   WARNING: This app is INTENTIONALLY         |
  |   VULNERABLE. Do NOT expose to the internet. |
  +==============================================+
  `);
});

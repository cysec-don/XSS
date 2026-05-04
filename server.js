/**
 * SpectreLab - Intentionally Vulnerable XSS Playground
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

function stripScriptTags(str) {
  return str.replace(/<script[\s\S]*?<\/script\s*>/gi, '');
}

function stripEventHandlers(str) {
  return str.replace(/\s+on\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]*)/gi, '');
}

function encodeAngleBrackets(str) {
  return str.replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function escapeForJSString(str) {
  return str.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"');
}

function domPurifyLite(str) {
  let s = str;
  s = s.replace(/<script[\s\S]*?<\/script\s*>/gi, '');
  s = s.replace(/\s+on\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]*)/gi, '');
  s = s.replace(/javascript\s*:/gi, '');
  s = s.replace(/<\/?(iframe|object|embed|form|base)[^>]*>/gi, '');
  return s;
}

function domPurifyFull(str) {
  let s = domPurifyLite(str);
  s = s.replace(/<\/?svg[^>]*>/gi, '');
  s = s.replace(/<\/?math[^>]*>/gi, '');
  s = s.replace(/<\/?(details|marquee|isindex)[^>]*>/gi, '');
  s = s.replace(/data\s*:/gi, '');
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

// --- UPDATE PROFILE ---
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

// --- PROGRESS DASHBOARD ---
app.get('/progress', (req, res) => {
  res.send(renderProgressPage());
});

// --- JSONP ENDPOINT ---
app.get('/api/callback', (req, res) => {
  const cb = req.query.cb || 'callback';
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
      style="--level-color: ${info.color}"
      data-type="${type}" data-level="${i}">
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
      <div class="level-complete-row">
        <button class="btn btn-success btn-sm" onclick="markComplete('${type}', ${currentLevel})" id="complete-btn-${type}-${currentLevel}">
          &#x2705; Mark Completed
        </button>
        <button class="btn btn-share-trigger btn-sm" onclick="toggleSharePanel('${type}', ${currentLevel})">
          &#x1F4E4; Share Progress
        </button>
      </div>
      <div class="share-panel" id="share-panel-${type}-${currentLevel}" style="display:none">
        <div class="share-panel-inner">
          <span class="share-label">Share your achievement:</span>
          <div class="share-buttons">
            <a class="share-btn share-x" onclick="shareTo('x','${type}',${currentLevel})" title="Share on X">
              <span class="share-icon">&#x1D54F;</span> X
            </a>
            <a class="share-btn share-linkedin" onclick="shareTo('linkedin','${type}',${currentLevel})" title="Share on LinkedIn">
              <span class="share-icon">in</span> LinkedIn
            </a>
            <a class="share-btn share-facebook" onclick="shareTo('facebook','${type}',${currentLevel})" title="Share on Facebook">
              <span class="share-icon">f</span> Facebook
            </a>
            <a class="share-btn share-reddit" onclick="shareTo('reddit','${type}',${currentLevel})" title="Share on Reddit">
              <span class="share-icon">R</span> Reddit
            </a>
            <a class="share-btn share-whatsapp" onclick="shareTo('whatsapp','${type}',${currentLevel})" title="Share on WhatsApp">
              <span class="share-icon">&#x1F4F1;</span> WhatsApp
            </a>
            <a class="share-btn share-telegram" onclick="shareTo('telegram','${type}',${currentLevel})" title="Share on Telegram">
              <span class="share-icon">&#x2708;</span> Telegram
            </a>
          </div>
          <button class="btn btn-sm btn-copy-link" onclick="copyProgressLink('${type}',${currentLevel})">
            &#x1F517; Copy Link
          </button>
        </div>
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
//  PROGRESS TRACKING + SOCIAL SHARING JS
// =============================================
const progressAndShareScript = `
<script>
(function() {
  // --- Progress Tracking (localStorage) ---
  const STORAGE_KEY = 'spectrelab_progress';
  const LEVELS = {
    reflected: { 1:'Easy', 2:'Medium', 3:'Hard', 4:'Expert', 5:'Insane' },
    stored:    { 1:'Easy', 2:'Medium', 3:'Hard', 4:'Expert', 5:'Insane' },
    dom:       { 1:'Easy', 2:'Medium', 3:'Hard', 4:'Expert', 5:'Insane' }
  };
  const TYPE_LABELS = { reflected:'Reflected XSS', stored:'Stored XSS', dom:'DOM-Based XSS' };
  const TYPE_ICONS = { reflected:'\\u{1F50D}', stored:'\\u{1F4AC}', dom:'\\u{1F3AF}' };

  function getProgress() {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_KEY)) || {};
    } catch(e) { return {}; }
  }

  function saveProgress(progress) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(progress));
    } catch(e) {}
  }

  window.markComplete = function(type, level) {
    var progress = getProgress();
    var key = type + '_' + level;
    if (!progress[key]) {
      progress[key] = { type: type, level: level, name: LEVELS[type][level], date: new Date().toISOString() };
      saveProgress(progress);
      var btn = document.getElementById('complete-btn-' + type + '-' + level);
      if (btn) { btn.innerHTML = '\\u2705 Completed!'; btn.disabled = true; btn.classList.add('btn-completed'); }
      updateNavProgress();
    }
  };

  window.toggleSharePanel = function(type, level) {
    var panel = document.getElementById('share-panel-' + type + '-' + level);
    if (panel) { panel.style.display = panel.style.display === 'none' ? 'block' : 'none'; }
  };

  function getShareText(type, level) {
    var name = LEVELS[type][level];
    var typeLabel = TYPE_LABELS[type];
    var icon = TYPE_ICONS[type];
    return icon + ' SpectreLab | I conquered ' + typeLabel + ' Level ' + level + ': ' + name + '! \\u{1F680}\\n\\nCan you beat it? \\u{1F449} https://github.com/cysec-don/XSS \\n\\n#SpectreLab #XSS #Cybersecurity #InfoSec #WebSecurity #EthicalHacking';
  }

  function getShareUrl(type, level) {
    var baseUrls = { reflected: '/', stored: '/comments', dom: '/profile/user1' };
    return window.location.origin + baseUrls[type] + '?level=' + level;
  }

  window.shareTo = function(platform, type, level) {
    var text = getShareText(type, level);
    var url = getShareUrl(type, level);
    var githubUrl = 'https://github.com/cysec-don/XSS';
    var encoded = encodeURIComponent(text);
    var encodedUrl = encodeURIComponent(url);
    var encodedGithub = encodeURIComponent(githubUrl);
    var shareUrl = '';

    switch(platform) {
      case 'x':
        shareUrl = 'https://twitter.com/intent/tweet?text=' + encoded;
        break;
      case 'linkedin':
        shareUrl = 'https://www.linkedin.com/sharing/share-offsite/?url=' + encodedGithub + '&summary=' + encoded;
        break;
      case 'facebook':
        shareUrl = 'https://www.facebook.com/sharer/sharer.php?u=' + encodedGithub + '&quote=' + encoded;
        break;
      case 'reddit':
        shareUrl = 'https://www.reddit.com/submit?url=' + encodedGithub + '&title=' + encodeURIComponent('SpectreLab | I conquered ' + TYPE_LABELS[type] + ' Level ' + level + ': ' + LEVELS[type][level] + '!');
        break;
      case 'whatsapp':
        shareUrl = 'https://wa.me/?text=' + encoded;
        break;
      case 'telegram':
        shareUrl = 'https://t.me/share/url?url=' + encodedGithub + '&text=' + encoded;
        break;
    }
    if (shareUrl) window.open(shareUrl, '_blank', 'width=600,height=500');
  };

  window.copyProgressLink = function(type, level) {
    var url = getShareUrl(type, level);
    var text = getShareText(type, level);
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text + '\\n' + url).then(function() {
        showCopyToast('Progress copied to clipboard!');
      });
    } else {
      var ta = document.createElement('textarea');
      ta.value = text + '\\n' + url;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showCopyToast('Progress copied to clipboard!');
    }
  };

  function showCopyToast(msg) {
    var toast = document.createElement('div');
    toast.className = 'copy-toast';
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(function() { toast.classList.add('toast-show'); }, 10);
    setTimeout(function() { toast.classList.remove('toast-show'); setTimeout(function() { toast.remove(); }, 300); }, 2500);
  }

  // --- Highlight already completed levels on page load ---
  function highlightCompleted() {
    var progress = getProgress();
    document.querySelectorAll('.level-btn').forEach(function(btn) {
      var type = btn.dataset.type;
      var level = btn.dataset.level;
      if (type && level && progress[type + '_' + level]) {
        btn.classList.add('level-btn-completed');
      }
    });
    // Update complete buttons
    document.querySelectorAll('[id^="complete-btn-"]').forEach(function(btn) {
      var parts = btn.id.replace('complete-btn-', '').split('-');
      var type = parts[0];
      var level = parts[1];
      if (progress[type + '_' + level]) {
        btn.innerHTML = '\\u2705 Completed!';
        btn.disabled = true;
        btn.classList.add('btn-completed');
      }
    });
  }

  // --- Nav progress indicator ---
  function updateNavProgress() {
    var progress = getProgress();
    var total = 15;
    var completed = Object.keys(progress).length;
    var badge = document.getElementById('nav-progress-badge');
    if (badge) {
      badge.textContent = completed + '/' + total;
      badge.style.display = completed > 0 ? 'inline' : 'none';
    }
  }

  // Init
  document.addEventListener('DOMContentLoaded', function() {
    highlightCompleted();
    updateNavProgress();
  });
})();
</script>`;

// =============================================
//  TEMPLATE RENDERERS
// =============================================

function renderLayout(title, content, extraHead = '') {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} - SpectreLab</title>
  <link rel="stylesheet" href="/css/style.css">
  ${extraHead}
</head>
<body>
  <nav class="navbar">
    <div class="nav-brand">
      <span class="logo">&#x1F47B;</span> SpectreLab
    </div>
    <div class="nav-links">
      <a href="/?level=1">Search</a>
      <a href="/comments?level=1">Comments</a>
      <a href="/profile/user1?level=1">Profile</a>
      <a href="/admin">Admin</a>
      <a href="/progress" class="nav-progress-link">&#x1F3C6; Progress</a>
    </div>
    <div class="nav-actions">
      <span id="nav-progress-badge" class="nav-progress-badge" style="display:none">0/15</span>
      <form method="POST" action="/reset" onsubmit="return confirm('Reset all data?')">
        <button type="submit" class="btn btn-danger btn-sm" title="Reset Database">&#x1F5D1;</button>
      </form>
    </div>
  </nav>
  <main class="container">
    ${content}
  </main>
  <footer class="footer">
    <p>SpectreLab XSS Playground | For Educational Purposes Only | By <a href="mailto:cysecdon@gmail.com">Cysec Don</a></p>
  </footer>
  ${progressAndShareScript}
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
    case 1: break;
    case 2:
      if (/script/i.test(query)) {
        displayQuery = query.replace(/script/gi, '<span class="blocked">BLOCKED</span>');
        inputVal = '';
        filterNote = 'The word "script" was filtered from your input.';
      }
      break;
    case 3:
      displayQuery = stripEventHandlers(query);
      if (displayQuery !== query) {
        filterNote = 'Event handler attributes (on*) were stripped from your input.';
      }
      break;
    case 4:
      displayQuery = encodeAngleBrackets(query);
      jsContext = escapeForJSString(query);
      break;
    case 5:
      displayQuery = encodeAngleBrackets(query);
      jsContext = escapeForJSString(query);
      extraHead = '<meta http-equiv="Content-Security-Policy" content="script-src \'self\'; style-src \'self\' \'unsafe-inline\'">';
      break;
  }

  const levelSelector = renderLevelSelector('reflected', level);

  let resultsSection;
  if (query) {
    if (level === 4 || level === 5) {
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

  let commentHTML = comments.map(c =>
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
      domScript = `
        var hash = window.location.hash.substring(1);
        if (hash) {
          document.getElementById('dynamic-content').innerHTML = decodeURIComponent(hash);
        }`;
      break;
    case 2:
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
      domScript = `
        var hash = window.location.hash.substring(1);
        if (hash) {
          var sanitized = decodeURIComponent(hash);
          var parts = sanitized.split(/(<\\/?svg[^>]*>)/gi);
          var result = parts.map(function(part, i) {
            if (/<\\/?svg[^>]*>/i.test(part)) return part;
            return part.replace(/</g, '&lt;').replace(/>/g, '&gt;');
          }).join('');
          document.getElementById('dynamic-content').innerHTML = result;
        }`;
      break;
    case 4:
      domScript = `
        var hash = window.location.hash.substring(1);
        if (hash) {
          var decoded = decodeURIComponent(hash);
          document.getElementById('dynamic-content').textContent = decoded;
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
      extraHead = '<meta http-equiv="Content-Security-Policy" content="script-src \'self\'; style-src \'self\' \'unsafe-inline\'; frame-src \'self\'">';
      domScript = `
        var hash = window.location.hash.substring(1);
        if (hash) {
          document.getElementById('dynamic-content').textContent = decodeURIComponent(hash);
        }
        window.addEventListener('message', function(e) {
          if (e.data && e.data.type === 'widget-data') {
            document.getElementById('dynamic-content').innerHTML = e.data.content;
          }
        });`;
      extraContent = `<iframe src="/dom-widget.html" class="widget-iframe" title="Dynamic Widget"></iframe>`;
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

// ─── DOM WIDGET IFRAME ───
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
    try {
      var hash = window.parent.location.hash.substring(1);
      if (hash) {
        var decoded = decodeURIComponent(hash);
        document.getElementById('widget-content').textContent = 'Hash: ' + decoded;
        window.parent.postMessage({
          type: 'widget-data',
          content: decoded
        }, '*');
      }
    } catch(e) {
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
          <tr><th>Author</th><th>Comment</th><th>Date</th></tr>
        </thead>
        <tbody>${commentRows}</tbody>
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

// ─── PROGRESS DASHBOARD ───
function renderProgressPage() {
  const types = [
    { key: 'reflected', label: 'Reflected XSS', icon: '\u{1F50D}', page: '/' },
    { key: 'stored', label: 'Stored XSS', icon: '\u{1F4AC}', page: '/comments' },
    { key: 'dom', label: 'DOM-Based XSS', icon: '\u{1F3AF}', page: '/profile/user1' }
  ];

  let cards = types.map(t => {
    let levelRows = '';
    for (let i = 1; i <= 5; i++) {
      const info = LEVELS[t.key][i];
      levelRows += `
        <div class="progress-level-row" data-type="${t.key}" data-level="${i}">
          <span class="progress-level-icon">${info.icon}</span>
          <span class="progress-level-name">L${i}: ${info.name}</span>
          <span class="progress-level-status" id="progress-status-${t.key}-${i}">&#x2B55;</span>
          <button class="btn btn-success btn-xs" onclick="markComplete('${t.key}',${i})" id="progress-complete-${t.key}-${i}">&#x2705; Mark</button>
          <button class="btn btn-share-trigger btn-xs" onclick="shareProgress('${t.key}',${i})" title="Share">&#x1F4E4;</button>
        </div>`;
    }
    return `
      <div class="progress-card">
        <div class="progress-card-header">
          <span class="progress-type-icon">${t.icon}</span>
          <span class="progress-type-name">${t.label}</span>
          <a href="${t.page}?level=1" class="btn btn-primary btn-xs">Go &#x2192;</a>
        </div>
        <div class="progress-levels">${levelRows}</div>
      </div>`;
  }).join('');

  const content = `
    <div class="page-header">
      <h1>&#x1F3C6; Your Progress</h1>
      <p class="subtitle">Track your conquests across all XSS challenges.</p>
    </div>
    <div class="progress-overview">
      <div class="progress-bar-container">
        <div class="progress-bar" id="total-progress-bar" style="width:0%"></div>
      </div>
      <span class="progress-text" id="total-progress-text">0 / 15 levels completed</span>
    </div>
    <div class="progress-share-all">
      <button class="btn btn-primary" onclick="shareAllProgress()">&#x1F4E4; Share Overall Progress</button>
      <button class="btn btn-danger btn-sm" onclick="clearAllProgress()">&#x1F5D1; Reset Progress</button>
    </div>
    <div class="progress-cards">${cards}</div>
    <div class="share-panel" id="share-panel-progress" style="display:none">
      <div class="share-panel-inner">
        <span class="share-label">Share your achievement:</span>
        <div class="share-buttons">
          <a class="share-btn share-x" onclick="sharePlatform('x')" title="Share on X"><span class="share-icon">&#x1D54F;</span> X</a>
          <a class="share-btn share-linkedin" onclick="sharePlatform('linkedin')" title="Share on LinkedIn"><span class="share-icon">in</span> LinkedIn</a>
          <a class="share-btn share-facebook" onclick="sharePlatform('facebook')" title="Share on Facebook"><span class="share-icon">f</span> Facebook</a>
          <a class="share-btn share-reddit" onclick="sharePlatform('reddit')" title="Share on Reddit"><span class="share-icon">R</span> Reddit</a>
          <a class="share-btn share-whatsapp" onclick="sharePlatform('whatsapp')" title="Share on WhatsApp"><span class="share-icon">&#x1F4F1;</span> WhatsApp</a>
          <a class="share-btn share-telegram" onclick="sharePlatform('telegram')" title="Share on Telegram"><span class="share-icon">&#x2708;</span> Telegram</a>
        </div>
        <button class="btn btn-sm btn-copy-link" onclick="copyProgressLink('reflected',1)">&#x1F517; Copy Progress</button>
      </div>
    </div>
    <script>
    // Progress page specific scripts
    (function() {
      var STORAGE_KEY = 'spectrelab_progress';
      var LEVELS_MAP = { 1:'Easy', 2:'Medium', 3:'Hard', 4:'Expert', 5:'Insane' };
      var TYPE_LABELS = { reflected:'Reflected XSS', stored:'Stored XSS', dom:'DOM-Based XSS' };

      function getProgress() {
        try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || {}; } catch(e) { return {}; }
      }

      function refreshProgressUI() {
        var progress = getProgress();
        var total = 0;
        ['reflected','stored','dom'].forEach(function(type) {
          for (var i = 1; i <= 5; i++) {
            var statusEl = document.getElementById('progress-status-' + type + '-' + i);
            var btnEl = document.getElementById('progress-complete-' + type + '-' + i);
            var key = type + '_' + i;
            if (progress[key]) {
              total++;
              if (statusEl) statusEl.innerHTML = '\\u2705';
              if (btnEl) { btnEl.innerHTML = '\\u2705 Done'; btnEl.disabled = true; btnEl.classList.add('btn-completed'); }
            } else {
              if (statusEl) statusEl.innerHTML = '\\u2B55';
            }
          }
        });
        var pct = Math.round((total / 15) * 100);
        var bar = document.getElementById('total-progress-bar');
        var text = document.getElementById('total-progress-text');
        if (bar) bar.style.width = pct + '%';
        if (text) text.textContent = total + ' / 15 levels completed (' + pct + '%)';
      }

      window.shareProgress = function(type, level) {
        window.shareTo('x', type, level);
      };

      window.shareAllProgress = function() {
        var panel = document.getElementById('share-panel-progress');
        if (panel) panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
      };

      var currentShareType = 'reflected';
      var currentShareLevel = 1;

      window.sharePlatform = function(platform) {
        window.shareTo(platform, currentShareType, currentShareLevel);
      };

      window.clearAllProgress = function() {
        if (confirm('Clear all progress data? This cannot be undone.')) {
          localStorage.removeItem(STORAGE_KEY);
          refreshProgressUI();
          updateNavProgress();
        }
      };

      document.addEventListener('DOMContentLoaded', refreshProgressUI);
    })();
    </script>`;

  return renderLayout('Progress', content);
}

// =============================================
//  START SERVER
// =============================================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`
  +==============================================+
  |   SpectreLab XSS Playground                  |
  |   Running on http://localhost:${PORT}            |
  |                                              |
  |   5 Difficulty Levels per XSS Type:          |
  |     L1: Easy    L2: Medium   L3: Hard        |
  |     L4: Expert  L5: Insane                   |
  |                                              |
  |   Share progress to social media!            |
  |                                              |
  |   WARNING: This app is INTENTIONALLY         |
  |   VULNERABLE. Do NOT expose to the internet. |
  +==============================================+
  `);
});

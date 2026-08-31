// This file contains INTENTIONALLY VULNERABLE JavaScript code for testing
// the AST heuristic engine.  Do NOT use any of this in production.

// ── A03: eval ───────────────────────────────────────────────────────────

function processInput(userInput) {
  return eval(userInput);
}

// ── A03: SQL injection (string concat) ──────────────────────────────────

function getUser(db, userId) {
  return db.query("SELECT * FROM users WHERE id=" + userId);
}

// ── A03: SQL injection (template literal) ───────────────────────────────

function getUserByName(db, name) {
  return db.query(`SELECT * FROM users WHERE name='${name}'`);
}

// ── A03: innerHTML (XSS) ────────────────────────────────────────────────

function renderContent(element, userContent) {
  element.innerHTML = userContent;
}

// ── A04: Empty catch ────────────────────────────────────────────────────

function riskyOperation() {
  try {
    doSomething();
  } catch (e) {}
}

// ── A02: Hardcoded secrets ──────────────────────────────────────────────

const apiSecret = "sk-live-abc123def456";
const dbPassword = "super_secret_123";

// ── A09: Logging sensitive data ─────────────────────────────────────────

function login(user, password) {
  console.log(password);
}

// ── Memory: addEventListener without removeEventListener ────────────────

function setupHandler() {
  document.addEventListener("click", handleClick);
}

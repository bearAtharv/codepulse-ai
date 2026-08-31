// This file contains CLEAN, SAFE JavaScript code that should NOT trigger
// any AST heuristic.  Used to verify zero false-positives.

// ── Safe data parsing (no eval) ─────────────────────────────────────────

function processInput(userInput) {
  return JSON.parse(userInput);
}

// ── Safe SQL (parameterised queries) ────────────────────────────────────

function getUser(db, userId) {
  return db.query("SELECT * FROM users WHERE id=$1", [userId]);
}

// ── Safe DOM update (textContent) ───────────────────────────────────────

function renderContent(element, userContent) {
  element.textContent = userContent;
}

// ── Proper error handling ───────────────────────────────────────────────

function riskyOperation() {
  try {
    doSomething();
  } catch (e) {
    console.error("Operation failed:", e);
  }
}

// ── Secrets from environment ────────────────────────────────────────────

const apiSecret = process.env.API_SECRET;
const dbPassword = process.env.DB_PASSWORD;

// ── Safe logging ────────────────────────────────────────────────────────

function login(user, password) {
  console.log("User logged in:", user);
}

// ── Proper event listener cleanup ───────────────────────────────────────

function setupHandler() {
  document.addEventListener("click", handleClick);
  // Cleanup registered
  document.removeEventListener("click", handleClick);
}

// CodePulse Web UI Client Scripts (Vanilla JS, Zero Dependencies)

document.addEventListener("DOMContentLoaded", () => {
  // 1. Finding Card Click -> Highlight Line in Code Viewer
  const findingCards = document.querySelectorAll(".finding-card[data-line]");
  findingCards.forEach((card) => {
    card.addEventListener("click", () => {
      const lineNum = card.getAttribute("data-line");
      highlightCodeLine(lineNum);
    });
  });

  // 2. Setup Code Samples
  setupSampleButtons();

  // 3. Setup File Upload Preview
  setupFileUpload();

  // 4. Setup Simulation Polling if on simulate page with active run
  const simContainer = document.getElementById("simulation-progress-container");
  if (simContainer && simContainer.dataset.runId) {
    pollSimulationStatus(simContainer.dataset.runId);
  }

  // 5. Setup Retry Button
  const retryBtn = document.getElementById("btn-retry-posting");
  if (retryBtn) {
    retryBtn.addEventListener("click", (e) => {
      e.preventDefault();
      const runId = retryBtn.dataset.runId;
      const csrfToken = retryBtn.dataset.csrfToken || "";
      executeRetryPosting(runId, csrfToken, retryBtn);
    });
  }
});

function highlightCodeLine(lineNum) {
  // Clear previous active focus
  document.querySelectorAll(".code-line.active-focus").forEach((el) => {
    el.classList.remove("active-focus");
  });

  const targetLine = document.getElementById(`code-line-${lineNum}`);
  if (targetLine) {
    targetLine.classList.add("active-focus");
    targetLine.scrollIntoView({ behavior: "smooth", block: "center" });
  }
}

const CODE_SAMPLES = {
  sqli: {
    lang: "python",
    code: `def get_user_profile(user_id):\n    # Vulnerability: f-string SQL query directly in execute call\n    cursor.execute(f"SELECT id, username, email FROM users WHERE id = '{user_id}'")\n    return cursor.fetchone()\n`,
  },
  eval: {
    lang: "python",
    code: `def process_dynamic_command(user_payload):\n    # Vulnerability: Dynamic code execution via eval() on untrusted payload\n    result = eval(user_payload.get("expression"))\n    return {"result": result}\n`,
  },
  secret: {
    lang: "python",
    code: `import os\n\n# Vulnerability: Hardcoded API secret key\nAWS_SECRET_KEY = "AKIA1234567890EXAMPLEKEY"\nDATABASE_PASSWORD = "super_secret_production_password_123"\n\ndef connect():\n    pass\n`,
  },
  xss: {
    lang: "javascript",
    code: `function renderUserProfile(container, userInput) {\n    // Vulnerability: Direct assignment to element.innerHTML creates XSS vector\n    const bioElement = document.getElementById("user-bio");\n    bioElement.innerHTML = "<div>" + userInput.bio + "</div>";\n}\n`,
  },
};

function setupSampleButtons() {
  const codeArea = document.getElementById("code-input");
  const langSelect = document.getElementById("language-select");

  document.querySelectorAll(".sample-btn[data-sample]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const sampleKey = btn.dataset.sample;
      const sample = CODE_SAMPLES[sampleKey];
      if (sample && codeArea) {
        codeArea.value = sample.code;
        if (langSelect) {
          langSelect.value = sample.lang;
        }
      }
    });
  });
}

function setupFileUpload() {
  const fileInput = document.getElementById("code-file");
  const codeArea = document.getElementById("code-input");
  const langSelect = document.getElementById("language-select");

  if (!fileInput || !codeArea) return;

  fileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;

    if (file.size > 200 * 1024) {
      alert("File size exceeds 200 KB limit.");
      fileInput.value = "";
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      codeArea.value = event.target.result;
      const ext = file.name.split(".").pop().toLowerCase();
      if (langSelect) {
        if (ext === "py") langSelect.value = "python";
        else if (ext === "js" || ext === "jsx") langSelect.value = "javascript";
        else if (ext === "ts" || ext === "tsx") langSelect.value = "typescript";
      }
    };
    reader.readAsText(file);
  });
}

function pollSimulationStatus(runId) {
  const statusBadge = document.getElementById("sim-status-badge");
  const resultsCard = document.getElementById("sim-results-card");
  const reviewBody = document.getElementById("sim-review-body");
  const inlineCommentsList = document.getElementById("sim-inline-comments");
  const progressBar = document.getElementById("sim-progress-bar");

  let intervalId = setInterval(async () => {
    try {
      const res = await fetch(`/ui/api/runs/${runId}`);
      if (!res.ok) return;

      const data = await res.json();
      if (statusBadge) {
        statusBadge.textContent = data.status.toUpperCase();
        statusBadge.className = `badge badge-${data.status}`;
      }

      if (data.status === "completed" || data.status === "failed") {
        clearInterval(intervalId);
        if (progressBar) progressBar.style.display = "none";
        if (resultsCard) resultsCard.style.display = "block";

        if (reviewBody && data.review_summary) {
          reviewBody.textContent = data.review_summary;
        }

        if (inlineCommentsList && Array.isArray(data.inline_comments)) {
          inlineCommentsList.innerHTML = "";
          if (data.inline_comments.length === 0) {
            inlineCommentsList.innerHTML = "<li><em>No inline comments generated.</em></li>";
          } else {
            data.inline_comments.forEach((c) => {
              const li = document.createElement("li");
              li.innerHTML = `<strong>${escapeHtml(c.path)}:${c.line}</strong> (${escapeHtml(c.side || "RIGHT")}):<br><pre>${escapeHtml(c.body)}</pre>`;
              inlineCommentsList.appendChild(li);
            });
          }
        }
      }
    } catch (err) {
      console.error("Simulation polling error:", err);
    }
  }, 1000);
}

async function executeRetryPosting(runId, csrfToken, button) {
  button.disabled = true;
  button.textContent = "Retrying...";
  try {
    const res = await fetch(`/ui/api/runs/${runId}/retry`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken,
      },
    });
    const result = await res.json();
    if (res.ok && result.success) {
      alert("Review successfully re-posted!");
      window.location.reload();
    } else {
      alert(`Retry failed: ${result.error || result.detail || "Unknown error"}`);
      button.disabled = false;
      button.textContent = "Retry posting";
    }
  } catch (err) {
    alert(`Retry request failed: ${err.message}`);
    button.disabled = false;
    button.textContent = "Retry posting";
  }
}

function escapeHtml(text) {
  if (!text) return "";
  const map = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  };
  return String(text).replace(/[&<>"']/g, (m) => map[m]);
}

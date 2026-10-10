/* Advanced Phishing Detection Tool - Frontend Logic */

const THEME_KEY = "advancedPhishingTheme";
const HISTORY_PAGE_SIZE = 10;
const HISTORY_STORAGE_KEY = "phishingDetectionHistory";

const state = {
    mode: "single",
    historyVisibleCount: HISTORY_PAGE_SIZE,
    historyItems: [],
    batchResults: [],
    sort: {
        key: "timestamp",
        dir: "desc",
    },
    lastSingleResult: null,
};

function loadHistoryFromStorage() {
    const raw = localStorage.getItem(HISTORY_STORAGE_KEY);
    if (!raw) {
        return [];
    }

    try {
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : [];
    } catch (_error) {
        localStorage.removeItem(HISTORY_STORAGE_KEY);
        return [];
    }
}

function saveHistoryToStorage(items) {
    const cleanItems = Array.isArray(items) ? items : [];
    localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(cleanItems.slice(0, 500)));
}

function historyKey(item) {
    return `${item.id || ""}|${item.url || ""}|${item.created_at || item.timestamp || ""}|${item.analysis_mode || ""}`;
}

function mergeHistory(serverHistory, localHistory) {
    const merged = [];
    const seen = new Set();

    const addUnique = (items) => {
        (Array.isArray(items) ? items : []).forEach((item) => {
            const key = historyKey(item);
            if (!seen.has(key)) {
                seen.add(key);
                merged.push(item);
            }
        });
    };

    addUnique(serverHistory);
    addUnique(localHistory);

    merged.sort((a, b) => {
        const aTime = new Date(a.created_at || a.timestamp || 0).getTime();
        const bTime = new Date(b.created_at || b.timestamp || 0).getTime();
        return bTime - aTime;
    });

    return merged;
}

function appendHistoryItems(newItems) {
    const localHistory = loadHistoryFromStorage();
    const merged = mergeHistory(newItems, localHistory);
    saveHistoryToStorage(merged);
    state.historyItems = merged;
}

const el = {
    body: document.body,
    singleModeBtn: document.getElementById("singleModeBtn"),
    batchModeBtn: document.getElementById("batchModeBtn"),
    singleModePanel: document.getElementById("singleModePanel"),
    batchModePanel: document.getElementById("batchModePanel"),

    urlInput: document.getElementById("urlInput"),
    batchInput: document.getElementById("batchInput"),

    analyzeBtn: document.getElementById("analyzeBtn"),
    analyzeBtnText: document.getElementById("analyzeBtnText"),
    analyzeBtnLoader: document.getElementById("analyzeBtnLoader"),

    analyzeBatchBtn: document.getElementById("analyzeBatchBtn"),
    analyzeBatchBtnText: document.getElementById("analyzeBatchBtnText"),
    analyzeBatchBtnLoader: document.getElementById("analyzeBatchBtnLoader"),

    errorMsg: document.getElementById("errorMsg"),

    singleResultPanel: document.getElementById("singleResultPanel"),
    batchResultPanel: document.getElementById("batchResultPanel"),

    scoreValue: document.getElementById("scoreValue"),
    ringProgress: document.getElementById("ringProgress"),
    riskLevelText: document.getElementById("riskLevelText"),
    confidenceText: document.getElementById("confidenceText"),
    analyzedUrl: document.getElementById("analyzedUrl"),
    recommendationText: document.getElementById("recommendationText"),
    typosquatText: document.getElementById("typosquatText"),
    sslCertText: document.getElementById("sslCertText"),
    blocklistText: document.getElementById("blocklistText"),
    interactionText: document.getElementById("interactionText"),
    reasonGroupWrap: document.getElementById("reasonGroupWrap"),

    copyResultBtn: document.getElementById("copyResultBtn"),

    batchTableBody: document.getElementById("batchTableBody"),
    sortButtons: document.querySelectorAll(".sort-btn"),

    historyList: document.getElementById("historyList"),
    historyInfo: document.getElementById("historyInfo"),
    historySearchInput: document.getElementById("historySearchInput"),
    historyRiskFilter: document.getElementById("historyRiskFilter"),
    loadMoreHistoryBtn: document.getElementById("loadMoreHistoryBtn"),

    exportCsvBtn: document.getElementById("exportCsvBtn"),
    clearHistoryBtn: document.getElementById("clearHistoryBtn"),

    themeToggleBtn: document.getElementById("themeToggleBtn"),
    themeToggleText: document.getElementById("themeToggleText"),
};

const RING_RADIUS = 52;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;

function init() {
    setupRing();
    bindEvents();
    restoreTheme();
    switchMode("single");
    refreshHistory();
}

function bindEvents() {
    el.singleModeBtn.addEventListener("click", () => switchMode("single"));
    el.batchModeBtn.addEventListener("click", () => switchMode("batch"));

    el.analyzeBtn.addEventListener("click", handleSingleAnalyze);
    el.urlInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
            handleSingleAnalyze();
        }
    });

    el.analyzeBatchBtn.addEventListener("click", handleBatchAnalyze);

    el.copyResultBtn.addEventListener("click", handleCopyResult);

    el.sortButtons.forEach((btn) => {
        btn.addEventListener("click", () => handleSort(btn.dataset.sort || "timestamp"));
    });

    el.historySearchInput.addEventListener("input", () => {
        state.historyVisibleCount = HISTORY_PAGE_SIZE;
        renderHistory();
    });

    el.historyRiskFilter.addEventListener("change", () => {
        state.historyVisibleCount = HISTORY_PAGE_SIZE;
        renderHistory();
    });

    el.loadMoreHistoryBtn.addEventListener("click", () => {
        state.historyVisibleCount += HISTORY_PAGE_SIZE;
        renderHistory();
    });

    el.exportCsvBtn.addEventListener("click", exportHistoryAsCsv);

    el.clearHistoryBtn.addEventListener("click", () => {
        clearHistoryOnServer();
    });

    el.themeToggleBtn.addEventListener("click", toggleTheme);
}

function switchMode(mode) {
    state.mode = mode;
    hideError();

    const singleActive = mode === "single";
    el.singleModeBtn.classList.toggle("active", singleActive);
    el.batchModeBtn.classList.toggle("active", !singleActive);
    el.singleModeBtn.setAttribute("aria-selected", String(singleActive));
    el.batchModeBtn.setAttribute("aria-selected", String(!singleActive));

    el.singleModePanel.classList.toggle("hidden", !singleActive);
    el.batchModePanel.classList.toggle("hidden", singleActive);
    el.singleResultPanel.classList.add("hidden");
    el.batchResultPanel.classList.add("hidden");

    if (singleActive) {
        el.urlInput.focus();
    } else {
        el.batchInput.focus();
    }
}

async function handleSingleAnalyze() {
    const url = el.urlInput.value.trim();
    hideError();

    if (!url) {
        showError("Please enter a URL.");
        return;
    }

    setLoading("single", true);

    try {
        const response = await fetch("/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });

        const payload = await response.json();
        if (!response.ok) {
            showError(payload.error || "Single analysis failed.");
            return;
        }

        const historyItem = {
            ...payload,
            analysis_mode: "single",
            created_at: new Date().toISOString(),
        };

        state.lastSingleResult = historyItem;
        appendHistoryItems([historyItem]);

        renderSingleResult(payload);
        renderHistory();
    } catch (_error) {
        showError("Unable to connect to server. Ensure app.py is running.");
    } finally {
        setLoading("single", false);
    }
}

async function handleBatchAnalyze() {
    hideError();

    const lines = el.batchInput.value
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean);

    if (!lines.length) {
        showError("Please provide at least one URL in batch mode.");
        return;
    }

    setLoading("batch", true);

    try {
        const response = await fetch("/analyze/batch", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ urls: lines }),
        });

        const payload = await response.json();
        if (!response.ok) {
            showError(payload.error || "Batch analysis failed.");
            return;
        }

        const timestamp = new Date().toISOString();
        const historyItems = payload.map((item) => ({
            ...item,
            analysis_mode: "batch",
            created_at: timestamp,
        }));

        state.batchResults = payload.map((item) => ({ ...item, timestamp }));
        appendHistoryItems(historyItems);
        renderBatchResults();
        renderHistory();
    } catch (_error) {
        showError("Unable to connect to server. Ensure app.py is running.");
    } finally {
        setLoading("batch", false);
    }
}

function setLoading(type, isLoading) {
    if (type === "single") {
        el.analyzeBtn.disabled = isLoading;
        el.analyzeBtnText.classList.toggle("hidden", isLoading);
        el.analyzeBtnLoader.classList.toggle("hidden", !isLoading);
    } else {
        el.analyzeBatchBtn.disabled = isLoading;
        el.analyzeBatchBtnText.classList.toggle("hidden", isLoading);
        el.analyzeBatchBtnLoader.classList.toggle("hidden", !isLoading);
    }
}

function showError(message) {
    el.errorMsg.textContent = message;
    el.errorMsg.classList.remove("hidden");
}

function hideError() {
    el.errorMsg.classList.add("hidden");
    el.errorMsg.textContent = "";
}

async function refreshHistory() {
    const localHistory = loadHistoryFromStorage();

    try {
        const response = await fetch(`/history?limit=${Math.max(HISTORY_PAGE_SIZE, state.historyVisibleCount)}`);
        const payload = await response.json();
        if (!response.ok || !Array.isArray(payload.history)) {
            state.historyItems = localHistory;
            saveHistoryToStorage(localHistory);
            renderHistory();
            return;
        }

        state.historyItems = mergeHistory(payload.history, localHistory);
        saveHistoryToStorage(state.historyItems);
        renderHistory();
    } catch (_error) {
        state.historyItems = localHistory;
        renderHistory();
    }
}

async function clearHistoryOnServer() {
    try {
        const response = await fetch("/history/clear", { method: "DELETE" });
        if (!response.ok) {
            showError("Failed to clear database history.");
            return;
        }

        localStorage.removeItem(HISTORY_STORAGE_KEY);
        state.historyItems = [];
        state.historyVisibleCount = HISTORY_PAGE_SIZE;
        renderHistory();
    } catch (_error) {
        showError("Failed to clear database history.");
    }
}

function setupRing() {
    el.ringProgress.style.strokeDasharray = `${RING_CIRCUMFERENCE}`;
    el.ringProgress.style.strokeDashoffset = `${RING_CIRCUMFERENCE}`;
}

function animateRiskRing(score, color) {
    const clamped = Math.max(0, Math.min(100, score));
    const endOffset = RING_CIRCUMFERENCE * (1 - clamped / 100);
    const startOffset = RING_CIRCUMFERENCE;
    const duration = 850;
    const start = performance.now();

    el.ringProgress.classList.remove("green", "yellow", "orange", "red", "gray");
    el.ringProgress.classList.add(color || "gray");

    function step(now) {
        const progress = Math.min(1, (now - start) / duration);
        const eased = 1 - Math.pow(1 - progress, 3);
        const offset = startOffset + (endOffset - startOffset) * eased;
        const scoreNow = Math.round(clamped * eased);

        el.ringProgress.style.strokeDashoffset = `${offset}`;
        el.scoreValue.textContent = `${scoreNow}%`;

        if (progress < 1) {
            window.requestAnimationFrame(step);
        }
    }

    window.requestAnimationFrame(step);
}

function renderSingleResult(result) {
    el.singleResultPanel.classList.remove("hidden");
    el.batchResultPanel.classList.add("hidden");

    animateRiskRing(result.risk_score, result.color);

    el.riskLevelText.textContent = result.risk_level;
    el.riskLevelText.className = "";
    el.riskLevelText.classList.add("risk-text", result.color || "gray");

    el.confidenceText.textContent = `${result.confidence}%`;
    el.analyzedUrl.textContent = result.normalized_url || result.url;
    el.recommendationText.textContent = result.recommendation || "-";

    renderExternalSignals(result.external_signals || {}, result.scoring_details || {});

    renderReasonGroups(result.reason_groups || {});
    el.singleResultPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderExternalSignals(externalSignals, scoringDetails) {
    const typosquatMatch = scoringDetails.typosquat_match;
    if (typosquatMatch) {
        el.typosquatText.textContent = `${typosquatMatch.domain} is close to ${typosquatMatch.matched_brand} (edit distance ${typosquatMatch.distance})`;
    } else {
        el.typosquatText.textContent = "No typosquatting match detected.";
    }

    const sslCert = externalSignals.ssl_certificate || {};
    const sslPieces = [];
    if (sslCert.checked) {
        sslPieces.push(sslCert.valid ? "valid certificate" : "certificate issue detected");
        if (sslCert.issuer) {
            sslPieces.push(`issuer: ${sslCert.issuer}`);
        }
        if (typeof sslCert.expires_in_days === "number") {
            sslPieces.push(`expires in ${sslCert.expires_in_days} day(s)`);
        }
        if (sslCert.error) {
            sslPieces.push(`note: ${sslCert.error}`);
        }
    } else {
        sslPieces.push(sslCert.error || "SSL inspection skipped");
    }
    el.sslCertText.textContent = sslPieces.join(" | ");

    const blocklist = externalSignals.realtime_blocklist || {};
    if (blocklist.checked) {
        el.blocklistText.textContent = blocklist.listed
            ? `Matched ${blocklist.matched_on || "url"} against public feed(s): ${(blocklist.sources || []).join(", ") || "unknown"}`
            : `No match found in cached public feeds${blocklist.sources && blocklist.sources.length ? ` (${blocklist.sources.join(", ")})` : ""}`;
    } else {
        el.blocklistText.textContent = blocklist.error || "Blocklist check skipped";
    }

    const interactionBits = [];
    if (typeof scoringDetails.weighted_sum === "number") {
        interactionBits.push(`Base weight sum ${scoringDetails.weighted_sum}`);
    }
    if (typeof scoringDetails.interaction_bonus === "number") {
        interactionBits.push(`interaction bonus +${scoringDetails.interaction_bonus.toFixed(3)}`);
    }
    const categoryMix = scoringDetails.category_mix || {};
    if (Object.keys(categoryMix).length) {
        interactionBits.push(
            `mix D:${categoryMix.domain || 0} K:${categoryMix.keyword || 0} S:${categoryMix.structural || 0} E:${categoryMix.encoding || 0}`
        );
    }
    if (Array.isArray(scoringDetails.interaction_reasons) && scoringDetails.interaction_reasons.length) {
        interactionBits.push(scoringDetails.interaction_reasons.join("; "));
    }
    el.interactionText.textContent = interactionBits.length ? interactionBits.join(" | ") : "No interaction details available.";
}

function renderReasonGroups(reasonGroups) {
    const categories = ["Structural", "Keyword-Based", "Encoding-Based", "Domain-Based"];
    el.reasonGroupWrap.innerHTML = "";

    categories.forEach((category) => {
        const entries = Array.isArray(reasonGroups[category]) ? reasonGroups[category] : [];

        const card = document.createElement("article");
        card.className = "reason-card";
        card.setAttribute("tabindex", "0");

        const heading = document.createElement("h4");
        heading.textContent = `${category} (${entries.length})`;
        card.appendChild(heading);

        const list = document.createElement("ul");

        if (!entries.length) {
            const li = document.createElement("li");
            li.className = "reason-empty";
            li.textContent = "No triggered rules in this category.";
            list.appendChild(li);
        } else {
            entries.forEach((entry) => {
                const li = document.createElement("li");
                li.className = "reason-item";

                const badge = document.createElement("span");
                badge.className = `severity-badge ${String(entry.severity || "Low").toLowerCase()}`;
                badge.textContent = entry.severity || "Low";

                const text = document.createElement("span");
                text.textContent = entry.message || "Triggered.";

                li.appendChild(badge);
                li.appendChild(text);
                list.appendChild(li);
            });
        }

        card.appendChild(list);
        el.reasonGroupWrap.appendChild(card);
    });
}

function handleCopyResult() {
    if (!state.lastSingleResult) {
        showError("No single analysis result available to copy.");
        return;
    }

    const result = state.lastSingleResult;
    const reasons = (result.reasons || [])
        .map((item) => `- [${item.category} | ${item.severity}] ${item.message}`)
        .join("\n");

    const text = [
        "Advanced Phishing Detection Result",
        `URL: ${result.url}`,
        `Normalized URL: ${result.normalized_url || "-"}`,
        `Risk Score: ${result.risk_score}%`,
        `Risk Level: ${result.risk_level}`,
        `Confidence: ${result.confidence}%`,
        `Recommendation: ${result.recommendation}`,
        `Typosquatting Match: ${result.scoring_details && result.scoring_details.typosquat_match ? `${result.scoring_details.typosquat_match.domain} -> ${result.scoring_details.typosquat_match.matched_brand} (distance ${result.scoring_details.typosquat_match.distance})` : "None"}`,
        `SSL Certificate: ${result.external_signals && result.external_signals.ssl_certificate ? (result.external_signals.ssl_certificate.valid ? "valid" : "issue detected") : "Unavailable"}`,
        `Blocklist: ${result.external_signals && result.external_signals.realtime_blocklist ? (result.external_signals.realtime_blocklist.listed ? "matched" : "not listed") : "Unavailable"}`,
        `Score Interaction: ${result.scoring_details ? `weighted_sum=${result.scoring_details.weighted_sum}, interaction_bonus=${result.scoring_details.interaction_bonus}` : "Unavailable"}`,
        "Reasons:",
        reasons || "- No reasons",
    ].join("\n");

    navigator.clipboard.writeText(text).then(() => {
        const oldLabel = el.copyResultBtn.textContent;
        el.copyResultBtn.textContent = "Copied";
        window.setTimeout(() => {
            el.copyResultBtn.textContent = oldLabel;
        }, 1200);
    }).catch(() => {
        showError("Clipboard copy failed in this browser context.");
    });
}

function handleSort(sortKey) {
    if (state.sort.key === sortKey) {
        state.sort.dir = state.sort.dir === "asc" ? "desc" : "asc";
    } else {
        state.sort.key = sortKey;
        state.sort.dir = "asc";
    }
    renderBatchResults();
}

function renderBatchResults() {
    const rows = [...state.batchResults];

    rows.sort((a, b) => {
        const key = state.sort.key;
        const dirMultiplier = state.sort.dir === "asc" ? 1 : -1;

        if (key === "risk_score") {
            return (a.risk_score - b.risk_score) * dirMultiplier;
        }

        if (key === "timestamp") {
            return (new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()) * dirMultiplier;
        }

        return String(a[key] || "").localeCompare(String(b[key] || "")) * dirMultiplier;
    });

    el.batchTableBody.innerHTML = "";

    rows.forEach((row) => {
        const tr = document.createElement("tr");

        tr.innerHTML = `
            <td title="${escapeHtml(row.url)}">${escapeHtml(row.url)}</td>
            <td><span class="score-pill ${escapeHtml(row.color || "gray")}">${row.risk_score}%</span></td>
            <td>${escapeHtml(row.risk_level)}</td>
            <td>${escapeHtml(formatTimestamp(row.timestamp))}</td>
        `;

        el.batchTableBody.appendChild(tr);
    });

    el.batchResultPanel.classList.remove("hidden");
    el.singleResultPanel.classList.add("hidden");
}

function getFilteredHistory() {
    const q = el.historySearchInput.value.trim().toLowerCase();
    const riskFilter = el.historyRiskFilter.value;

    return state.historyItems.filter((item) => {
        const matchesQuery = !q
            || String(item.url || "").toLowerCase().includes(q)
            || String(item.risk_level || "").toLowerCase().includes(q);

        const normalizedLevel = String(item.risk_level || "").toLowerCase();
        const matchesRisk = riskFilter === "all" || normalizedLevel === riskFilter;

        return matchesQuery && matchesRisk;
    });
}

function renderHistory() {
    const filtered = getFilteredHistory();
    const visible = filtered.slice(0, state.historyVisibleCount);

    el.historyList.innerHTML = "";

    if (!visible.length) {
        const empty = document.createElement("p");
        empty.className = "empty-state";
        empty.textContent = "No matching history records.";
        el.historyList.appendChild(empty);
    } else {
        visible.forEach((item) => {
            const card = document.createElement("article");
            card.className = "history-item";
            card.setAttribute("tabindex", "0");

            card.innerHTML = `
                <div class="history-meta">
                    <div class="url" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</div>
                    <div class="sub">${escapeHtml(formatTimestamp(item.created_at || item.timestamp))} | ${escapeHtml(item.analysis_mode || "single")}</div>
                </div>
                <div class="history-badges">
                    <span class="score-pill ${escapeHtml(item.color || "gray")}">${Number(item.risk_score || 0)}%</span>
                    <span class="risk-chip">${escapeHtml(item.risk_level || "-")}</span>
                </div>
            `;

            el.historyList.appendChild(card);
        });
    }

    const showing = Math.min(filtered.length, state.historyVisibleCount);
    el.historyInfo.textContent = `${showing} of ${filtered.length} item(s)`;

    const canLoadMore = filtered.length > state.historyVisibleCount;
    el.loadMoreHistoryBtn.classList.toggle("hidden", !canLoadMore);
}

function exportHistoryAsCsv() {
    const history = getFilteredHistory();
    if (!history.length) {
        showError("No history available for CSV export.");
        return;
    }

    const columns = ["url", "normalized_url", "risk_score", "risk_level", "confidence", "analysis_mode", "created_at"];

    const lines = [columns.join(",")];
    history.forEach((row) => {
        const values = columns.map((col) => csvEscape(row[col]));
        lines.push(values.join(","));
    });

    const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `phishing-history-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
}

function csvEscape(value) {
    const safe = String(value ?? "").replace(/"/g, '""');
    return `"${safe}"`;
}

function toggleTheme() {
    const next = el.body.dataset.theme === "light" ? "dark" : "light";
    applyTheme(next);
    localStorage.setItem(THEME_KEY, next);
}

function restoreTheme() {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === "light" || saved === "dark") {
        applyTheme(saved);
        return;
    }

    applyTheme("dark");
}

function applyTheme(theme) {
    el.body.dataset.theme = theme;
    el.themeToggleText.textContent = theme === "dark" ? "Light Mode" : "Dark Mode";
}

function formatTimestamp(timestamp) {
    const d = new Date(timestamp);
    if (Number.isNaN(d.getTime())) {
        return "-";
    }
    return d.toLocaleString();
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

document.addEventListener("DOMContentLoaded", init);

window.addEventListener("load", () => {
    refreshHistory();
});

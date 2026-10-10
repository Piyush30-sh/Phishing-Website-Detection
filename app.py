"""
Main Flask application for the Advanced Phishing Detection Tool.

Features:
- Single URL analysis endpoint
- Batch URL analysis endpoint
- MongoDB-backed scan history
- In-memory rate limiting per client IP
- Health endpoint
- Input validation with explicit error messages
"""

from __future__ import annotations

import os
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import PyMongoError

from detector import analyze_url


# ---------------------------------------------------------------------------
# App and API configuration
# ---------------------------------------------------------------------------

APP_HOST = "0.0.0.0"
APP_PORT = 5000
DEBUG_MODE = True

RATE_LIMIT_REQUESTS = 30
RATE_LIMIT_WINDOW_SECONDS = 60
MAX_BATCH_SIZE = 100
MAX_HISTORY_LIMIT = 500
DEFAULT_HISTORY_LIMIT = 50

# Leave this blank and paste your MongoDB URI when you are ready.
# Example: mongodb://localhost:27017/
# Example Atlas URI: mongodb+srv://USERNAME:PASSWORD@CLUSTER_HOST/?retryWrites=true&w=majority
MONGODB_URI = os.getenv("MONGODB_URI", "")
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "phishing_detection")
MONGODB_COLLECTION_NAME = os.getenv("MONGODB_COLLECTION_NAME", "scan_history")
MONGODB_CONNECTION_TIMEOUT_MS = int(os.getenv("MONGODB_CONNECTION_TIMEOUT_MS", "2000"))

URL_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

app = Flask(__name__, template_folder="templates")


# ---------------------------------------------------------------------------
# In-memory rate limiter
# ---------------------------------------------------------------------------

_rate_limit_store: dict[str, deque[float]] = defaultdict(deque)
_rate_limit_lock = threading.Lock()


# ---------------------------------------------------------------------------
# MongoDB helpers
# ---------------------------------------------------------------------------

_mongo_client: MongoClient | None = None
_mongo_collection: Collection | None = None
_mongo_lock = threading.Lock()
_mongo_error: str = ""


def _ensure_mongo_connection() -> Collection | None:
    """Create a cached MongoDB collection handle when a URI is configured."""
    global _mongo_client, _mongo_collection, _mongo_error

    if _mongo_collection is not None:
        return _mongo_collection

    if not MONGODB_URI.strip():
        _mongo_error = "MONGODB_URI is empty"
        return None

    with _mongo_lock:
        if _mongo_collection is not None:
            return _mongo_collection

        try:
            client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=MONGODB_CONNECTION_TIMEOUT_MS)
            client.admin.command("ping")
            collection = client[MONGODB_DB_NAME][MONGODB_COLLECTION_NAME]
            collection.create_index([("created_at", -1)])
            collection.create_index([("url", 1)])
            collection.create_index([("risk_level", 1)])
            _mongo_client = client
            _mongo_collection = collection
            _mongo_error = ""
            return collection
        except PyMongoError as exc:
            _mongo_client = None
            _mongo_collection = None
            _mongo_error = str(exc)
            return None


def _database_status() -> dict[str, Any]:
    """Return current MongoDB connectivity information."""
    collection = _ensure_mongo_connection()
    return {
        "enabled": bool(MONGODB_URI.strip()),
        "connected": collection is not None,
        "database": MONGODB_DB_NAME,
        "collection": MONGODB_COLLECTION_NAME,
        "error": _mongo_error,
    }


def _serialize_scan_document(document: dict[str, Any]) -> dict[str, Any]:
    """Convert MongoDB documents into JSON-safe API payloads."""
    payload = dict(document)
    payload["id"] = str(payload.pop("_id", ""))

    created_at = payload.get("created_at")
    if isinstance(created_at, datetime):
        payload["created_at"] = created_at.replace(tzinfo=timezone.utc).isoformat()
    elif created_at is None:
        payload["created_at"] = ""

    return payload


def _save_scan_result(result: dict[str, Any], analysis_mode: str, client_ip: str) -> None:
    """Persist one scan result to MongoDB if the database is configured."""
    collection = _ensure_mongo_connection()
    if collection is None:
        return

    document = {
        "url": result.get("url", ""),
        "normalized_url": result.get("normalized_url", ""),
        "risk_score": result.get("risk_score", 0),
        "risk_level": result.get("risk_level", "Invalid"),
        "color": result.get("color", "gray"),
        "confidence": result.get("confidence", 0),
        "recommendation": result.get("recommendation", ""),
        "reasons": result.get("reasons", []),
        "reason_groups": result.get("reason_groups", {}),
        "external_signals": result.get("external_signals", {}),
        "scoring_details": result.get("scoring_details", {}),
        "triggered_rules": result.get("triggered_rules", 0),
        "total_rules_checked": result.get("total_rules_checked", 0),
        "analysis_mode": analysis_mode,
        "client_ip": client_ip,
        "created_at": datetime.now(timezone.utc),
    }

    try:
        collection.insert_one(document)
    except PyMongoError:
        # Keep the API functional even if persistence fails.
        pass


def _fetch_scan_history(limit: int) -> list[dict[str, Any]]:
    """Return recent scan history records from MongoDB."""
    collection = _ensure_mongo_connection()
    if collection is None:
        return []

    limit = max(1, min(MAX_HISTORY_LIMIT, limit))
    try:
        cursor = collection.find({}, {}).sort("created_at", -1).limit(limit)
        documents = list(cursor)
        return [_serialize_scan_document(document) for document in documents]
    except PyMongoError:
        return []


def _clear_scan_history() -> int:
    """Delete all scan history records from MongoDB."""
    collection = _ensure_mongo_connection()
    if collection is None:
        return 0

    try:
        result = collection.delete_many({})
        return int(result.deleted_count)
    except PyMongoError:
        return 0


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


def _get_client_ip() -> str:
    """Return best-effort client IP, honoring X-Forwarded-For if present."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip() or "unknown"
    return request.remote_addr or "unknown"


def _is_rate_limited(client_ip: str) -> tuple[bool, int]:
    """Check and update request counters for a client IP."""
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW_SECONDS

    with _rate_limit_lock:
        timestamps = _rate_limit_store[client_ip]

        while timestamps and timestamps[0] < window_start:
            timestamps.popleft()

        if len(timestamps) >= RATE_LIMIT_REQUESTS:
            retry_after = max(1, int(RATE_LIMIT_WINDOW_SECONDS - (now - timestamps[0])))
            return True, retry_after

        timestamps.append(now)
        return False, 0


def _rate_limit_response(retry_after: int):
    """Return standardized 429 response payload."""
    response = jsonify(
        {
            "error": "Rate limit exceeded. Please retry later.",
            "limit": RATE_LIMIT_REQUESTS,
            "window_seconds": RATE_LIMIT_WINDOW_SECONDS,
            "retry_after_seconds": retry_after,
        }
    )
    response.status_code = 429
    response.headers["Retry-After"] = str(retry_after)
    return response


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _normalize_for_validation(url: str) -> str:
    """Add scheme for parsing when input omits it."""
    stripped = url.strip()
    if not URL_SCHEME_RE.match(stripped):
        return f"http://{stripped}"
    return stripped


def _validate_url_value(value: Any) -> tuple[bool, str]:
    """Validate URL shape before analysis."""
    if not isinstance(value, str):
        return False, "URL must be a string."

    url = value.strip()
    if not url:
        return False, "URL cannot be empty."

    if len(url) > 2048:
        return False, "URL is too long. Maximum length is 2048 characters."

    parsed = urlparse(_normalize_for_validation(url))
    if not parsed.hostname:
        return False, "Malformed URL. Expected a valid host name or IP."

    return True, ""


def _parse_single_payload(payload: Any) -> tuple[bool, str, str]:
    """Parse and validate single URL payload."""
    if not isinstance(payload, dict):
        return False, "", "Request body must be a JSON object with a 'url' field."

    if "url" not in payload:
        return False, "", "Missing required field: 'url'."

    url_value = payload.get("url")
    ok, error = _validate_url_value(url_value)
    if not ok:
        return False, "", error

    return True, str(url_value).strip(), ""


def _parse_batch_payload(payload: Any) -> tuple[bool, list[str], str]:
    """Parse and validate batch URL payload."""
    urls: Any

    if isinstance(payload, list):
        urls = payload
    elif isinstance(payload, dict) and "urls" in payload:
        urls = payload.get("urls")
    else:
        return False, [], "Batch request must be a JSON array or an object with 'urls' array."

    if not isinstance(urls, list):
        return False, [], "'urls' must be an array of URL strings."

    if not urls:
        return False, [], "URL list cannot be empty."

    if len(urls) > MAX_BATCH_SIZE:
        return False, [], f"Batch size exceeds maximum of {MAX_BATCH_SIZE} URLs."

    validated: list[str] = []
    for idx, item in enumerate(urls):
        ok, error = _validate_url_value(item)
        if not ok:
            return False, [], f"Invalid URL at index {idx}: {error}"
        validated.append(str(item).strip())

    return True, validated, ""


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------

@app.before_request
def enforce_rate_limit():
    """Rate-limit API endpoints to reduce abuse risk."""
    if request.path not in {"/analyze", "/analyze/batch", "/history", "/history/clear"}:
        return None

    limited, retry_after = _is_rate_limited(_get_client_ip())
    if limited:
        return _rate_limit_response(retry_after)

    return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Render the application UI."""
    return render_template("index.html")


@app.route("/health", methods=["GET"])
def health():
    """Return basic API health status."""
    status = {
        "status": "ok",
        "service": "phishing-detection-api",
        "timestamp": int(time.time()),
        "database": _database_status(),
    }
    return jsonify(status), 200


@app.route("/history", methods=["GET"])
def get_history():
    """Return recent scan history from MongoDB."""
    limit_raw = request.args.get("limit", str(DEFAULT_HISTORY_LIMIT))
    try:
        limit = int(limit_raw)
    except ValueError:
        return jsonify({"error": "'limit' must be an integer."}), 400

    history = _fetch_scan_history(limit)
    return jsonify({"history": history, "count": len(history), "database": _database_status()}), 200


@app.route("/history/clear", methods=["DELETE"])
def clear_history():
    """Delete all stored scan history records from MongoDB."""
    deleted_count = _clear_scan_history()
    return jsonify({"deleted_count": deleted_count, "database": _database_status()}), 200


@app.route("/analyze", methods=["POST"])
def analyze_single():
    """Analyze one URL, persist the result, and return the analysis object."""
    payload = request.get_json(silent=True)
    ok, url, error = _parse_single_payload(payload)
    if not ok:
        return jsonify({"error": error}), 400

    result = analyze_url(url)
    _save_scan_result(result, "single", _get_client_ip())
    return jsonify(result), 200


@app.route("/analyze/batch", methods=["POST"])
def analyze_batch():
    """Analyze a list of URLs, persist the results, and return a JSON array."""
    payload = request.get_json(silent=True)
    ok, urls, error = _parse_batch_payload(payload)
    if not ok:
        return jsonify({"error": error}), 400

    client_ip = _get_client_ip()
    results = [analyze_url(url) for url in urls]
    for result in results:
        _save_scan_result(result, "batch", client_ip)

    return jsonify(results), 200


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def page_not_found(_err):
    """Return JSON 404 for unknown API routes."""
    if request.path.startswith("/analyze") or request.path.startswith("/health") or request.path.startswith("/history"):
        return jsonify({"error": "Route not found."}), 404
    return render_template("index.html"), 200


@app.errorhandler(405)
def method_not_allowed(_err):
    """Return JSON 405 for unsupported methods."""
    return jsonify({"error": "Method not allowed for this route."}), 405


@app.errorhandler(500)
def internal_server_error(_err):
    """Return JSON 500 response."""
    return jsonify({"error": "Internal server error."}), 500


if __name__ == "__main__":
    app.run(debug=DEBUG_MODE, host=APP_HOST, port=APP_PORT)

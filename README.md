# Advanced Phishing Detection Tool

A Flask web app for analyzing individual URLs or batches of URLs with explainable, rule-based phishing risk scoring. Results include a risk score, triggered rules, recommendations, and supporting signals.

## Features

- Analyze one URL or a batch of up to 100 URLs.
- Review categorized detection reasons, risk scores, and recommendations.
- Inspect HTTPS certificate details and check public phishing blocklists.
- Search, filter, sort, and export scan history as CSV.
- Keep history in the browser, or enable MongoDB persistence.
- Use the JSON API and health endpoint.

## Requirements

- Python 3.10 or later
- Internet access for live blocklist and HTTPS certificate checks
- MongoDB is optional; without it, browser-side history still works

## Run locally

From the project directory, create and activate a virtual environment, then install the dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

On macOS or Linux, activate the environment with `source .venv/bin/activate` instead.

Start the app:

```powershell
python app.py
```

Open <http://127.0.0.1:5000> in your browser. The built-in Flask server is for local development only; do not use it as a public production server.

## MongoDB (optional)

Set `MONGODB_URI` in your environment to enable server-side scan history. The database and collection default to `phishing_detection` and `scan_history`.

PowerShell example:

```powershell
$env:MONGODB_URI = "mongodb://localhost:27017/"
python app.py
```

Optional settings are `MONGODB_DB_NAME`, `MONGODB_COLLECTION_NAME`, and `MONGODB_CONNECTION_TIMEOUT_MS`. Keep database credentials in environment variables or a local, untracked `.env` file; never commit secrets.

## API

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/health` | App and database status |
| `POST` | `/analyze` | Analyze one URL; JSON body: `{"url":"https://example.com"}` |
| `POST` | `/analyze/batch` | Analyze up to 100 URLs; JSON body: `{"urls":["https://example.com"]}` |
| `GET` | `/history?limit=50` | Return saved MongoDB scan history |
| `DELETE` | `/history/clear` | Clear saved MongoDB scan history |

Analysis endpoints accept a URL with or without an `http://` or `https://` scheme. API requests are limited to 30 per client IP per minute.

## How analysis works

The detector uses deterministic heuristics; it is not a machine-learning model and cannot guarantee that a URL is safe or malicious. HTTPS certificate inspection connects to the analyzed host, and the live blocklist check fetches public feeds. These checks require network access, can affect response time, and may be unavailable when remote services are unreachable. Treat results as an additional signal, not as a substitute for security review.

## Project structure

```text
app.py                 Flask app, web routes, and JSON API
detector.py            URL analysis rules and supporting checks
templates/index.html   Main page
static/script.js       Browser interactions
static/style.css       App styles
requirements.txt       Python dependencies
```

## GitHub notes

The source can be uploaded as a repository. There is no license file included; choose and add a license before granting others permission to use or redistribute the project. No automated test suite is included yet.

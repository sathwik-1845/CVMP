"""
server.py  —  Bridge between the dashboard and OpenCTI
------------------------------------------------------
Serves the dashboard HTML and proxies GraphQL requests
to OpenCTI, adding the auth token server-side.

Install:  pip install flask flask-cors requests python-dotenv
Run:      python server.py
Open:     http://localhost:5000
"""

import json
import os

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

load_dotenv()

OPENCTI_URL = os.getenv("OPENCTI_URL", "http://localhost:8500/graphql")
TOKEN       = os.getenv("OPENCTI_TOKEN", "")
TIMEOUT     = 60

app = Flask(__name__, static_folder=".")
CORS(app)


# ── Serve dashboard ──────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(".", "dashboard.html")


# ── Health check ─────────────────────────────────────────────────
@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "opencti": OPENCTI_URL})


# ── Fetch observables from OpenCTI ───────────────────────────────
@app.route("/api/observables")
def get_observables():
    query = """
    query GetObservables {
      stixCyberObservables(first: 100) {
        edges {
          node {
            id
            entity_type
            observable_value
            created_at
            indicators {
              edges {
                node {
                  id
                  name
                }
              }
            }
          }
        }
      }
    }
    """
    data, error = opencti_query(query)
    if error:
        return jsonify({"error": error}), 500

    observables = [
        {
            "id":         e["node"]["id"],
            "type":       e["node"]["entity_type"],
            "value":      e["node"]["observable_value"],
            "created_at": e["node"]["created_at"],
        }
        for e in data.get("stixCyberObservables", {}).get("edges", [])
    ]
    return jsonify(observables)


# ── Fetch indicators from OpenCTI ────────────────────────────────
@app.route("/api/indicators")
def get_indicators():
    query = """
    query GetIndicators {
      indicators(first: 100) {
        edges {
          node {
            id
            name
            pattern
            created_at
            confidence
            revoked
          }
        }
      }
    }
    """
    data, error = opencti_query(query)
    if error:
        return jsonify({"error": error}), 500

    indicators = [
        {
            "id":         e["node"]["id"],
            "name":       e["node"]["name"],
            "pattern":    e["node"]["pattern"],
            "created_at": e["node"]["created_at"],
            "confidence": e["node"]["confidence"],
            "revoked":    e["node"]["revoked"],
        }
        for e in data.get("indicators", {}).get("edges", [])
    ]
    return jsonify(indicators)


# ── Fetch reports from OpenCTI ───────────────────────────────────
@app.route("/api/reports")
def get_reports():
    query = """
    query GetReports {
      reports(first: 50) {
        edges {
          node {
            id
            name
            description
            created_at
            confidence
          }
        }
      }
    }
    """
    data, error = opencti_query(query)
    if error:
        return jsonify({"error": error}), 500

    reports = [
        {
            "id":          e["node"]["id"],
            "name":        e["node"]["name"],
            "description": e["node"]["description"],
            "created_at":  e["node"]["created_at"],
            "confidence":  e["node"]["confidence"],
        }
        for e in data.get("reports", {}).get("edges", [])
    ]
    return jsonify(reports)


# ── Local vuln_results.json ──────────────────────────────────────
@app.route("/api/vulns")
def get_vulns():
    path = os.path.join(os.path.dirname(__file__), "vuln_results.json")
    if not os.path.exists(path):
        return jsonify([])
    results = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return jsonify(results)


# ── Helper ───────────────────────────────────────────────────────
def opencti_query(query: str, variables: dict = None):
    if not TOKEN:
        return None, "OPENCTI_TOKEN not set in .env"
    try:
        resp = requests.post(
            OPENCTI_URL,
            json={"query": query, "variables": variables or {}},
            headers={
                "Authorization": f"Bearer {TOKEN}",
                "Content-Type": "application/json",
            },
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        body = resp.json()
        if "errors" in body:
            return None, body["errors"][0].get("message", "GraphQL error")
        return body.get("data", {}), None
    except requests.exceptions.ConnectionError:
        return None, f"Cannot reach OpenCTI at {OPENCTI_URL}"
    except requests.exceptions.Timeout:
        return None, "OpenCTI request timed out"
    except Exception as e:
        return None, str(e)


if __name__ == "__main__":
    print(f"  Dashboard : http://localhost:5000")
    print(f"  OpenCTI   : {OPENCTI_URL}")
    print(f"  Token set : {'YES' if TOKEN else 'NO — set OPENCTI_TOKEN in .env'}")
    app.run(debug=True, port=5000)





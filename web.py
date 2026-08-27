#!/usr/bin/env python3
"""
web.py — Flask web front-end for the Phishing / Malicious URL Scanner.

Run with:
    python web.py
Then open http://localhost:5000
"""

from flask import Flask, render_template, request, jsonify

from app.scanner import scan_url

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", result=None)


@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url", "").strip()
    if not url:
        return render_template("index.html", result=None, error="Please enter a URL.")
    result = scan_url(url)
    return render_template("index.html", result=result, error=None)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "Missing 'url' field"}), 400
    result = scan_url(url)
    return jsonify(result.to_dict())


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

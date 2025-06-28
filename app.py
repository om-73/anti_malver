from flask import Flask, request, render_template
import os
import hashlib
import requests
import time
import base64

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

VIRUSTOTAL_API_KEY = "f5f439718c900ca3b5e9efad27196385a31a4243900d348cde425da4d23905aa"  # Replace with your key

def get_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def scan_file(file_path):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    with open(file_path, 'rb') as f:
        response = requests.post("https://www.virustotal.com/api/v3/files", files={"file": f}, headers=headers)
    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        return get_report(analysis_id, is_url=False)
    return f"<p class='error'>❌ File Scan Error: {response.status_code} – {response.text}</p>"

def scan_url(url_to_scan):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={'url': url_to_scan})
    if response.status_code == 200:
        url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
        return get_report(url_id, is_url=True)
    return f"<p class='error'>❌ URL Scan Error: {response.status_code} – {response.text}</p>"

def get_report(scan_id, is_url=False):
    time.sleep(10)  # Give time for VirusTotal to process
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    endpoint = f"https://www.virustotal.com/api/v3/{'urls' if is_url else 'analyses'}/{scan_id}"
    response = requests.get(endpoint, headers=headers)
    if response.status_code != 200:
        return f"<p class='error'>❌ Report Fetch Error: {response.status_code} – {response.text}</p>"

    data = response.json().get('data', {}).get('attributes', {})
    stats = data.get('last_analysis_stats' if is_url else 'stats', {})
    results = data.get('last_analysis_results' if is_url else 'results', {})

    score_color = "red" if stats.get('malicious', 0) > 0 else "green"
    html = f"<p><strong>Score:</strong> <span style='color:{score_color};'>{stats.get('malicious', 0)} / {sum(stats.values())}</span></p>"
    html += "<table border='1' cellspacing='0' cellpadding='5'><tr><th>Engine</th><th>Result</th><th>Category</th></tr>"
    for engine, info in results.items():
        result = info.get('result') or 'Clean'
        category = info.get('category') or 'unknown'
        color = "red" if category in ['malicious', 'suspicious'] else "black"
        html += f"<tr><td>{engine}</td><td style='color:{color};'>{result}</td><td style='color:{color};'>{category}</td></tr>"
    html += "</table>"
    return html

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ""
    if request.method == 'POST':
        file = request.files.get('file')
        url_input = request.form.get('url')

        if file and file.filename:
            file_path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(file_path)
            md5 = get_md5(file_path)
            result += f"<p>🗂 <strong>File:</strong> {file.filename}</p><p>🔑 <strong>MD5:</strong> {md5}</p>"
            result += scan_file(file_path)
            os.remove(file_path)

        if url_input:
            result += f"<p>🔗 <strong>URL:</strong> {url_input}</p>"
            result += scan_url(url_input)

        if not file and not url_input:
            result = "<p class='error'>⚠️ Please provide a file or a URL.</p>"

    return render_template("index.html", result=result)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5050))  # default to 5050 if not specified
    app.run(host='0.0.0.0', port=port)


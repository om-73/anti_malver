

from flask import Flask, request, render_template
import os
import hashlib
import requests
import time
import base64

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

VIRUSTOTAL_API_KEY = "f5f439718c900ca3b5e9efad27196385a31a4243900d348cde425da4d23905aa"  # Replace with your API key

def get_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def scan_file(file_path):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    with open(file_path, 'rb') as f:
        upload_response = requests.post("https://www.virustotal.com/api/v3/files", files={"file": f}, headers=headers)
    if upload_response.status_code != 200:
        return f"<p class='error'>❌ File Upload Error: {upload_response.status_code} – {upload_response.text}</p>"

    analysis_id = upload_response.json().get("data", {}).get("id")
    if not analysis_id:
        return "<p class='error'>❌ Could not get analysis ID from VirusTotal.</p>"

    # Poll for completion
    for _ in range(10):
        status_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        if status_response.status_code == 200:
            status_data = status_response.json()
            if status_data.get("data", {}).get("attributes", {}).get("status") == "completed":
                file_hash = status_data.get("meta", {}).get("file_info", {}).get("md5")
                if file_hash:
                    return get_file_report(file_hash)
        time.sleep(3)
    return "<p class='error'>❌ Report not ready after waiting. Try again later.</p>"

def get_file_report(file_hash):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)
    if response.status_code != 200:
        return f"<p class='error'>❌ Report Fetch Error: {response.status_code} – {response.text}</p>"

    data = response.json().get('data', {}).get('attributes', {})
    stats = data.get('last_analysis_stats', {})
    results = data.get('last_analysis_results', {})

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

def scan_url(url_to_scan):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={'url': url_to_scan})
    if response.status_code != 200:
        return f"<p class='error'>❌ URL Scan Error: {response.status_code} – {response.text}</p>"

    url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
    time.sleep(10)  # Wait briefly for analysis
    return get_url_report(url_id)

def get_url_report(url_id):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
    if response.status_code != 200:
        return f"<p class='error'>❌ URL Report Error: {response.status_code} – {response.text}</p>"

    data = response.json().get('data', {}).get('attributes', {})
    stats = data.get('last_analysis_stats', {})
    results = data.get('last_analysis_results', {})

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
        # Clean previous files
        for f in os.listdir(UPLOAD_FOLDER):
            try:
                os.remove(os.path.join(UPLOAD_FOLDER, f))
            except:
                pass

        file = request.files.get('file')
        url_input = request.form.get('url')

        if file and file.filename:
            file_path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(file_path)
            md5 = get_md5(file_path)
            result += f"<p>🗂 <strong>File:</strong> {file.filename}</p><p>🔑 <strong>MD5:</strong> {md5}</p>"
            result += scan_file(file_path)
            os.remove(file_path)

        elif url_input:
            result += f"<p>🔗 <strong>URL:</strong> {url_input}</p>"
            result += scan_url(url_input)

        else:
            result = "<p class='error'>⚠️ Please provide a file or a URL.</p>"

    return render_template("index.html", result=result)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5050))
    app.run(host='0.0.0.0', port=port)

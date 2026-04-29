from flask import Flask, request
import requests
import json
import os
import numpy as np
from sklearn.linear_model import LogisticRegression

app = Flask(__name__)

import os
API_KEY = os.environ.get("API_KEY")
# ---------------- ML MODEL ----------------
X = np.array([
    [0, 0], [5, 1], [10, 2],
    [30, 10], [45, 20], [60, 30],
    [75, 50], [85, 80], [95, 120]
])

y = np.array([
    0, 0, 0,
    1, 1, 1,
    2, 2, 2
])

model = LogisticRegression()
model.fit(X, y)
# ------------------------------------------

@app.route('/', methods=['GET', 'POST'])
def home():
    result = ""
    history_html = "<h3>Recent Scans</h3>"
    ip_value = ""

    #  DEFAULT VALUES 
    color = "#38bdf8"
    status = ""
    message = ""
    anomaly = ""
    country = ""
    isp = ""
    reports = 0
    abuse_score = 0
    width = 0

    if request.method == 'POST':
        ip_value = request.form.get('ip')

        # Auto detect
        if request.form.get('auto') == "1":
            ip_value = requests.get('https://api.ipify.org').text

        try:
            #  AbuseIPDB
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {'Accept': 'application/json', 'Key': API_KEY}
            params = {'ipAddress': ip_value, 'maxAgeInDays': '90'}

            res = requests.get(url, headers=headers, params=params)
            data = res.json()

            abuse_score = data['data']['abuseConfidenceScore']
            reports = data['data']['totalReports']

            #  Geo
            geo = requests.get(f"http://ip-api.com/json/{ip_value}").json()
            country = geo.get("country", "Unknown")
            city = geo.get("city", "Unknown")
            isp = geo.get("isp", "Unknown")
            org = geo.get("org", "Unknown")

            #  ML Prediction
            prediction = model.predict([[abuse_score, reports]])[0]

            if prediction == 0:
                status = "LOW RISK 🟢"
                color = "#22c55e"
                message = "Low risk: minimal suspicious activity"
            elif prediction == 1:
                status = "MEDIUM RISK 🟡"
                color = "#facc15"
                message = "Moderate risk: some reports found"
            else:
                status = "HIGH RISK 🔴"
                color = "#ef4444"
                message = "High risk: reported multiple times"

            #  Anomaly Detection
            if abuse_score > 80 and reports < 5:
                anomaly = "⚠️ Unusual: High score but low reports"
            else:
                anomaly = "Normal pattern"

            width = max(abuse_score, 5)

            #  Save history
            entry = {"ip": ip_value, "status": status, "score": abuse_score}

            if os.path.exists("history.json"):
                with open("history.json", "r") as f:
                    history = json.load(f)
            else:
                history = []

            history.append(entry)

            with open("history.json", "w") as f:
                json.dump(history[-10:], f)

        except Exception as e:
            result = f"<p style='color:red;'>Error: {e}</p>"

    #  Load history
    try:
        with open("history.json", "r") as f:
            history = json.load(f)
            for item in reversed(history):
                history_html += f"<p>{item['ip']} → {item['status']}</p>"
    except:
        history_html += "<p>No history yet</p>"

    # 🎯 Result (only if valid)
    if ip_value and status:
        result = f"""
        <div class='result'>
            <p><b>IP:</b> {ip_value}</p>
            <p><b>Status:</b> <span style='color:{color}'>{status}</span></p>
            <p><b>ML Insight:</b> {message}</p>
            <p><b>Anomaly:</b> {anomaly}</p>
            <p><b>IP Location:</b> {city}, {country}</p>
<p><b>Server / ISP:</b> {org}</p>
<p><b>Real Location:</b> <span id="realLocation">Detecting...</span></p>

<!-- IP MAP -->
<iframe
    width="100%"
    height="150"
    style="border-radius:10px; margin-top:10px;"
    src="https://maps.google.com/maps?q={country}&z=5&output=embed">
</iframe>

<!-- REAL LOCATION MAP -->
<iframe
    id="realMap"
    width="100%"
    height="150"
    style="border-radius:10px; margin-top:10px;"
></iframe>
            
            <p><b>Reports:</b> {reports}</p>
            <p><b>Risk Score:</b> {abuse_score}</p>

            <div class="progress">
                <div class="bar" style="width:{width}%; background:{color};"></div>
            </div>
        </div>
        """

    return f"""
<!DOCTYPE html>
<html>
<head>
<title>IP Threat Checker</title>

<style>
body {{
    font-family: Arial;
    background: #0f172a;
    color: white;
    text-align: center;
    padding-top: 60px;
}}

.box {{
    background: #1e293b;
    padding: 30px;
    border-radius: 12px;
    display: inline-block;
    box-shadow: 0 0 25px rgba(0,0,0,0.6);
}}

input {{
    padding: 10px;
    width: 250px;
    border-radius: 6px;
    border: none;
}}

button {{
    padding: 10px 20px;
    margin: 5px;
    background: #38bdf8;
    border: none;
    border-radius: 6px;
    cursor: pointer;
}}

button:hover {{
    transform: scale(1.05);
}}

.progress {{
    width: 100%;
    background: #334155;
    border-radius: 10px;
    margin-top: 10px;
}}

.bar {{
    height: 15px;
    transition: width 1s;
}}

.loader {{
    border: 4px solid #1e293b;
    border-top: 4px solid #38bdf8;
    border-radius: 50%;
    width: 30px;
    height: 30px;
    animation: spin 1s linear infinite;
    margin: 10px auto;
    display: none;
}}

@keyframes spin {{
    0% {{ transform: rotate(0deg); }}
    100% {{ transform: rotate(360deg); }}
}}
</style>

<script>
function getRealLocation() {{
    if (!navigator.geolocation) {{
        document.getElementById("realLocation").innerText = "Not supported";
        return;
    }}

    navigator.geolocation.getCurrentPosition(
        async (position) => {{
            const lat = position.coords.latitude;
            const lon = position.coords.longitude;

            try {{
                const res = await fetch(`https://api.bigdatacloud.net/data/reverse-geocode-client?latitude=${{lat}}&longitude=${{lon}}&localityLanguage=en`);
                const data = await res.json();

                const city = data.city || data.locality || "Unknown";
                const country = data.countryName || "";

                document.getElementById("realLocation").innerText = city + ", " + country;

                document.getElementById("realMap").src =
                    `https://maps.google.com/maps?q=${{lat}},${{lon}}&z=12&output=embed`;

            }} catch {{
                document.getElementById("realLocation").innerText = lat + ", " + lon;
            }}
        }},
        () => {{
            document.getElementById("realLocation").innerText = "Permission denied";
        }}
    );
}}

getRealLocation();
</script>
</head>

<body>

<div class="box">
    <h2>IP Threat Checker 🔐</h2>

    <form method="POST" onsubmit="showLoader()">
        <input type="text" name="ip" value="{ip_value}" placeholder="Enter IP address">
        <br><br>
        <button type="submit">Scan</button>
        <button type="submit" name="auto" value="1">Auto Detect</button>
    </form>

    <div id="loader" class="loader"></div>

    {result}

    <br>
    {history_html}

</div>

</body>
</html>
"""

if __name__ == '__main__':
    app.run(debug=True)

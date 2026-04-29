from flask import Flask, request
import requests
import json
import os
import numpy as np
from sklearn.linear_model import LogisticRegression

app = Flask(__name__)

API_KEY = os.environ.get("API_KEY")

# ML MODEL
X = np.array([
    [0, 0], [5, 1], [10, 2],
    [30, 10], [45, 20], [60, 30],
    [75, 50], [85, 80], [95, 120]
])
y = np.array([0,0,0,1,1,1,2,2,2])

model = LogisticRegression()
model.fit(X, y)

@app.route('/', methods=['GET','POST'])
def home():
    result = ""
    history_html = "<h3>Recent Scans</h3>"
    ip_value = ""

    # DEFAULTS
    color = "#38bdf8"
    status = ""
    message = ""
    anomaly = ""
    country = ""
    city = ""
    isp = ""
    org = ""
    reports = 0
    abuse_score = 0
    width = 0

    if request.method == 'POST':
        ip_value = request.form.get('ip')

        if request.form.get('auto') == "1":
            ip_value = requests.get('https://api.ipify.org').text

        try:
            # Abuse API
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {'Accept': 'application/json', 'Key': API_KEY}
            params = {'ipAddress': ip_value, 'maxAgeInDays': '90'}

            res = requests.get(url, headers=headers, params=params)
            data = res.json()

            abuse_score = data['data']['abuseConfidenceScore']
            reports = data['data']['totalReports']

            # GEO DATA
            geo = requests.get(f"http://ip-api.com/json/{ip_value}").json()
            country = geo.get("country", "Unknown")
            city = geo.get("city", "Unknown")
            isp = geo.get("isp", "Unknown")
            org = geo.get("org", "Unknown")

            # ML
            pred = model.predict([[abuse_score, reports]])[0]

            if pred == 0:
                status="LOW RISK 🟢"; color="#22c55e"
                message="Low risk: minimal suspicious activity"
            elif pred == 1:
                status="MEDIUM RISK 🟡"; color="#facc15"
                message="Moderate risk detected"
            else:
                status="HIGH RISK 🔴"; color="#ef4444"
                message="Highly suspicious IP"

            if abuse_score > 80 and reports < 5:
                anomaly="⚠️ Unusual pattern"
            else:
                anomaly="Normal behavior"

            width = max(abuse_score, 5)

            # SAVE HISTORY
            entry={"ip":ip_value,"status":status,"score":abuse_score}

            if os.path.exists("history.json"):
                with open("history.json","r") as f:
                    history=json.load(f)
            else:
                history=[]

            history.append(entry)

            with open("history.json","w") as f:
                json.dump(history[-10:],f)

        except Exception as e:
            result=f"<p style='color:red;'>Error: {e}</p>"

    # LOAD HISTORY
    try:
        with open("history.json","r") as f:
            history=json.load(f)
            for item in reversed(history):
                history_html+=f"<p>{item['ip']} → {item['status']}</p>"
    except:
        history_html+="<p>No history yet</p>"

    # RESULT
    if ip_value and status:
        result=f"""
        <div class='result'>
            <p><b>IP:</b> {ip_value}</p>
            <p><b>Status:</b> <span style='color:{color}'>{status}</span></p>
            <p><b>ML Insight:</b> {message}</p>
            <p><b>Anomaly:</b> {anomaly}</p>

            <p><b>IP Location:</b> {city}, {country}</p>
            <p><b>Organization:</b> {org}</p>

            <p><b>Real Location:</b> <span id="realLocation">Detecting...</span></p>

            <!-- IP MAP -->
            <iframe width="100%" height="150"
            style="border-radius:10px;margin-top:10px;"
            src="https://maps.google.com/maps?q={city}&z=5&output=embed"></iframe>

            <!-- REAL MAP -->
            <iframe id="realMap" width="100%" height="150"
            style="border-radius:10px;margin-top:10px;"></iframe>

            <p><b>Reports:</b> {reports}</p>
            <p><b>Risk Score:</b> {abuse_score}</p>

            <div class="progress">
                <div class="bar" style="width:{width}%; background:{color};"></div>
            </div>
        </div>
        """

    return f"""
<html>
<head>
<title>IP Threat Checker</title>

<style>
body {{
    background:#0f172a;
    color:white;
    text-align:center;
    font-family:Arial;
}}

.box {{
    background:#1e293b;
    padding:25px;
    border-radius:12px;
    display:inline-block;
}}

.progress {{
    width:100%;
    background:#334155;
}}

.bar {{
    height:12px;
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
                const res = await fetch(`https://api.bigdatacloud.net/data/reverse-geocode-client?latitude=${{lat}}&longitude=${{lon}}`);
                const data = await res.json();

                document.getElementById("realLocation").innerText =
                    (data.city || "Unknown") + ", " + (data.countryName || "");

                document.getElementById("realMap").src =
                    `https://maps.google.com/maps?q=${{lat}},${{lon}}&z=12&output=embed`;

            }} catch {{
                document.getElementById("realLocation").innerText = lat + "," + lon;
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

<form method="POST">
<input name="ip" value="{ip_value}" placeholder="Enter IP">
<br><br>
<button>Scan</button>
<button name="auto" value="1">Auto Detect</button>
</form>

{result}
<br>
{history_html}

</div>

</body>
</html>
"""

if __name__ == "__main__":
    app.run(debug=True)
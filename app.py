from flask import Flask, render_template, request
from ipintel import check_abuseipdb, check_virustotal, check_ipapi

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    report = {}
    ip = ""
    if request.method == "POST":
        ip = request.form["ip"]
        report["abuseipdb"] = check_abuseipdb(ip)
        report["virustotal"] = check_virustotal(ip)
        report["ipapi"] = check_ipapi(ip)
    return render_template("index.html", report=report, ip=ip)

if __name__ == "__main__":
    app.run(debug=True)
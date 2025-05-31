from flask import Flask, render_template, request
from ipintel import (
    check_abuseipdb,
    check_virustotal,
    check_ipapi,
    aggregate_report_data
)

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    report = {}
    aggregated_report = {}
    ip = ""

    if request.method == "POST":
        ip = request.form["ip"]
        report["abuseipdb"] = check_abuseipdb(ip)
        report["virustotal"] = check_virustotal(ip)
        report["ipapi"] = check_ipapi(ip)

        aggregated_report = aggregate_report_data(report, ip)

    return render_template("index.html", ip=ip, report=report, aggregated_report=aggregated_report)

if __name__ == "__main__":
    app.run(debug=True)

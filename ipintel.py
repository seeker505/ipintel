import os
import requests
import pycountry
import vt
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def get_country_name(code):
    try:
        return pycountry.countries.get(alpha_2=code).name
    except:
        return "Unknown"

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    link = f"https://www.abuseipdb.com/check/{ip}"

    response = requests.get(url, headers=headers, params=params)
    if response.status_code != 200:
        return {"error": response.text}
    
    data = response.json()['data']
    country = get_country_name(data['countryCode'])
    totalReports = data['totalReports']
    abuseConfidenceScore = data['abuseConfidenceScore']

    if totalReports == 0 and abuseConfidenceScore == 0:
        summary = "As per AbuseIPDB, IP is clean."
    else:
        summary = f"As per AbuseIPDB, the IP has been reported {totalReports} times. Confidence of Abuse is {abuseConfidenceScore}%."

    return {
        "summary": summary,
        "totalReports": totalReports,
        "abuseConfidenceScore": abuseConfidenceScore,
        "isp": data.get("isp", "Unknown"),
        "usage": data.get("usageType", "Unknown"),
        "location": country,
        "link": link
    }

def check_virustotal(ip):
    link = f"https://www.virustotal.com/gui/ip-address/{ip}"
    try:
        with vt.Client(VIRUSTOTAL_API_KEY) as client:
            ip_obj = client.get_object(f"/ip_addresses/{ip}")
            analysis = ip_obj.get("last_analysis_stats", {})
            malicious = analysis.get("malicious", 0)
            total = sum(analysis.values())
            country = get_country_name(ip_obj.get("country", ""))
            summary = (
                "As per VT, IP is clean."
                if malicious == 0 else
                f"As per VT, this IP has been flagged malicious by {malicious}/{total}."
            )
            return {
                "summary": summary,
                "malicious": malicious,
                "total": total,
                "as_owner": ip_obj.get("as_owner", "Unknown"),
                "country": country,
                "link": link
            }
    except Exception as e:
        return {"error": str(e)}

def check_ipapi(ip):
    url = f"http://ip-api.com/json/{ip}?fields=country,city,isp,proxy,hosting"
    link = f"https://ip-api.com/#{ip}"
    response = requests.get(url)
    data = response.json()
    return {
        "summary": "As per IP-API, found this geo info:",
        "city": data.get("city", "Unknown"),
        "country": data.get("country", "Unknown"),
        "isp": data.get("isp", "Unknown"),
        "proxy": data.get("proxy", "Unknown"),
        "hosting": data.get("hosting", "Unknown"),
        "link": link
    }

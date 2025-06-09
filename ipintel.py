import os
import requests
import pycountry
import vt
from dotenv import load_dotenv
# import json

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
    params = {"ipAddress": ip, "maxAgeInDays": 365}
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
    url = f"http://ip-api.com/json/{ip}?fields=country,city,isp,proxy,hosting,as"
    link = f"https://ip-api.com/#{ip}"
    response = requests.get(url)
    data = response.json()
    return {
        "summary": "As per IP-API, found this geo info:",
        "city": data.get("city", "N/A"),
        "country": data.get("country", "N/A"),
        "isp": data.get("isp", "N/A"),
        "proxy": data.get("proxy", "N/A"),
        "hosting": data.get("hosting", "N/A"),
        "link": link,
        "as": data.get("as", "N/A")
    }


def aggregate_report_data(report_data, ip):
    overall_risk_level = "Unknown"
    overall_risk_summary_text = "Data not fully processed for overall assessment."
    aggregated_location = "N/A"
    aggregated_isp = "N/A"
    aggregated_asn = "N/A"
    calculated_risk_score = 0
    risk_factors_found = []

    ipapi_data = report_data.get('ipapi', {})
    if ipapi_data:
        city = ipapi_data.get('city')
        country = ipapi_data.get('country')
        if city and country:
            aggregated_location = f"{city}, {country}"
        elif country:
            aggregated_location = country
        aggregated_isp = ipapi_data.get('isp')
        aggregated_asn = ipapi_data.get('as')
    elif report_data.get('abuseipdb'):
        abuse = report_data['abuseipdb']
        aggregated_location = abuse.get("location", "N/A")
        aggregated_isp = abuse.get("isp", "N/A")

    abuse = report_data.get('abuseipdb', {})
    abuse_score = abuse.get('abuseConfidenceScore')
    calculated_risk_score = 0
    risk_factors_found = []

    # --- AbuseIPDB Scoring ---
    if abuse_score is not None:
        abuse_score = int(abuse_score)
        if abuse_score >= 90:
            calculated_risk_score += 4
            risk_factors_found.append(f"very high AbuseIPDB confidence ({abuse_score}%)")
        elif abuse_score >= 70:
            calculated_risk_score += 3
            risk_factors_found.append(f"high AbuseIPDB confidence ({abuse_score}%)")
        elif abuse_score >= 40:
            calculated_risk_score += 2
            risk_factors_found.append(f"moderate AbuseIPDB confidence ({abuse_score}%)")
        elif abuse_score >= 10:
            calculated_risk_score += 1
            risk_factors_found.append(f"low AbuseIPDB confidence ({abuse_score}%)")

    # --- VirusTotal Scoring ---
    vt = report_data.get('virustotal', {})
    vt_malicious = vt.get('malicious')

    if vt_malicious is not None:
        vt_malicious = int(vt_malicious)
        if vt_malicious >= 60:
            calculated_risk_score += 4
            risk_factors_found.append(f"{vt_malicious} VirusTotal detections (very high)")
        elif vt_malicious >= 40:
            calculated_risk_score += 3
            risk_factors_found.append(f"{vt_malicious} VirusTotal detections (high)")
        elif vt_malicious >= 20:
            calculated_risk_score += 2
            risk_factors_found.append(f"{vt_malicious} VirusTotal detections (moderate)")
        elif vt_malicious > 5:
            calculated_risk_score += 1
            risk_factors_found.append(f"{vt_malicious} VirusTotal detection(s) (low)")

    # --- Proxy/VPN Detection (Optional Weight) ---
    proxy_detected = ipapi_data.get("proxy", False)
    if proxy_detected:
        calculated_risk_score += 1
        risk_factors_found.append("identified as Proxy/VPN")

    # --- Risk Level Classification ---
    if not risk_factors_found and (abuse or vt or ipapi_data):
        overall_risk_level = "Low"
        overall_risk_summary_text = "No significant threat indicators found."

    elif calculated_risk_score >= 6:
        overall_risk_level = "Critical"
        overall_risk_summary_text = "Multiple critical threat indicators: " + ", ".join(risk_factors_found) + "."

    elif calculated_risk_score >= 4:
        overall_risk_level = "High"
        overall_risk_summary_text = "Significant threat indicators: " + ", ".join(risk_factors_found) + "."

    elif calculated_risk_score >= 2:
        overall_risk_level = "Medium"
        overall_risk_summary_text = "Some potential concerns: " + ", ".join(risk_factors_found) + "."

    elif risk_factors_found:
        overall_risk_level = "Low"
        overall_risk_summary_text = "Minor indicators noted: " + ", ".join(risk_factors_found) + "."

    else:
        overall_risk_level = "None"
        overall_risk_summary_text = "No data available to assess risk."


    return {
        "ip": ip,
        "overall_risk_level": overall_risk_level,
        "overall_risk_summary_text": overall_risk_summary_text,
        "aggregated_location": aggregated_location,
        "aggregated_isp": aggregated_isp,
        "aggregated_asn": aggregated_asn,   
        "risk_score": calculated_risk_score,
        "risk_factors": risk_factors_found
    }

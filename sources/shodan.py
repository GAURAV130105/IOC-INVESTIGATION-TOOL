import os,json
import requests
from cache import cache_get, cache_set
from dotenv import load_dotenv

load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

BASE_URL= "https://api.shodan.io"

def shodan_check(indicator,ind_type):
    if ind_type!="ip":
        return None
    cached= cache_get(indicator,"shodan")
    if cached:
        return cached
    url = f"{BASE_URL}/shodan/host/{indicator}"
    
    try:
        response= requests.get(url,params={"key":SHODAN_API_KEY},timeout=10,)
    except requests.exceptions.Timeout:
        print ("[Shodan] Request timed out")
        return None
    except requests.exceptions.ConnectionError:
        print("[Shodan] Connection error, check your network")
        return None
    
    if response.status_code==404:
        print("[Shodan] No data found for this IP")
        return None
    if response.status_code==401:
        print("[Shodan] Invalid API key")
        return None
    if response.status_code==403:
        print("[Shodan] Access forbidden — this IP may require a paid plan")
        return None
    if response.status_code==429:
        print("[Shodan] Rate limit hit")
        return None
    if response.status_code!=200:
        print(f"[Shodan] Error {response.status_code}")
        return None
    
    data=response.json()
    
    ip_str     = data.get("ip_str", "")
    org        = data.get("org", "")
    isp        = data.get("isp", "")
    asn        = data.get("asn", "")
    country    = data.get("country_name", "")
    city       = data.get("city", "")
    os         = data.get("os", None)
    last_update = data.get("last_update", "")
    hostnames  = data.get("hostnames", [])
    domains    = data.get("domains", [])
    ports      = data.get("ports", [])
    tags       = data.get("tags", [])
    
    services=[]
    for banner in data.get("data",[]):
        service={
            "port": banner.get("port",""),
            "transport": banner.get("transport","tcp"),
            "product": banner.get("product",""),
            "version": banner.get("version",""),
            "cpe":banner.get("cpe",[]),
            "vulns": list(banner.get("vulns", {}).keys()),        }
        services.append(service)
        
    all_vulns = []
    for service in services:
        for vuln in service["vulns"]:
            if vuln not in all_vulns:
                all_vulns.append(vuln)
        
    result = {
        "ip":          ip_str,
        "org":         org,
        "isp":         isp,
        "asn":         asn,
        "country":     country,
        "city":        city,
        "os":          os,
        "last_update": last_update,
        "hostnames":   hostnames,
        "domains":     domains,
        "ports":       ports,
        "tags":        tags,
        "services":    services,
        "vulns":       all_vulns,
    }

    cache_set(indicator, "shodan", result)
    return result
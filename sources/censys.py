import requests, os
from cache import cache_get, cache_set
from dotenv import load_dotenv

load_dotenv()
CENSYS_API_KEY = os.getenv("CENSYS_API_KEY")

BASE_URL_CENSYS = "https://api.platform.censys.io/v3/global/"
headers_CENSYS  = {"X-CENSYS-API-KEY": CENSYS_API_KEY}

def vt_check(indicator, ind_type):

    cached = cache_get(indicator, "virustotal")
    if cached:
        return cached

    if ind_type == "ip":
        url = f"{BASE_URL_CENSYS}/ip_addresses/{indicator}"
    elif ind_type == "hash":
        url = f"{BASE_URL_CENSYS}/files/{indicator}"
    else:
        url = f"{BASE_URL_CENSYS}/domains/{indicator}"

    try:
        response = requests.get(url, headers=headers_CENSYS, timeout=30)
    except requests.exceptions.Timeout:
        print("  [CENSYS] Request timed out, try again later")
        return None
    except requests.exceptions.ConnectionError:
        print("  [CENSYS] Connection error, check your network")
        return None

    if response.status_code == 404:
        return None
    if response.status_code == 429:
        print("  [CENSYS] Rate limit hit, wait a minute and try again")
        return None
    if response.status_code != 200:
        print(f"  [CENSYS] Error {response.status_code}")
        return None



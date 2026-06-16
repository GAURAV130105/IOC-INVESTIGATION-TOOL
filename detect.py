import ipaddress

def is_valid_ipv4(value):
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False

def is_hash(value):
    return len(value) in [32, 40, 64] and all(c in "0123456789abcdef" for c in value.lower())

def detect_type(indicator):
    if is_valid_ipv4(indicator):
        return "ip"
    if is_hash(indicator):
        return "hash"
    if "." in indicator:
        return "domain"
    return None

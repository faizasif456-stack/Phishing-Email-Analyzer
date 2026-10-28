import ipaddress
import re
import unicodedata

MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "co.jp",
    "com.pk", "org.pk", "edu.pk", "gov.pk", "net.pk", "com.br", "co.za", "com.cn", "com.sg",
    "com.my", "co.nz", "com.tr", "com.mx", "com.sa", "com.eg",
}

MICROSOFT = {"microsoft.com", "office.com", "office365.com", "live.com", "outlook.com", "microsoftonline.com", "sharepoint.com", "onmicrosoft.com"}

BRAND_DOMAINS = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": MICROSOFT,
    "office365": MICROSOFT,
    "outlook": MICROSOFT,
    "onedrive": MICROSOFT,
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazonaws.com", "amazonses.com"},
    "netflix": {"netflix.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "googlemail.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com"},
    "instagram": {"instagram.com", "facebookmail.com"},
    "linkedin": {"linkedin.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "adobe": {"adobe.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "hbl": {"hbl.com"},
    "easypaisa": {"easypaisa.com.pk"},
    "jazzcash": {"jazzcash.com.pk"},
}

DISPLAY_NAMES = {
    "paypal": "paypal", "microsoft": "microsoft", "office 365": "office365", "office365": "office365",
    "outlook": "outlook", "onedrive": "onedrive", "apple": "apple", "icloud": "icloud", "amazon": "amazon",
    "netflix": "netflix", "google": "google", "facebook": "facebook", "instagram": "instagram",
    "linkedin": "linkedin", "dhl": "dhl", "fedex": "fedex", "docusign": "docusign", "dropbox": "dropbox",
    "adobe": "adobe", "chase": "chase", "wells fargo": "wellsfargo", "hbl": "hbl", "easypaisa": "easypaisa",
    "jazzcash": "jazzcash",
}

FREEMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "aol.com",
    "icloud.com", "proton.me", "protonmail.com", "gmx.com", "mail.com", "yandex.com", "zoho.com",
}

CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ӏ": "l", "ј": "j",
})

ALL_OFFICIAL = set().union(*BRAND_DOMAINS.values())


def domain_of(address):
    return address.rsplit("@", 1)[-1].strip(" <>").lower() if "@" in address else ""


def org_domain(host):
    host = (host or "").lower().strip(".")
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def same_org(a, b):
    return bool(a) and bool(b) and org_domain(a) == org_domain(b)


def is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def is_public_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def decode_idna(host):
    if "xn--" not in host:
        return host
    try:
        return host.encode().decode("idna")
    except UnicodeError:
        return host


def normalize(host):
    host = decode_idna(host.lower())
    host = unicodedata.normalize("NFKC", host).translate(CONFUSABLES)
    return host.replace("rn", "m").replace("vv", "w")


def is_official(host, brand=None):
    org = org_domain(host)
    if brand:
        return org in BRAND_DOMAINS.get(brand, set())
    return org in ALL_OFFICIAL


def impersonated_brand(host):
    if not host or is_ip(host) or is_official(host):
        return None
    normalized = normalize(host)
    for brand in BRAND_DOMAINS:
        if re.search(rf"(^|[.-]){brand}([.-]|$)", normalized):
            return brand
    return None


def brand_in_text(text):
    text = " ".join(text.lower().split())
    for phrase, brand in DISPLAY_NAMES.items():
        if re.search(rf"\b{re.escape(phrase)}\b", text):
            return brand
    return None

import re
import socket
import requests
from urllib.parse import urlparse
from datetime import datetime
import whois

# List of high-risk TLDs
SUSPICIOUS_TLDS = ['xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'cn', 'ru']

def extract_features(url):
    # Normalize URL: add scheme if missing
    if not url.startswith("http"):
        url = "http://" + url
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.strip().lower()
    if domain.startswith("www."):
        domain = domain[4:]
    
    try:
        domain_info = whois.whois(domain)
    except Exception:
        domain_info = None

    # 1. Has IP address in URL
    def has_ip(url):
        return 1 if re.search(r'\d{1,3}(\.\d{1,3}){3}', url) else -1

    # 2. URL Length: short is safe, long is suspicious
    def url_length(url):
        l = len(url)
        if l < 54:
            return -1
        elif l <= 75:
            return 0
        else:
            return 1

    # 3. Use of shortening services
    def has_shortener(url):
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
        return 1 if any(s in url for s in shorteners) else -1

    # 4. Presence of "@" symbol
    def has_at(url):
        return 1 if "@" in url else -1

    # 5. Double slash in path (beyond protocol)
    def double_slash_redirect(url):
        return 1 if parsed_url.path.count("//") > 0 else -1

    # 6. Hyphen in domain (suspicious)
    def prefix_suffix(url):
        return 1 if '-' in domain else -1

    # 7. Subdomain count: More than 1 dot before main domain is suspicious
    def subdomain_count(domain):
        parts = domain.split('.')
        if len(parts) <= 2:
            return -1
        elif len(parts) == 3:
            return 0
        else:
            return 1

    # 8. SSL final state: HTTPS is safe (return -1 if HTTPS), otherwise try fallback
    def ssl_final_state(url):
        if parsed_url.scheme == "https":
            return -1  # safe
        try:
            test_url = "https://" + domain
            r = requests.get(test_url, timeout=5, allow_redirects=True)
            if r.url.startswith("https") and r.status_code == 200:
                return -1
            else:
                return 0  # neutral instead of suspicious
        except:
            return 0



    # 9. Domain registration length: Long is safe
    def domain_registration_length(info):
        try:
            creation_date = info.creation_date
            expiration_date = info.expiration_date
            if isinstance(creation_date, list): creation_date = creation_date[0]
            if isinstance(expiration_date, list): expiration_date = expiration_date[0]
            if creation_date and expiration_date:
                duration = (expiration_date - creation_date).days
                return -1 if duration >= 365 else 1
        except:
            return 0
        return 0

    # 10. Favicon: Accessible favicon is safe
    def favicon(url):
        try:
            for scheme in ['https', 'http']:
                favicon_url = f"{scheme}://{domain}/favicon.ico"
                r = requests.get(favicon_url, timeout=3)
                if r.status_code == 200:
                    return -1
        except:
            pass
        return 0  # neutral instead of suspicious


    # 11. Port: No port specified is safe
    def port(url):
        return 1 if ':' in domain and not domain.endswith((":80", ":443")) else -1

    # 12. HTTPS token: "https" in domain is suspicious
    def https_token(url):
        return 1 if "https" in domain else -1

    # 13. Request URL: Excessive slashes in path are suspicious
    def request_url(url):
        return 1 if parsed_url.path.count('/') > 5 else -1

    # 14. URL of Anchor: Placeholder (neutral)
    def anchor_url(url):
        return 0

    # 15. Links in Tags: Placeholder (neutral)
    def links_in_tags(url):
        return 0

    # 16. SFH (Server Form Handling): Empty path is safe
    def sfh(url):
        return -1 if parsed_url.path in ["", "/"] else 1

    # 17. Submitting to Email: Presence of "mailto:" is suspicious
    def submit_to_email(url):
        return 1 if "mailto:" in url.lower() else -1

    # 18. Abnormal URL: If domain resolves, it's safe
    def abnormal_url(url):
        try:
            socket.gethostbyname(domain)
            return -1
        except:
            return 1

    # 19. Redirect: Presence of "redirect" is suspicious
    def redirect(url):
        return 1 if "redirect" in url.lower() else 0

    # 20. On Mouseover: Placeholder (neutral)
    def on_mouseover(url):
        return 0

    # 21. Right Click: Placeholder (neutral)
    def right_click(url):
        return 0

    # 22. Popup Window: Placeholder (neutral)
    def popup_window(url):
        return 0

    # 23. Iframe: Placeholder (neutral)
    def iframe(url):
        return 0

    # 24. Age of Domain: Older is safe
    def age_of_domain(info):
        try:
            creation_date = info.creation_date
            if isinstance(creation_date, list): creation_date = creation_date[0]
            if creation_date:
                age = (datetime.now() - creation_date).days
                return -1 if age >= 180 else 1
        except:
            return 0
        return 0

    # 25. DNS Record: Existence of DNS record is safe
    def dns_record(url):
        try:
            socket.gethostbyname(domain)
            return -1
        except:
            return 1

    # 26. Web Traffic: Placeholder (neutral)
    def web_traffic(url):
        return 0

    # 27. Page Rank: Placeholder (neutral)
    def page_rank(url):
        return 0

    # 28. Google Index: Placeholder (neutral)
    def google_index(url):
        return 0

    # 29. Links Pointing: Placeholder (neutral)
    def links_pointing(url):
        return 0

    # 30. Suspicious TLD: Explicitly flag high-risk TLDs (e.g., .xyz)
    def suspicious_tld(url):
        tld = domain.split('.')[-1]
        return 1 if tld in SUSPICIOUS_TLDS else -1

    # Build feature list (exactly 30 features)
    features = [
        has_ip(url),                    # 1
        url_length(url),                # 2
        has_shortener(url),             # 3
        has_at(url),                    # 4
        double_slash_redirect(url),     # 5
        prefix_suffix(url),             # 6
        subdomain_count(domain),        # 7
        ssl_final_state(url),           # 8
        domain_registration_length(domain_info),  # 9
        favicon(url),                   # 10
        port(url),                      # 11
        https_token(url),               # 12
        request_url(url),               # 13
        anchor_url(url),                # 14
        links_in_tags(url),             # 15
        sfh(url),                       # 16
        submit_to_email(url),           # 17
        abnormal_url(url),              # 18
        redirect(url),                  # 19
        on_mouseover(url),              # 20
        right_click(url),               # 21
        popup_window(url),              # 22
        iframe(url),                    # 23
        age_of_domain(domain_info),     # 24
        dns_record(url),                # 25
        web_traffic(url),               # 26
        page_rank(url),                 # 27
        google_index(url),              # 28
        links_pointing(url),            # 29
        suspicious_tld(url)             # 30
    ]
    return features

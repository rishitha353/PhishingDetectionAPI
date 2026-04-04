def extract_features_from_url(url: str):
    import numpy as np

    length = len(url)
    num_slash = url.count("/")
    num_dot = url.count(".")
    has_https = 1 if url.startswith("https") else 0
    has_at = 1 if "@" in url else 0
    has_hyphen = 1 if "-" in url else 0
    has_ip = 1 if any(ch.isdigit() for ch in url.split("/")[2].split(":")[0]) else 0 if "://" in url else 0
    num_question = url.count("?")
    num_equal = url.count("=")
    num_amp = url.count("&")
    num_percent = url.count("%")
    num_hash = url.count("#")
    num_digits = sum(ch.isdigit() for ch in url)
    num_letters = sum(ch.isalpha() for ch in url)
    ratio_digits = num_digits / max(1, length)
    ratio_letters = num_letters / max(1, length)
    url_depth = url.count("/") - 2 if "://" in url else url.count("/")
    subdomain_count = max(0, url.split("//")[-1].split("/")[0].count(".") - 1)
    has_suspicious_words = 1 if any(w in url.lower() for w in ["login", "verify", "update", "secure", "bank"]) else 0
    starts_with_ip = 1 if has_ip else 0
    ends_with_exe = 1 if url.lower().endswith(".exe") else 0
    ends_with_zip = 1 if url.lower().endswith(".zip") else 0
    has_port = 1 if ":" in url.split("//")[-1].split("/")[0] else 0
    path_length = len(url.split("//")[-1].split("/", 1)[1]) if "/" in url.split("//")[-1] else 0
    host_length = len(url.split("//")[-1].split("/")[0])
    num_special = sum(ch in "!*$^(){}[]|\"'<>" for ch in url)
    ratio_special = num_special / max(1, length)
    has_https_token = 1 if "https" in url.lower().split("//")[-1].split("/")[0] and not url.startswith("https") else 0
    tld_length = len(url.split(".")[-1].split("/")[0])

    features = [
        length, num_slash, num_dot, has_https, has_at, has_hyphen, has_ip,
        num_question, num_equal, num_amp, num_percent, num_hash,
        num_digits, num_letters, ratio_digits, ratio_letters,
        url_depth, subdomain_count, has_suspicious_words, starts_with_ip,
        ends_with_exe, ends_with_zip, has_port, path_length,
        host_length, num_special, ratio_special, has_https_token,
        tld_length, 0.0  # 30th dummy feature
    ]

    X_structured = np.array([features], dtype=float)
    X_seq = np.array([[length]], dtype=float)  # placeholder for CNN
    return X_structured, X_seq

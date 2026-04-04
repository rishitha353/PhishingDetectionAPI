from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import uvicorn
import numpy as np
import tensorflow as tf


app = FastAPI()


# ---------- load models ----------
rf_model = joblib.load("models/rf_model.pkl")
svm_model = joblib.load("models/svm_model.pkl")
xgb_model = joblib.load("models/xgb_model.pkl")
cnn_model = tf.keras.models.load_model("models/cnn_model.h5")


# ---------- feature extraction (30 features) ----------
def extract_features_from_url(url: str):
    length = len(url)
    num_slash = url.count("/")
    num_dot = url.count(".")
    has_https = 1 if url.startswith("https") else 0
    has_at = 1 if "@" in url else 0
    has_hyphen = 1 if "-" in url else 0

    host = url.split("//")[-1].split("/")[0] if "://" in url else url.split("/")[0]
    has_ip = 1 if any(ch.isdigit() for ch in host) else 0

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
    subdomain_count = max(0, host.count(".") - 1)

    has_suspicious_words = 1 if any(
        w in url.lower() for w in ["login", "verify", "update", "secure", "bank"]
    ) else 0

    starts_with_ip = 1 if has_ip else 0
    ends_with_exe = 1 if url.lower().endswith(".exe") else 0
    ends_with_zip = 1 if url.lower().endswith(".zip") else 0
    has_port = 1 if ":" in host else 0

    path = url.split("//")[-1].split("/", 1)[1] if "/" in url.split("//")[-1] else ""
    path_length = len(path)
    host_length = len(host)

    num_special = sum(ch in "!*$^(){}[]|\"'<>" for ch in url)
    ratio_special = num_special / max(1, length)

    has_https_token = 1 if "https" in host.lower() and not url.startswith("https") else 0
    tld = host.split(".")[-1] if "." in host else ""
    tld_length = len(tld)

    dummy = 0.0

    features = [
        length, num_slash, num_dot, has_https, has_at, has_hyphen, has_ip,
        num_question, num_equal, num_amp, num_percent, num_hash,
        num_digits, num_letters, ratio_digits, ratio_letters,
        url_depth, subdomain_count, has_suspicious_words, starts_with_ip,
        ends_with_exe, ends_with_zip, has_port, path_length,
        host_length, num_special, ratio_special, has_https_token,
        tld_length, dummy
    ]

    # structured input for RF/SVM/XGB: (1, 30)
    X_structured = np.array([features], dtype=float)
    return X_structured


# ---------- request model ----------
class UrlRequest(BaseModel):
    url: str
    model: str = "rf"   # "rf", "svm", "xgb", "cnn", "ensemble"


# ---------- main endpoint ----------
@app.post("/predict")
def predict(req: UrlRequest):
    url = req.url
    model_name = req.model.lower()

    # common 30-feature vector
    X_structured = extract_features_from_url(url)

    # CNN input (reuse for cnn and ensemble)
    feats = X_structured.reshape(1, 30)
    X_cnn = feats.reshape(1, 5, 6, 1)

    # single-model branches
    if model_name == "svm":
        proba = float(svm_model.predict_proba(X_structured)[0][1])
        used = "svm"

    elif model_name == "xgb":
        proba = float(xgb_model.predict_proba(X_structured)[0][1])
        used = "xgb"

    elif model_name == "cnn":
        proba = float(cnn_model.predict(X_cnn)[0][0])
        used = "cnn"

    elif model_name == "ensemble":
        # ---- ENSEMBLE: average probabilities of all four models ----
        p_rf  = float(rf_model.predict_proba(X_structured)[0][1])
        p_svm = float(svm_model.predict_proba(X_structured)[0][1])
        p_xgb = float(xgb_model.predict_proba(X_structured)[0][1])
        p_cnn = float(cnn_model.predict(X_cnn)[0][0])

        proba = float((p_rf + p_svm + p_xgb + p_cnn) / 4.0)
        used = "ensemble_rf_svm_xgb_cnn"

    else:
        # default RF
        proba = float(rf_model.predict_proba(X_structured)[0][1])
        used = "rf"

    return {
        "is_phishing": proba >= 0.5,
        "confidence": proba,
        "model_used": used
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)

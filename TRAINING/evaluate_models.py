import pandas as pd
import numpy as np
import joblib
import tensorflow as tf
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# 1) load test data (your phishing_test.csv)
data = pd.read_csv("phishing_test.csv")
X = data.drop(columns=["label"]).values
y_true = data["label"].values

print("Test samples:", X.shape[0])
print("Feature count:", X.shape[1])

# 2) load trained models
rf_model = joblib.load("models/rf_model.pkl")
svm_model = joblib.load("models/svm_model.pkl")
xgb_model = joblib.load("models/xgb_model.pkl")
cnn_model = tf.keras.models.load_model("models/cnn_model.h5")

# 3) prepare CNN input: (n_samples, 5, 6, 1) because 30 features
feats = X.reshape(-1, 30)
X_cnn = feats.reshape(-1, 5, 6, 1)

# 4) get probabilities from each model
p_rf  = rf_model.predict_proba(X)[:, 1]
p_svm = svm_model.predict_proba(X)[:, 1]
p_xgb = xgb_model.predict_proba(X)[:, 1]
p_cnn = cnn_model.predict(X_cnn)[:, 0]
p_ens = (p_rf + p_svm + p_xgb + p_cnn) / 4.0


def evaluate(name, probs):
    # convert labels -1/1 -> 0/1
    y_bin = np.where(y_true == -1, 0, y_true)

    y_pred = (np.array(probs) >= 0.5).astype(int)

    acc = accuracy_score(y_bin, y_pred)
    prec = precision_score(y_bin, y_pred, average="binary", zero_division=0)
    rec = recall_score(y_bin, y_pred, average="binary", zero_division=0)
    f1 = f1_score(y_bin, y_pred, average="binary", zero_division=0)
    cm = confusion_matrix(y_bin, y_pred)

    print(f"\n=== {name} ===")
    print("Accuracy :", acc)
    print("Precision:", prec)
    print("Recall   :", rec)
    print("F1-score :", f1)
    print("Confusion matrix:\n", cm)


# 5) run evaluation for all models
evaluate("RandomForest", p_rf)
evaluate("SVM", p_svm)
evaluate("XGBoost", p_xgb)
evaluate("CNN", p_cnn)
evaluate("Ensemble", p_ens)

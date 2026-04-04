import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

df = pd.read_csv("dataset.csv")
X = df.drop("Result", axis=1)     # ✅ updated
y = df["Result"]                  # ✅ updated

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
model = RandomForestClassifier()
model.fit(X_train, y_train)

joblib.dump(model, "models/rf_model.pkl")

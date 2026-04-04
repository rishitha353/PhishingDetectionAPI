import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
import joblib

# Load dataset
df = pd.read_csv("dataset.csv")

# Convert -1 to 0 in the label column
df["Result"] = df["Result"].replace(-1, 0)

X = df.drop("Result", axis=1)
y = df["Result"]

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# Train XGBoost model
model = xgb.XGBClassifier()
model.fit(X_train, y_train)

# Save model
joblib.dump(model, "models/xgb_model.pkl")

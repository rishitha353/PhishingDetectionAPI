import pandas as pd
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
import joblib

# Load dataset
df = pd.read_csv("dataset.csv")
X = df.drop("Result", axis=1)     # Features
y = df["Result"]                  # Labels

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# Train SVM model
model = SVC(probability=True)
model.fit(X_train, y_train)

# Save model
joblib.dump(model, "models/svm_model.pkl")

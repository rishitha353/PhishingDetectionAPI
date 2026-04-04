import pandas as pd
from sklearn.model_selection import train_test_split

# 1) load full dataset
data = pd.read_csv("dataset.csv")

# 2) rename columns to standard names for our pipeline
data = data.rename(columns={"Result": "label"})  # label column
# there is no URL column here; all features are already numeric

# 3) split into train/test (80/20)
train_df, test_df = train_test_split(
    data, test_size=0.2, random_state=42, stratify=data["label"]
)

# 4) save only test split
test_df.to_csv("dataset.csv", index=False)

print("Saved test split to dataset.csv")

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import pickle

# Sample dataset for initial testing
data = {
    "url_length": [20, 25, 30, 35, 40, 45, 50, 55, 60, 65,
                   70, 75, 80, 85, 90, 95, 100, 105, 110, 115],
    "https":      [1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    "suspicious": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
    "label":      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
}

df = pd.DataFrame(data)

X = df[["url_length", "https", "suspicious"]]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

with open("phishing_model.pkl", "wb") as file:
    pickle.dump(model, file)

print("Model trained successfully!")
print(f"Test accuracy: {accuracy * 100:.2f}%")
print("Model saved as phishing_model.pkl")
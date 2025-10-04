import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder
import joblib
import os

# Load dataset
data_path = 'data/cicids2017_cleaned.csv'
df = pd.read_csv(data_path)

# Drop any unnamed index columns
df = df.loc[:, ~df.columns.str.contains('^Unnamed')]

# Use the correct label column name
label_col = 'Attack Type'

# Encode label if it's categorical
if df[label_col].dtype == 'object':
    le = LabelEncoder()
    df[label_col] = le.fit_transform(df[label_col])
    os.makedirs('models', exist_ok=True)
    joblib.dump(le, 'models/label_encoder.joblib')

# Split features and labels
X = df.drop(label_col, axis=1)
y = df[label_col]

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train Random Forest
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"\n✅ Accuracy: {acc:.4f}")
print("\n📊 Classification Report:\n", classification_report(y_test, y_pred))

# Save the model

os.makedirs('models', exist_ok=True)
joblib.dump(model, 'models/rf_model.joblib')
print("\n💾 Model saved to models/rf_model.joblib")

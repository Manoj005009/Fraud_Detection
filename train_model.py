import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib

df = pd.read_csv('realistic_fraud_dataset.csv')
X = df['url']
y = df['is_fraud']

vectorizer = TfidfVectorizer()
X_vec = vectorizer.fit_transform(X)

model = RandomForestClassifier()
model.fit(X_vec, y)

joblib.dump(model, 'model.pkl')
joblib.dump(vectorizer, 'vectorizer.pkl')
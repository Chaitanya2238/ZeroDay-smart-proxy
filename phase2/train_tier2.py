import pandas as pd
import math
import re
from collections import Counter
from sklearn.ensemble import IsolationForest
import joblib

class FeatureExtractor:
    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        if not data or pd.isna(data): 
            return 0.0
        data = str(data)
        entropy = 0.0
        length = len(data)
        counts = Counter(data)
        for count in counts.values():
            p_x = count / length
            entropy += - p_x * math.log2(p_x)
        return entropy

    @staticmethod
    def extract_features(row) -> list:
        """Extracts numerical features from a CSIC dataset row."""
        # The CSIC dataset has 'URL' and 'content' (body) columns
        url = str(row.get('URL', ''))
        body = str(row.get('content', '')) if not pd.isna(row.get('content')) else ''
        
        # Feature 1: URL Length
        url_length = len(url)
        
        # Feature 2: URL Depth (Number of slashes)
        url_depth = url.count('/')
        
        # Feature 3: Body Length
        body_length = len(body)
        
        # Feature 4: Body Entropy (Informational density)
        # Cap entropy calculation to small payloads to match Tier 1 logic
        entropy = FeatureExtractor.calculate_shannon_entropy(body) if body_length > 0 and body_length < 1024 else 3.5
        
        # Feature 5: Special Character Ratio in Body
        special_chars = len(re.findall(r'[^a-zA-Z0-9\s]', body))
        special_char_ratio = special_chars / body_length if body_length > 0 else 0.0
        
        return [url_length, url_depth, body_length, entropy, special_char_ratio]

def train_model():
    print("🚀 Loading CSIC 2010 Dataset...")
    
    # 1. Load the CSV
    df = pd.read_csv('csic_database.csv')
    
    # 2. Filter for NORMAL traffic only. 
    # In CSIC 2010 Kaggle CSVs, classification '0' or 'Normal' indicates benign traffic
    if 'classification' in df.columns:
        normal_df = df[df['classification'] == 0]
    elif 'Unnamed: 0' in df.columns:
        normal_df = df[df['Unnamed: 0'].str.contains('Normal', na=False, case=False)]
    else:
        print("❌ Could not find classification column. Check CSV format.")
        return

    print(f"✅ Found {len(normal_df)} normal requests. Extracting features...")
    
    # 3. Extract features into a 2D array
    features_list = [FeatureExtractor.extract_features(row) for _, row in normal_df.iterrows()]
    training_data = pd.DataFrame(features_list, columns=[
        'url_length', 'url_depth', 'body_length', 'entropy', 'special_char_ratio'
    ])
    
    # 4. Train the Isolation Forest
    # contamination=0.01 means we expect an extremely tight boundary
    print("🧠 Training Isolation Forest...")
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    model.fit(training_data)
    
    # 5. Save the compiled model
    joblib.dump(model, 'phase2_isolation_forest.pkl')
    print("✅ Model trained and saved as 'phase2_isolation_forest.pkl'!")

if __name__ == "__main__":
    train_model()
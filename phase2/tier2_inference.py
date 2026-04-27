# tier2_inference.py - Tier 2: Isolation Forest-based Anomaly Detection
import os
import re
import math
from collections import Counter
from typing import Dict, Optional
import joblib
import logging

logger = logging.getLogger(__name__)

class Tier2AI:
    """
    Tier 2 Analysis: Isolation Forest-based anomaly detection for zero-day threats
    Loads pre-trained model and provides synchronous inference
    """

    MODEL_PATH = 'phase2_isolation_forest.pkl'
    DEFAULT_SCORE_THRESHOLD = -0.5

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or self.MODEL_PATH
        self.model = None
        self.feature_extractor = FeatureExtractor()
        self._load_model()

    def _load_model(self):
        """Load the pre-trained Isolation Forest model"""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                logger.info(f"✅ Loaded Isolation Forest model from {self.model_path}")
            except Exception as e:
                logger.error(f"❌ Failed to load model: {e}")
                self.model = None
        else:
            logger.warning(f"⚠️ Model file not found at {self.model_path}. Tier 2 will use fallback scoring.")

    def _extract_features(self, request_data: Dict) -> list:
        """
        Extract the same 5 features used during training.
        Must match FeatureExtractor.extract_features() in train_tier2.py
        """
        url = request_data.get('path', '/')
        body = request_data.get('request_body_preview', '')

        url_length = len(url)
        url_depth = url.count('/')
        body_length = len(body)

        if body_length > 0 and body_length < 1024:
            entropy = self.feature_extractor.calculate_shannon_entropy(body)
        else:
            entropy = 3.5

        special_chars = len(re.findall(r'[^a-zA-Z0-9\s]', body))
        special_char_ratio = special_chars / body_length if body_length > 0 else 0.0

        return [url_length, url_depth, body_length, entropy, special_char_ratio]

    def _score_to_severity(self, anomaly_score: float, request_data: Dict) -> int:
        """
        Convert Isolation Forest score (-1 to 1) to severity (0-10).
        IF returns: -1 for anomalies, 1 for normal
        We use decision_function which gives raw scores.
        """
        if anomaly_score < self.DEFAULT_SCORE_THRESHOLD:
            base_severity = 5
        else:
            base_severity = 0

        indicators = []
        threat_type = 'NORMAL'

        body = request_data.get('request_body_preview', '')
        method = request_data.get('method', 'GET')
        path = request_data.get('path', '/')
        user_agent = request_data.get('headers', {}).get('user-agent', '')

        if method == 'POST' and path == '/' and not body:
            base_severity += 3
            indicators.append('EMPTY_POST_ROOT')
            threat_type = 'EMPTY_POST_ROOT'

        if not user_agent:
            base_severity += 2
            indicators.append('MISSING_USER_AGENT')

        if base_severity > 10:
            base_severity = 10

        return base_severity

    def analyze(self, request_data: Dict) -> Dict:
        """
        Synchronous inference using Isolation Forest model.
        Returns AI verdict matching the ai_engine.py interface.
        """
        if not self.model:
            return {
                'severity': 0,
                'threat_type': 'MODEL_UNAVAILABLE',
                'confidence': 0.0,
                'is_zeroday': False,
                'attack_vectors': [],
                'reasoning': 'Isolation Forest model not loaded - using safe fallback',
                'recommended_action': 'allow',
                'indicators': [],
                'cve_reference': []
            }

        try:
            features = self._extract_features(request_data)
            feature_names = ['url_length', 'url_depth', 'body_length', 'entropy', 'special_char_ratio']

            import numpy as np
            feature_vector = np.array(features).reshape(1, -1)

            raw_score = self.model.decision_function(feature_vector)[0]
            prediction = self.model.predict(feature_vector)[0]

            is_anomaly = prediction == -1
            severity = self._score_to_severity(raw_score, request_data)

            if is_anomaly:
                threat_type = 'ANOMALY_ZERODAY'
                confidence = min(0.9, max(0.5, abs(raw_score) / 2))
                reasoning = f'Isolation Forest detected anomalous request pattern (score={raw_score:.3f})'
                recommended_action = 'investigate' if severity < 7 else 'block'
                is_zeroday = True
                attack_vectors = ['Unusual request pattern detected by ML model']
                indicators = [f'Score: {raw_score:.3f}']
            else:
                threat_type = 'NORMAL'
                confidence = min(0.9, max(0.5, raw_score))
                reasoning = f'Request pattern within normal parameters (score={raw_score:.3f})'
                recommended_action = 'allow'
                is_zeroday = False
                attack_vectors = []
                indicators = []

            return {
                'severity': severity,
                'threat_type': threat_type,
                'confidence': float(confidence),
                'is_zeroday': is_zeroday,
                'attack_vectors': attack_vectors,
                'reasoning': reasoning,
                'recommended_action': recommended_action,
                'indicators': indicators,
                'cve_reference': []
            }

        except Exception as e:
            logger.error(f"Tier 2 inference error: {e}")
            return {
                'severity': 2,
                'threat_type': 'INFERENCE_ERROR',
                'confidence': 0.0,
                'is_zeroday': False,
                'attack_vectors': [],
                'reasoning': f'Isolation Forest inference failed: {str(e)}',
                'recommended_action': 'monitor',
                'indicators': [],
                'cve_reference': []
            }


class FeatureExtractor:
    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        # Handle NaN/None values for consistency with training
        try:
            if data is None or (isinstance(data, float) and math.isnan(data)):
                return 0.0
        except (TypeError, ValueError):
            pass
        data = str(data)
        entropy = 0.0
        length = len(data)
        if length == 0:
            return 0.0
        counts = Counter(data)
        for count in counts.values():
            p_x = count / length
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy
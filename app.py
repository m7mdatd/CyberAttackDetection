# Importing all required libraries
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score, confusion_matrix
from sklearn.decomposition import PCA
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Conv1D, MaxPooling1D, Flatten, Dropout, BatchNormalization, Input, \
    GlobalAveragePooling1D
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
import joblib
import logging
import warnings
from datetime import datetime
from scipy import spatial
import json

# Logging Configuration
warnings.filterwarnings('ignore')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cybersecurity_system.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)



class DataPreprocessor:
    def __init__(self):
        self.label_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.pca = None  # TBD dynamically

    def load_and_preprocess(self, file):
        try:
            # Download data
            data = pd.read_csv(file, encoding="utf-8", low_memory=False)
            logging.info("✅ Data uploaded successfully!")

            logging.info(f"🔍 Columns in the file: {list(data.columns)}")
            logging.info(f"📊 Data types in the file:\n{data.dtypes}")
            logging.info(f"🧐 Sample of data:\n{data.head()}")

            # 🔹 Search for categories column automatically
            possible_labels = ["label", "attack_type", "Attack category", "Category"]
            label_column = next((col for col in possible_labels if col in data.columns), None)

            if not label_column:
                raise ValueError("⚠️ Categories column not found (label) In the data.")

            data.rename(columns={label_column: "label"}, inplace=True)
            data["label"] = self.label_encoder.fit_transform(data["label"])
            logging.info(f"✅ The Categories column is selected: {label_column}")

            # 🔹 Automatically extract digital features only
            numeric_features = data.select_dtypes(include=[np.number]).columns.tolist()

            if "label" in numeric_features:
                numeric_features.remove("label")  # 🔹 Remove rating column from features

            if not numeric_features:
                raise ValueError("⚠️ There are not enough numerical features in the data.")

            logging.info(f"🔹 Features used: {numeric_features}")

            # 🔹 Handle missing values ​​before applying PCA
            data[numeric_features] = data[numeric_features].fillna(data[numeric_features].median())
            logging.info("✅ Missing values ​​were replaced with the mean values ​​for each numerical column.")

            # 🔹 Set the number of components to be equal to the lesser of the number of features or 95%
            n_components = min(len(numeric_features), int(len(numeric_features) * 0.95))
            if n_components < 1:
                raise ValueError("⚠️ The number of features is too few, it is not possible to apply PCA.")

            self.pca = PCA(n_components=n_components)
            X_numeric = data[numeric_features].values
            X_reduced = self.pca.fit_transform(X_numeric)
            logging.info(f"✅ Dimensions have been reduced from {X_numeric.shape[1]} to {X_reduced.shape[1]}")

            # 🔹 Delete the file after processing
            try:
                os.remove(file)
                logging.info(f"🗑️ The temporary file has been deleted: {file}")
            except Exception as e:
                logging.warning(f"⚠️ The temporary file was not deleted: {str(e)}")

            return X_reduced, data["label"]

        except Exception as e:
            logging.error(f"❌ Error processing data: {str(e)}")
            return None, None

class ModelBuilder:
    @staticmethod
    def build_cnn(input_shape, num_classes):
        model = Sequential([
            Input(shape=(input_shape[0], 1)),
            Conv1D(64, kernel_size=3, activation='relu', padding='same'),
            BatchNormalization(),
            MaxPooling1D(pool_size=2),
            Conv1D(128, kernel_size=3, activation='relu', padding='same'),
            BatchNormalization(),
            MaxPooling1D(pool_size=2),
            Conv1D(256, kernel_size=3, activation='relu', padding='same'),
            BatchNormalization(),
            GlobalAveragePooling1D(),
            Dense(128, activation='relu'),
            Dropout(0.5),
            Dense(64, activation='relu'),
            Dropout(0.3),
            Dense(num_classes, activation='softmax')
        ])
        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        return model

    @staticmethod
    def build_rnn(input_shape, num_classes):
        model = Sequential([
            Input(shape=(input_shape[0], 1)),
            LSTM(128, return_sequences=True),
            Dropout(0.4),
            LSTM(64),
            Dense(64, activation='relu'),
            Dropout(0.3),
            Dense(32, activation='relu'),
            Dense(num_classes, activation='softmax')
        ])
        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        return model


class ThreatPredictor:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.pattern_memory = {}
        self.threshold = 0.8

    def train_anomaly_detector(self, X_train):
        """Training an anomaly detector on normal data"""
        self.anomaly_detector.fit(X_train)
        logging.info("✅ تم تدريب كاشف الشذوذ على %d عينة", len(X_train))

    def generate_threat_report(self, predictions, scores, timestamps):
        """Create a report on detected threats"""
        report = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_samples': len(predictions),
            'potential_threats': int(np.sum(predictions)),
            'average_threat_score': float(np.mean(scores[predictions]) if any(predictions) else 0),
            'high_risk_threats': int(np.sum(scores > 0.9)),
            'threat_details': []
        }
        return report

    def detect_new_patterns(self, X_new):
        """Discover new patterns in data"""
        anomaly_scores = self.anomaly_detector.score_samples(X_new)
        anomalies = anomaly_scores < np.percentile(anomaly_scores, 10)

        if np.any(anomalies):
            logging.warning("تم اكتشاف %d نمط جديد محتمل", np.sum(anomalies))
            return X_new[anomalies], anomaly_scores[anomalies]
        return None, None

    def update_pattern_memory(self, new_patterns, confidence_scores):
        """Refresh pattern memory with new patterns"""
        if new_patterns is not None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            for pattern, score in zip(new_patterns, confidence_scores):
                pattern_hash = hash(pattern.tobytes())
                self.pattern_memory[pattern_hash] = {
                    'pattern': pattern,
                    'score': score,
                    'first_seen': timestamp,
                    'frequency': 1
                }
            logging.info("تم تحديث ذاكرة الأنماط مع %d نمط جديد", len(new_patterns))

    def predict_threats(self, X_current):
        """Predict potential threats based on stored patterns"""
        predictions = []
        threat_scores = []

        for x in X_current:
            max_similarity = 0
            for stored_pattern in self.pattern_memory.values():
                similarity = self._calculate_similarity(x, stored_pattern['pattern'])
                max_similarity = max(max_similarity, similarity)

            is_threat = max_similarity > self.threshold
            predictions.append(is_threat)
            threat_scores.append(max_similarity)

        return np.array(predictions), np.array(threat_scores)

    def _calculate_similarity(self, pattern1, pattern2):
        """Calculating the degree of similarity between two patterns"""
        return 1 - spatial.distance.cosine(pattern1, pattern2)

class EnhancedCyberSecuritySystem:
    def __init__(self):
        self.models = {}
        self.callbacks = self._create_callbacks()
        self.threat_predictor = ThreatPredictor()

    def _create_callbacks(self):
        return [
            EarlyStopping(
                monitor='val_loss',
                patience=5,
                restore_best_weights=True
            ),
            ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.2,
                patience=3,
                min_lr=1e-6
            )
        ]

    def initialize_models(self, num_classes, input_dim):
        self.models = {
            'svm': SVC(probability=True, class_weight='balanced'),
            'random_forest': RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                class_weight='balanced',
                n_jobs=-1
            ),
            'cnn': ModelBuilder.build_cnn((input_dim,), num_classes),
            'rnn': ModelBuilder.build_rnn((input_dim,), num_classes)
        }

    def train_and_evaluate(self, X_train, X_test, y_train, y_test):
        results = {}
        X_train_reshaped = X_train.reshape(-1, X_train.shape[1], 1)
        X_test_reshaped = X_test.reshape(-1, X_test.shape[1], 1)

        # Threat detector training
        self.threat_predictor.train_anomaly_detector(X_train)

        # Find new styles
        new_patterns, confidence_scores = self.threat_predictor.detect_new_patterns(X_test)
        if new_patterns is not None:
            self.threat_predictor.update_pattern_memory(new_patterns, confidence_scores)

        # Threat prediction
        timestamps = pd.date_range(start='now', periods=len(X_test), freq='S')
        predictions, threat_scores = self.threat_predictor.predict_threats(X_test)

        # Create a threat report
        threat_report = self.threat_predictor.generate_threat_report(
            predictions, threat_scores, timestamps
        )

        logging.info("\n=== تقرير التهديدات ===\n%s", json.dumps(threat_report, indent=2, ensure_ascii=False))

        param_grid = {
            'svm': {
                'C': [1, 10],
                'gamma': ['scale', 'auto'],
                'kernel': ['rbf']
            },
            'random_forest': {
                'n_estimators': [100, 200],
                'max_depth': [10, 20],
                'min_samples_split': [2, 5]
            }
        }

        for name, model in self.models.items():
            try:
                logging.info(f"Model training {name}")

                if name in ['svm', 'random_forest']:
                    grid_search = GridSearchCV(
                        model,
                        param_grid[name],
                        cv=3,
                        n_jobs=-1,
                        scoring='f1_macro'
                    )
                    grid_search.fit(X_train, y_train)
                    model = grid_search.best_estimator_
                    self.models[name] = model
                    joblib.dump(model, f'models/{name}_model.pkl')
                    y_pred = model.predict(X_test)

                else:  # Neural models
                    model.fit(
                        X_train_reshaped,
                        y_train,
                        validation_split=0.2,
                        epochs=50,
                        batch_size=32,
                        callbacks=self.callbacks,
                        verbose=1
                    )
                    model.save(f'models/{name}_model.keras')
                    y_pred = np.argmax(model.predict(X_test_reshaped), axis=1)

                results[name] = self._calculate_metrics(y_test, y_pred)

            except Exception as e:
                logging.error(f"Error training model {name}: {str(e)}")
                continue

        self._display_results(results)
        return results, threat_report

    def _calculate_metrics(self, y_true, y_pred):
        return {
            'accuracy': round(accuracy_score(y_true, y_pred) * 100, 2),
            'recovery': round(recall_score(y_true, y_pred, average='macro') * 100, 2),
            'Positive precision': round(precision_score(y_true, y_pred, average='macro') * 100, 2),
            'an average F1': round(f1_score(y_true, y_pred, average='macro') * 100, 2)
        }

    def _display_results(self, results):
        df_results = pd.DataFrame.from_dict(results, orient='index')
        logging.info("\n=== Model evaluation report ===\n%s", df_results.to_string())

        plt.figure(figsize=(12, 6))
        df_results.plot(kind='bar')
        plt.title('Compare models performance')
        plt.xlabel('Models')
        plt.ylabel('Percentage')
        plt.legend(loc='lower right')
        plt.grid(axis='y')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('model_comparison.png')
        plt.close()

        best_model = df_results.sort_values(by=['معدل F1'], ascending=False).index[0]
        logging.info(f"Best model based on rate F1: {best_model}")


def main():
    try:
        os.makedirs('models', exist_ok=True)

        preprocessor = DataPreprocessor()
        file_path = 'Payload_data_UNSW.csv'
        X, y = preprocessor.load_and_preprocess(file_path)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=0.1,
            random_state=42,
            stratify=y
        )

        system = EnhancedCyberSecuritySystem()
        num_classes = len(np.unique(y))
        system.initialize_models(num_classes, X.shape[1])
        results, threat_report = system.train_and_evaluate(X_train, X_test, y_train, y_test)

        # Save threat report
        with open('threat_report.json', 'w', encoding='utf-8') as f:
            json.dump(threat_report, f, ensure_ascii=False, indent=2)

    except Exception as e:
        logging.error(f"System operation error: {str(e)}")
        raise


if __name__ == "__main__":
    main()

"""
Machine Learning Model Training Module for ScamShield
Trains and evaluates models for call and SMS scam detection
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, accuracy_score
import joblib
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ModelTrainer:
    """Train and evaluate scam detection models"""
    
    def __init__(self, data_dir='data', model_dir='models'):
        """
        Initialize model trainer
        
        Args:
            data_dir: Directory containing training data
            model_dir: Directory to save trained models
        """
        self.data_dir = data_dir
        self.model_dir = model_dir
        
        # Create directories if they don't exist
        os.makedirs(model_dir, exist_ok=True)
    
    def train_call_model(self, dataset_path='data/call_dataset.csv'):
        """
        Train call scam detection model
        
        Args:
            dataset_path: Path to call dataset
        """
        logger.info("Training call scam detection model...")
        
        # Load data
        df = pd.read_csv(dataset_path)
        logger.info(f"Loaded {len(df)} call records")
        
        # Features for training
        feature_columns = [
            'duration', 'call_frequency', 'is_unknown', 'is_international',
            'is_risky_country', 'very_short_call', 'repeated_calls',
            'excessive_calls', 'has_repeated_digits', 'has_sequential_digits',
            'time_risk', 'unknown_and_international', 'short_and_repeated'
        ]
        
        X = df[feature_columns]
        y = df['is_scam']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        logger.info(f"Training set: {len(X_train)} samples")
        logger.info(f"Test set: {len(X_test)} samples")
        logger.info(f"Scam ratio: {y.mean():.2%}")
        
        # Train Random Forest model
        logger.info("Training Random Forest model...")
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            class_weight='balanced'
        )
        rf_model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = rf_model.predict(X_test)
        y_pred_proba = rf_model.predict_proba(X_test)[:, 1]
        
        accuracy = accuracy_score(y_test, y_pred)
        auc = roc_auc_score(y_test, y_pred_proba)
        
        logger.info(f"Random Forest - Accuracy: {accuracy:.4f}, AUC: {auc:.4f}")
        logger.info("\nClassification Report:")
        logger.info(classification_report(y_test, y_pred, target_names=['Safe', 'Scam']))
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': feature_columns,
            'importance': rf_model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        logger.info("\nTop 5 Important Features:")
        logger.info(feature_importance.head().to_string())
        
        # Save model
        model_path = os.path.join(self.model_dir, 'call_model.pkl')
        joblib.dump(rf_model, model_path)
        logger.info(f"Model saved to {model_path}")
        
        return {
            'model': rf_model,
            'accuracy': accuracy,
            'auc': auc,
            'feature_importance': feature_importance
        }
    
    def train_sms_model(self, dataset_path='data/sms_dataset.csv'):
        """
        Train SMS scam detection model
        
        Args:
            dataset_path: Path to SMS dataset
        """
        logger.info("Training SMS scam detection model...")
        
        # Load data
        df = pd.read_csv(dataset_path)
        logger.info(f"Loaded {len(df)} SMS records")
        
        # Features for training
        feature_columns = [
            'length', 'word_count', 'exclamation_count', 'question_count',
            'uppercase_ratio', 'digit_count', 'scam_keyword_count',
            'has_urls', 'url_count', 'has_urgency', 'requests_action',
            'mentions_money', 'mentions_account', 'has_threat'
        ]
        
        X = df[feature_columns]
        y = df['is_scam']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        logger.info(f"Training set: {len(X_train)} samples")
        logger.info(f"Test set: {len(X_test)} samples")
        logger.info(f"Scam ratio: {y.mean():.2%}")
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train Logistic Regression model
        logger.info("Training Logistic Regression model...")
        lr_model = LogisticRegression(
            max_iter=1000,
            random_state=42,
            class_weight='balanced'
        )
        lr_model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = lr_model.predict(X_test_scaled)
        y_pred_proba = lr_model.predict_proba(X_test_scaled)[:, 1]
        
        accuracy = accuracy_score(y_test, y_pred)
        auc = roc_auc_score(y_test, y_pred_proba)
        
        logger.info(f"Logistic Regression - Accuracy: {accuracy:.4f}, AUC: {auc:.4f}")
        logger.info("\nClassification Report:")
        logger.info(classification_report(y_test, y_pred, target_names=['Safe', 'Scam']))
        
        # Train Random Forest for comparison
        logger.info("\nTraining Random Forest model...")
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        rf_model.fit(X_train, y_train)
        
        y_pred_rf = rf_model.predict(X_test)
        y_pred_proba_rf = rf_model.predict_proba(X_test)[:, 1]
        
        accuracy_rf = accuracy_score(y_test, y_pred_rf)
        auc_rf = roc_auc_score(y_test, y_pred_proba_rf)
        
        logger.info(f"Random Forest - Accuracy: {accuracy_rf:.4f}, AUC: {auc_rf:.4f}")
        
        # Use the better model
        if auc_rf > auc:
            logger.info("Using Random Forest model (better performance)")
            best_model = rf_model
            best_accuracy = accuracy_rf
            best_auc = auc_rf
            
            # Feature importance
            feature_importance = pd.DataFrame({
                'feature': feature_columns,
                'importance': rf_model.feature_importances_
            }).sort_values('importance', ascending=False)
        else:
            logger.info("Using Logistic Regression model (better performance)")
            best_model = lr_model
            best_accuracy = accuracy
            best_auc = auc
            
            # Feature coefficients
            feature_importance = pd.DataFrame({
                'feature': feature_columns,
                'importance': np.abs(lr_model.coef_[0])
            }).sort_values('importance', ascending=False)
        
        logger.info("\nTop 5 Important Features:")
        logger.info(feature_importance.head().to_string())
        
        # Save model
        model_path = os.path.join(self.model_dir, 'sms_model.pkl')
        joblib.dump(best_model, model_path)
        logger.info(f"Model saved to {model_path}")
        
        return {
            'model': best_model,
            'accuracy': best_accuracy,
            'auc': best_auc,
            'feature_importance': feature_importance
        }
    
    def evaluate_model(self, model_path, test_data_path, feature_columns):
        """
        Evaluate a trained model on test data
        
        Args:
            model_path: Path to saved model
            test_data_path: Path to test dataset
            feature_columns: List of feature column names
        """
        logger.info(f"Evaluating model: {model_path}")
        
        # Load model and data
        model = joblib.load(model_path)
        df = pd.read_csv(test_data_path)
        
        X = df[feature_columns]
        y = df['is_scam']
        
        # Predict
        y_pred = model.predict(X)
        y_pred_proba = model.predict_proba(X)[:, 1]
        
        # Metrics
        accuracy = accuracy_score(y, y_pred)
        auc = roc_auc_score(y, y_pred_proba)
        
        logger.info(f"Accuracy: {accuracy:.4f}")
        logger.info(f"AUC: {auc:.4f}")
        logger.info("\nClassification Report:")
        logger.info(classification_report(y, y_pred, target_names=['Safe', 'Scam']))
        logger.info("\nConfusion Matrix:")
        logger.info(confusion_matrix(y, y_pred))
        
        return {
            'accuracy': accuracy,
            'auc': auc
        }


def main():
    """Main training function"""
    trainer = ModelTrainer()
    
    print("="*60)
    print("ScamShield ML Model Training")
    print("="*60)
    
    # Train call model
    print("\n" + "="*60)
    print("TRAINING CALL SCAM DETECTION MODEL")
    print("="*60)
    try:
        call_results = trainer.train_call_model()
        print(f"\n✓ Call model training completed")
        print(f"  Accuracy: {call_results['accuracy']:.2%}")
        print(f"  AUC: {call_results['auc']:.4f}")
    except Exception as e:
        print(f"✗ Call model training failed: {e}")
    
    # Train SMS model
    print("\n" + "="*60)
    print("TRAINING SMS SCAM DETECTION MODEL")
    print("="*60)
    try:
        sms_results = trainer.train_sms_model()
        print(f"\n✓ SMS model training completed")
        print(f"  Accuracy: {sms_results['accuracy']:.2%}")
        print(f"  AUC: {sms_results['auc']:.4f}")
    except Exception as e:
        print(f"✗ SMS model training failed: {e}")
    
    print("\n" + "="*60)
    print("Training completed! Models saved in 'models/' directory")
    print("="*60)


if __name__ == "__main__":
    main()

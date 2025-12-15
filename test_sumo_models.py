#!/usr/bin/env python3
"""
Test script to verify SUMo pretrained models load correctly.
"""
import os
import sys
import joblib

# Add SUMo pipeline to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'sumo'))

def test_source_separation_model():
    """Test loading source separation model."""
    model_path = 'sumo/sumo_pipeline/source_separation/models/source_separation_model_bayesian_optimization.joblib'
    
    print("🔍 Testing Source Separation Model...")
    print(f"   Path: {model_path}")
    
    if not os.path.exists(model_path):
        print("   ❌ Model file not found!")
        return False
    
    try:
        model = joblib.load(model_path)
        print(f"   ✅ Model loaded successfully!")
        print(f"   Type: {type(model).__name__}")
        
        # Check if model has expected methods
        if hasattr(model, 'predict_proba'):
            print(f"   ✅ predict_proba method available")
        if hasattr(model, 'feature_names'):
            print(f"   ✅ Feature names stored: {len(model.feature_names)} features")
        
        return True
    except Exception as e:
        print(f"   ❌ Error loading model: {e}")
        return False

def test_target_separation_model():
    """Test loading target separation model."""
    model_path = 'sumo/sumo_pipeline/target_separation/models/target_separation_model_bayesian_optimization.joblib'
    
    print("\n🔍 Testing Target Separation Model...")
    print(f"   Path: {model_path}")
    
    if not os.path.exists(model_path):
        print("   ❌ Model file not found!")
        return False
    
    try:
        model = joblib.load(model_path)
        print(f"   ✅ Model loaded successfully!")
        print(f"   Type: {type(model).__name__}")
        
        # Check if model has expected methods
        if hasattr(model, 'predict_proba'):
            print(f"   ✅ predict_proba method available")
        if hasattr(model, 'feature_names'):
            print(f"   ✅ Feature names stored: {len(model.feature_names)} features")
        
        return True
    except Exception as e:
        print(f"   ❌ Error loading model: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("SUMo Pretrained Model Verification")
    print("=" * 60)
    
    source_ok = test_source_separation_model()
    target_ok = test_target_separation_model()
    
    print("\n" + "=" * 60)
    if source_ok and target_ok:
        print("✅ All models loaded successfully!")
        print("=" * 60)
        sys.exit(0)
    else:
        print("❌ Some models failed to load")
        print("=" * 60)
        sys.exit(1)

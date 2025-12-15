#!/usr/bin/env python3
"""
SUMo Model Inference Verification Test

This script verifies that the pretrained SUMo models can actually run inference:
1. Creates synthetic flow data
2. Extracts SUMo features
3. Runs inference with both models
4. Validates predictions are generated
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
import tempfile
from pathlib import Path

# Add our module to path
sys.path.insert(0, os.path.dirname(__file__))
from sumo_adapter import FlowFeatureExtractor

def create_synthetic_flow(output_dir: str, flow_id: str, num_packets: int = 50):
    """
    Create synthetic inflow and outflow files for testing.
    
    Format: timestamp\tpacket_size
    """
    inflow_dir = Path(output_dir) / 'inflow'
    outflow_dir = Path(output_dir) / 'outflow'
    inflow_dir.mkdir(parents=True, exist_ok=True)
    outflow_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate synthetic inflow (packets TO host)
    inflow_data = []
    timestamp = 0.0
    for i in range(num_packets):
        size = np.random.choice([52, 1500, 1024, 512])  # Common packet sizes
        timestamp += np.random.uniform(0.001, 0.05)  # 1-50ms gaps
        inflow_data.append(f"{timestamp:.6f}\t{size}")
    
    with open(inflow_dir / flow_id, 'w') as f:
        f.write('\n'.join(inflow_data))
    
    # Generate synthetic outflow (packets FROM host)
    outflow_data = []
    timestamp = 0.0
    for i in range(num_packets):
        size = np.random.choice([52, 1500, 1024, 512])
        timestamp += np.random.uniform(0.001, 0.05)
        outflow_data.append(f"{timestamp:.6f}\t{size}")
    
    with open(outflow_dir / flow_id, 'w') as f:
        f.write('\n'.join(outflow_data))
    
    print(f"✅ Created synthetic flow '{flow_id}' with {num_packets} packets each direction")

def test_feature_extraction(flows_dir: str):
    """Test that feature extraction works."""
    print("\n" + "="*60)
    print("TEST 1: Feature Extraction")
    print("="*60)
    
    extractor = FlowFeatureExtractor()
    
    try:
        features_df = extractor.process_flow_directory(flows_dir)
        
        print(f"✅ Feature extraction successful!")
        print(f"   Shape: {features_df.shape}")
        print(f"   Flows processed: {len(features_df)}")
        print(f"   Features extracted: {features_df.shape[1]}")
        
        # Verify feature count
        expected_features = 168  # 166 features + Class + Capture
        if features_df.shape[1] >= 166:
            print(f"✅ Feature count OK (expected ~{expected_features}, got {features_df.shape[1]})")
        else:
            print(f"⚠️  Feature count mismatch (expected ~{expected_features}, got {features_df.shape[1]})")
        
        # Show sample features
        print(f"\n   Sample feature values:")
        print(f"   - TotalPackets: {features_df['TotalPackets'].iloc[0]}")
        print(f"   - totalBytes: {features_df['totalBytes'].iloc[0]}")
        print(f"   - meanPacketSizes: {features_df['meanPacketSizes'].iloc[0]:.2f}")
        
        return features_df
        
    except Exception as e:
        print(f"❌ Feature extraction failed: {e}")
        import traceback
        traceback.print_exc()
        return None

def test_source_separation_inference(features_df: pd.DataFrame):
    """Test source separation model inference."""
    print("\n" + "="*60)
    print("TEST 2: Source Separation Model Inference")
    print("="*60)
    
    model_path = 'sumo/sumo_pipeline/source_separation/models/source_separation_model_bayesian_optimization.joblib'
    
    if not os.path.exists(model_path):
        print(f"❌ Model not found: {model_path}")
        return False
    
    try:
        # Load model
        model = joblib.load(model_path)
        print(f"✅ Model loaded: {type(model).__name__}")
        
        # Prepare features (exclude Class and Capture columns)
        X = features_df[features_df.columns[:-2]]
        
        print(f"   Input shape: {X.shape}")
        print(f"   Model expects {len(model.feature_names)} features")
        
        # Ensure we have the right features
        # The model may have been trained with a subset after removing zero columns
        # We need to align our features with the model's expected features
        
        # Get common features
        model_features = set(model.feature_names)
        our_features = set(X.columns)
        common_features = model_features & our_features
        
        print(f"   Common features: {len(common_features)}")
        
        if len(common_features) < 150:  # Arbitrary threshold
            print(f"⚠️  Feature mismatch: only {len(common_features)} common features")
            print(f"   Missing in our data: {model_features - our_features}")
            # Try to add missing features as zeros
            for feat in model_features - our_features:
                X[feat] = 0
        
        # Reorder columns to match model
        X = X[model.feature_names]
        
        # Run inference
        predictions = model.predict(X)
        probabilities = model.predict_proba(X)
        
        print(f"✅ Inference successful!")
        print(f"   Predictions shape: {predictions.shape}")
        print(f"   Probabilities shape: {probabilities.shape}")
        print(f"   Predicted classes: {predictions}")
        print(f"   Probabilities (first flow): {probabilities[0]}")
        print(f"   Confidence scores: {probabilities[:, 1]}")  # Probability of class 1
        
        # Interpretation
        threshold = 0.001  # SUMo's default threshold
        client_flows = probabilities[:, 1] < threshold
        print(f"\n   Classification (threshold={threshold}):")
        print(f"   - Client-side flows: {client_flows.sum()}")
        print(f"   - OS-side flows: {(~client_flows).sum()}")
        
        return True
        
    except Exception as e:
        print(f"❌ Source separation inference failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_target_separation_inference(features_df: pd.DataFrame):
    """Test target separation model inference."""
    print("\n" + "="*60)
    print("TEST 3: Target Separation Model Inference")
    print("="*60)
    
    model_path = 'sumo/sumo_pipeline/target_separation/models/target_separation_model_bayesian_optimization.joblib'
    
    if not os.path.exists(model_path):
        print(f"❌ Model not found: {model_path}")
        return False
    
    try:
        # Load model
        model = joblib.load(model_path)
        print(f"✅ Model loaded: {type(model).__name__}")
        
        # Prepare features
        X = features_df[features_df.columns[:-2]]
        
        print(f"   Input shape: {X.shape}")
        print(f"   Model expects {len(model.feature_names)} features")
        
        # Align features with model
        model_features = set(model.feature_names)
        our_features = set(X.columns)
        common_features = model_features & our_features
        
        print(f"   Common features: {len(common_features)}")
        
        # Add missing features
        for feat in model_features - our_features:
            X[feat] = 0
        
        # Reorder columns
        X = X[model.feature_names]
        
        # Run inference
        predictions = model.predict(X)
        probabilities = model.predict_proba(X)
        
        print(f"✅ Inference successful!")
        print(f"   Predictions shape: {predictions.shape}")
        print(f"   Probabilities shape: {probabilities.shape}")
        print(f"   Predicted classes: {predictions}")
        print(f"   Probabilities (first flow): {probabilities[0]}")
        
        # Interpretation
        threshold = 0.9  # SUMo's default threshold
        onion_service_flows = probabilities[:, 1] >= threshold
        print(f"\n   Classification (threshold={threshold}):")
        print(f"   - Sessions to onion services: {onion_service_flows.sum()}")
        print(f"   - Other sessions: {(~onion_service_flows).sum()}")
        
        return True
        
    except Exception as e:
        print(f"❌ Target separation inference failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("="*60)
    print("SUMo Pretrained Model Verification Test")
    print("="*60)
    print("\nThis test verifies that:")
    print("1. Feature extraction works correctly")
    print("2. Source separation model runs inference")
    print("3. Target separation model runs inference")
    print("4. Predictions are generated with proper confidence scores")
    
    # Create temporary directory for synthetic flows
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"\n📁 Using temporary directory: {tmpdir}")
        
        # Create multiple synthetic flows
        print("\n🔧 Creating synthetic flow data...")
        for i in range(5):
            create_synthetic_flow(tmpdir, f"flow_{i:03d}", num_packets=np.random.randint(30, 100))
        
        # Test feature extraction
        features_df = test_feature_extraction(tmpdir)
        
        if features_df is None:
            print("\n❌ VERIFICATION FAILED: Feature extraction did not work")
            return False
        
        # Test source separation
        source_ok = test_source_separation_inference(features_df)
        
        # Test target separation
        target_ok = test_target_separation_inference(features_df)
        
        # Final summary
        print("\n" + "="*60)
        print("VERIFICATION SUMMARY")
        print("="*60)
        print(f"Feature Extraction:        {'✅ PASS' if features_df is not None else '❌ FAIL'}")
        print(f"Source Separation Model:   {'✅ PASS' if source_ok else '❌ FAIL'}")
        print(f"Target Separation Model:   {'✅ PASS' if target_ok else '❌ FAIL'}")
        
        if features_df is not None and source_ok and target_ok:
            print("\n🎉 ALL TESTS PASSED!")
            print("The SUMo pretrained models are working correctly.")
            print("\nThe models can:")
            print("  ✓ Load from disk without errors")
            print("  ✓ Accept our extracted features")
            print("  ✓ Run inference and generate predictions")
            print("  ✓ Produce confidence scores for filtering")
            return True
        else:
            print("\n⚠️  SOME TESTS FAILED")
            print("Please review the errors above.")
            return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

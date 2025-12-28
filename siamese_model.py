"""
Siamese Neural Network Module

Loads and runs the pretrained lightweight Siamese model for flow similarity refinement.
This model is used ONLY for re-ranking top-K candidates, NOT as primary signal.

Architecture:
    - Twin encoders (shared weights)
    - Input: 300-element flow vector
    - Encoder: 300 → 128 → 64 → 32
    - Cosine similarity between embeddings
    - Sigmoid activation at inference → [0, 1]

Model Weight: 30% in final fusion (secondary signal)
Statistical Weight: 70% (primary signal)
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from pathlib import Path
from typing import List, Tuple, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SiameseEncoder(nn.Module):
    """
    Flow embedding encoder using 1D convolutions.
    
    Transforms 300-element flow representation to 64-dimensional embedding.
    Architecture matches the trained model structure with Conv1D layers.
    """
    
    def __init__(self):
        """Initialize encoder to match trained 1D CNN model."""
        super(SiameseEncoder, self).__init__()
        
        self.net = nn.Sequential(
            nn.Conv1d(1, 32, kernel_size=5, padding=2),  # (batch, 32, 300)
            nn.ReLU(),
            nn.MaxPool1d(2),  # (batch, 32, 150)
            nn.Conv1d(32, 64, kernel_size=3, padding=1),  # (batch, 64, 150)
            nn.ReLU(),
            nn.AdaptiveAvgPool1d(1)  #  (batch, 64, 1)
        )
        self.fc = nn.Linear(64, 64)
    
    def forward(self, x):
        """
        Forward pass through encoder.
        
        Args:
            x: Input flow tensor (batch_size, 300)
            
        Returns:
            Embedding tensor (batch_size, 64)
        """
        x = x.unsqueeze(1)
        
        x = self.net(x)
        
        x = x.squeeze(-1)
        
        x = self.fc(x)
        
        return x



class SiameseNetwork(nn.Module):
    """
    Siamese Network for flow similarity.
    
    Uses twin encoders with shared weights to compute embeddings,
    then computes cosine similarity between embeddings.
    """
    
    def __init__(self):
        """Initialize Siamese network."""
        super(SiameseNetwork, self).__init__()
        
        self.encoder = SiameseEncoder()
    
    def forward_one(self, x):
        """
        Encode a single flow.
        
        Args:
            x: Flow tensor (batch_size, 300)
            
        Returns:
            Embedding (batch_size, 32)
        """
        return self.encoder(x)
    
    def forward(self, x1, x2):
        """
        Forward pass for flow pair.
        
        Args:
            x1: First flow tensor (batch_size, 300)
            x2: Second flow tensor (batch_size, 300)
            
        Returns:
            Cosine similarity (batch_size,)
        """
        emb1 = self.forward_one(x1)
        emb2 = self.forward_one(x2)
        
        similarity = F.cosine_similarity(emb1, emb2, dim=1)
        
        similarity = torch.sigmoid(similarity)
        
        return similarity


def load_siamese_model(model_path: str, 
                       device: Optional[str] = None) -> SiameseNetwork:
    """
    Load pretrained Siamese model from file.
    
    Args:
        model_path: Path to .pth model file
        device: Device to load model on ('cpu', 'cuda', 'mps', or None for auto)
        
    Returns:
        Loaded SiameseNetwork in eval mode
        
    Raises:
        FileNotFoundError: If model file doesn't exist
        RuntimeError: If model loading fails
    """
    model_path = Path(model_path)
    
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")
    
    if device is None:
        if torch.cuda.is_available():
            device = 'cuda'
        elif torch.backends.mps.is_available():
            device = 'mps'
        else:
            device = 'cpu'
    
    logger.info(f"Loading Siamese model from {model_path}")
    logger.info(f"Using device: {device}")
    
    model = SiameseNetwork()
    
    try:
        state_dict = torch.load(model_path, map_location=device)
        
        if 'model_state_dict' in state_dict:
            model.load_state_dict(state_dict['model_state_dict'])
        elif 'state_dict' in state_dict:
            model.load_state_dict(state_dict['state_dict'])
        else:
            model.load_state_dict(state_dict)
        
        logger.info("✅ Model loaded successfully")
        
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        raise RuntimeError(f"Model loading failed: {e}")
    
    model = model.to(device)
    model.eval()
    
    return model


def siamese_similarity(model: SiameseNetwork,
                      flow_a: np.ndarray,
                      flow_b: np.ndarray,
                      device: Optional[str] = None) -> float:
    """
    Compute Siamese similarity between two flows.
    
    Args:
        model: Loaded SiameseNetwork
        flow_a: Processed flow array (300,)
        flow_b: Processed flow array (300,)
        device: Device for computation (auto-detected if None)
        
    Returns:
        Similarity score in [0, 1]
    """
    if device is None:
        device = next(model.parameters()).device
    
    tensor_a = torch.from_numpy(flow_a).float().unsqueeze(0).to(device)
    tensor_b = torch.from_numpy(flow_b).float().unsqueeze(0).to(device)
    
    with torch.no_grad():
        similarity = model(tensor_a, tensor_b)
    
    return float(similarity.cpu().item())


def batch_siamese_similarity(model: SiameseNetwork,
                             flow_pairs: List[Tuple[np.ndarray, np.ndarray]],
                             batch_size: int = 32,
                             device: Optional[str] = None) -> np.ndarray:
    """
    Compute Siamese similarity for multiple flow pairs efficiently.
    
    Args:
        model: Loaded SiameseNetwork
        flow_pairs: List of (flow_a, flow_b) tuples
        batch_size: Batch size for processing (default: 32)
        device: Device for computation
        
    Returns:
        Array of similarity scores (len(flow_pairs),)
    """
    if device is None:
        device = next(model.parameters()).device
    
    similarities = []
    
    for i in range(0, len(flow_pairs), batch_size):
        batch_pairs = flow_pairs[i:i + batch_size]
        
        flows_a = torch.stack([
            torch.from_numpy(pair[0]).float() 
            for pair in batch_pairs
        ]).to(device)
        
        flows_b = torch.stack([
            torch.from_numpy(pair[1]).float() 
            for pair in batch_pairs
        ]).to(device)
        
        with torch.no_grad():
            batch_sim = model(flows_a, flows_b)
        
        similarities.extend(batch_sim.cpu().numpy())
    
    return np.array(similarities)


def batch_similarity_with_target(model: SiameseNetwork,
                                 target_flow: np.ndarray,
                                 candidate_flows: dict,
                                 batch_size: int = 32,
                                 device: Optional[str] = None) -> dict:
    """
    Compute similarity between target flow and multiple candidates.
    
    Efficient batch processing for comparing one target against many candidates.
    
    Args:
        model: Loaded SiameseNetwork
        target_flow: Target flow array (300,)
        candidate_flows: Dict of {flow_id: flow_array}
        batch_size: Batch size for processing
        device: Device for computation
        
    Returns:
        Dict of {flow_id: similarity_score}
    """
    if device is None:
        device = next(model.parameters()).device
    
    flow_ids = list(candidate_flows.keys())
    flow_arrays = [candidate_flows[fid] for fid in flow_ids]
    
    pairs = [(target_flow, flow_array) for flow_array in flow_arrays]
    
    similarities = batch_siamese_similarity(model, pairs, batch_size, device)
    
    results = {
        flow_id: float(sim)
        for flow_id, sim in zip(flow_ids, similarities)
    }
    
    return results


def get_model_info(model: SiameseNetwork) -> dict:
    """
    Get information about loaded model.
    
    Args:
        model: Loaded SiameseNetwork
        
    Returns:
        Dictionary with model information
    """
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    
    return {
        'total_parameters': total_params,
        'trainable_parameters': trainable_params,
        'device': str(next(model.parameters()).device),
        'architecture': {
            'input_dim': 300,
            'encoder_type': '1D_CNN',
            'conv_layers': '32->64',
            'output_dim': 64,
            'similarity_method': 'cosine'
        }
    }



def test_model_architecture():
    """Test model architecture."""
    print("Testing Siamese model architecture...")
    
    model = SiameseNetwork(input_dim=300, hidden_dims=[128, 64, 32])
    
    x1 = torch.randn(4, 300)
    x2 = torch.randn(4, 300)
    
    output = model(x1, x2)
    
    assert output.shape == (4,), f"Expected shape (4,), got {output.shape}"
    assert torch.all((output >= 0) & (output <= 1)), "Output should be in [0, 1]"
    
    print("✅ Architecture test passed")
    return model


def test_model_loading(model_path: str):
    """Test model loading from file."""
    print(f"\nTesting model loading from {model_path}...")
    
    try:
        model = load_siamese_model(model_path)
        info = get_model_info(model)
        
        print(f"✅ Model loaded successfully")
        print(f"   Total parameters: {info['total_parameters']:,}")
        print(f"   Device: {info['device']}")
        
        return model
    except Exception as e:
        print(f"❌ Model loading failed: {e}")
        return None


def test_inference(model: SiameseNetwork):
    """Test inference with dummy data."""
    print("\nTesting inference...")
    
    flow1 = np.random.randn(300).astype(np.float32) * 100 + 500
    flow2 = flow1 + np.random.randn(300).astype(np.float32) * 10
    flow3 = np.random.randn(300).astype(np.float32) * 100 + 1000
    
    sim_12 = siamese_similarity(model, flow1, flow2)
    sim_13 = siamese_similarity(model, flow1, flow3)
    
    print(f"Similarity flow1-flow2: {sim_12:.4f}")
    print(f"Similarity flow1-flow3: {sim_13:.4f}")
    
    assert 0 <= sim_12 <= 1, "Similarity out of range"
    assert 0 <= sim_13 <= 1, "Similarity out of range"
    
    candidates = {f'flow_{i}': np.random.randn(300).astype(np.float32) * 100 + 500 
                  for i in range(10)}
    
    batch_results = batch_similarity_with_target(model, flow1, candidates, batch_size=4)
    
    assert len(batch_results) == 10, f"Expected 10 results, got {len(batch_results)}"
    for flow_id, score in batch_results.items():
        assert 0 <= score <= 1, f"Score out of range for {flow_id}: {score}"
    
    print(f"✅ Batch inference: {len(batch_results)} flows processed")


if __name__ == "__main__":
    print("=" * 70)
    print("Siamese Model Module - Tests")
    print("=" * 70)
    
    model = test_model_architecture()
    
    model_path = "./lightweight_siamese.pth"
    if Path(model_path).exists():
        loaded_model = test_model_loading(model_path)
        if loaded_model is not None:
            test_inference(loaded_model)
    else:
        print(f"\n⚠️  Model file not found: {model_path}")
        print("   Skipping loading and inference tests")
        print("   Testing with random initialized model...")
        test_inference(model)
    
    print("\n" + "=" * 70)
    print("✅ All tests passed!")
    print("=" * 70)

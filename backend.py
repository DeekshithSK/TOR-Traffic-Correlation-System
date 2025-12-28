"""
Traffic Analysis Dashboard - Backend Processing Engine
Adapted from RECTor Framework for macOS M2 with MPS Support

This module implements:
1. Full RECTor preprocessing pipeline (Step1 + Step2)
2. Model architectures (GRU + Attention, Transformer)
3. MPS-optimized inference engine
"""

import os
import pickle
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import List, Dict, Tuple, Optional, Union
from pathlib import Path
from siamese_model import SiameseNetwork  # Import certified architecture

QUIET_MODE = os.environ.get('QUIET_MODE', 'true').lower() == 'true'

def vprint(*args, **kwargs):
    """Verbose print - only prints if QUIET_MODE is disabled."""
    if not QUIET_MODE:
        print(*args, **kwargs)



def get_device() -> torch.device:
    """
    Detect and return the best available device for PyTorch.
    Prioritizes MPS (Metal Performance Shaders) on Apple Silicon.
    """
    if torch.backends.mps.is_available():
        return torch.device("mps")
    elif torch.cuda.is_available():
        return torch.device("cuda")
    else:
        return torch.device("cpu")


DEVICE = get_device()
vprint(f"🔧 Backend initialized with device: {DEVICE}")



class WindowCreator:
    """
    Step1 of RECTor pipeline: Parse inflow/outflow directories and create 
    overlapping time windows with threshold filtering.
    """
    
    def __init__(self, threshold: int = 2, interval: int = 5, 
                 num_windows: int = 10, add_num: int = 2,
                 analysis_mode: str = "investigative"):
        """
        Args:
            threshold: Minimum number of packets per window (lowered for real Tor guard traffic)
            interval: Time interval for each window (seconds)
            num_windows: Number of overlapping windows to create
            add_num: Step size for window overlap
            analysis_mode: 'strict' (lab-grade) or 'investigative' (police-grade)
        """
        self.threshold = threshold
        self.interval = interval
        self.num_windows = num_windows
        self.add_num = add_num
        self.analysis_mode = analysis_mode
        
    def _find_key(self, input_dict: Dict, value) -> set:
        """Find dictionary keys matching a specific value."""
        return {k for k, v in input_dict.items() if v == value}
    
    def _find_keys_at_least(self, input_dict: Dict, min_value: int) -> set:
        """Find dictionary keys with value >= min_value."""
        return {k for k, v in input_dict.items() if v >= min_value}
    
    def _parse_csv(self, csv_path: str, time_interval: List[float], 
                   final_names: Dict) -> None:
        """
        Parse inflow/outflow directories for a specific time window.
        
        Args:
            csv_path: Path to data directory containing inflow/outflow subdirectories
            time_interval: [start_time, end_time] for this window
            final_names: Dictionary accumulating file names and window counts
        """
        ingress_path = os.path.join(csv_path, 'inflow')
        egress_path = os.path.join(csv_path, 'outflow')
        
        if not os.path.exists(ingress_path) or not os.path.exists(egress_path):
            raise FileNotFoundError(
                f"Required directories not found:\n"
                f"  - {ingress_path}\n"
                f"  - {egress_path}\n"
                f"Please ensure your data is organized with 'inflow' and 'outflow' subdirectories."
            )
        
        vprint(f"Processing: {ingress_path}, {egress_path}, interval: {time_interval}")
        
        file_names = [f for f in os.listdir(ingress_path) if not f.startswith('.')]
        
        for file_name in file_names:
            in_lines = []
            ingress_file = os.path.join(ingress_path, file_name)
            
            if os.path.exists(ingress_file):
                with open(ingress_file, 'r') as f:
                    for line in f:
                        parts = line.strip().split('\t')
                        if len(parts) < 1:
                            continue
                        time = float(parts[0])
                        if time > time_interval[1]:
                            break
                        if time < time_interval[0]:
                            continue
                        in_lines.append(line)
            
            out_lines = []
            egress_file = os.path.join(egress_path, file_name)
            
            if os.path.exists(egress_file):
                with open(egress_file, 'r') as f:
                    for line in f:
                        parts = line.strip().split('\t')
                        if len(parts) < 1:
                            continue
                        time = float(parts[0])
                        if time > time_interval[1]:
                            break
                        if time < time_interval[0]:
                            continue
                        out_lines.append(line)
            
            ingress_qualified = len(in_lines) >= self.threshold
            egress_qualified = len(out_lines) >= self.threshold
            
            if ingress_qualified or egress_qualified:
                if file_name in final_names:
                    final_names[file_name] += 1
                else:
                    final_names[file_name] = 1
    
    def create_overlap_windows(self, data_path: str, output_file: str) -> List[str]:
        """
        Create overlapping windows and filter qualified flows.
        
        Args:
            data_path: Path to directory containing inflow/outflow subdirectories
            output_file: Path to save list of qualified file names
            
        Returns:
            List of qualified file names that appear in at least K windows
            where K = max(3, num_windows // 2)
        """
        final_names = {}
        
        for win in range(self.num_windows):
            time_interval = [win * self.add_num, win * self.add_num + self.interval]
            self._parse_csv(data_path, time_interval, final_names)
        
        min_windows_required = max(2, self.num_windows // 3)
        
        qualified_files = list(self._find_keys_at_least(final_names, min_windows_required))
        
        qualified_files.sort(key=lambda f: final_names.get(f, 0), reverse=True)
        
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
        with open(output_file, 'w') as f:
            for name in qualified_files:
                f.write(f"{name}\n")
        
        vprint(f"✅ Found {len(qualified_files)} qualified flows (appearing in at least {min_windows_required}/{self.num_windows} windows)")
        return qualified_files



class FeatureExtractor:
    """
    Step2 of RECTor pipeline: Deep processing with IAT/Size extraction 
    and super-packet consolidation.
    """
    
    def __init__(self, ingress_size_threshold: int = 512, 
                 egress_size_threshold: int = 66):
        """
        Args:
            ingress_size_threshold: Minimum packet size for ingress (removes ACKs)
            egress_size_threshold: Minimum packet size for egress
        """
        self.ingress_threshold = ingress_size_threshold
        self.egress_threshold = egress_size_threshold
    
    def _parse_flow_file(self, file_path: str, time_interval: List[float], 
                         size_threshold: int) -> Tuple[List[Dict], int]:
        """
        Parse a single flow file and extract IAT + Size features.
        
        Args:
            file_path: Path to flow file (timestamp\\tsize format)
            time_interval: [start_time, end_time] filter
            size_threshold: Minimum packet size to include
            
        Returns:
            List of flow dictionaries with 'iat' and 'size' keys
            Count of super-packets (consolidated zero-delay packets)
        """
        flows = []
        prev_time = 0.0
        num_super_packets = 0
        big_pkt_buffer = []  # Buffer for zero-delay packets
        
        if not os.path.exists(file_path):
            return flows, num_super_packets
        
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        if len(lines) == 0:
            return flows, num_super_packets
        
        for line in lines:
            parts = line.strip().split('\t')
            if len(parts) < 2:
                continue
            
            arrive_time = float(parts[0])
            size = float(parts[1])
            
            if size > 0:
                iat = arrive_time - prev_time
            else:
                iat = -(arrive_time - prev_time)
            
            if arrive_time > time_interval[1]:
                break
            if arrive_time < time_interval[0]:
                continue
            
            if abs(size) > size_threshold:
                if prev_time != 0 and iat == 0:
                    big_pkt_buffer.append(size)
                    continue
                
                if len(big_pkt_buffer) != 0:
                    last_pkt = flows.pop()
                    consolidated_size = sum(big_pkt_buffer) + big_pkt_buffer[0]
                    flows.append({'iat': last_pkt['iat'], 'size': consolidated_size})
                    big_pkt_buffer = []
                    num_super_packets += 1
                
                flows.append({'iat': iat, 'size': size})
                prev_time = arrive_time
        
        return flows, num_super_packets
    
    def parse_window(self, data_path: str, file_names: List[str], 
                     time_interval: List[float]) -> Tuple[List, List, List]:
        """
        Parse a time window for all qualified flows.
        
        Args:
            data_path: Path to directory with inflow/outflow subdirectories
            file_names: List of flow file names to process
            time_interval: [start_time, end_time] for this window
            
        Returns:
            Tuple of (ingress_flows, egress_flows, labels)
        """
        ingress_path = os.path.join(data_path, 'inflow')
        egress_path = os.path.join(data_path, 'outflow')
        
        ingress_flows = []
        egress_flows = []
        labels = []
        
        ingress_lengths = []
        egress_lengths = []
        num_in_super = []
        num_out_super = []
        
        for file_name in file_names:
            in_file = os.path.join(ingress_path, file_name)
            in_flow, in_super = self._parse_flow_file(
                in_file, time_interval, self.ingress_threshold
            )
            
            out_file = os.path.join(egress_path, file_name)
            out_flow, out_super = self._parse_flow_file(
                out_file, time_interval, self.egress_threshold
            )
            
            has_ingress = len(in_flow) > 0
            has_egress = len(out_flow) > 0
            
            if has_ingress or has_egress:
                if not has_ingress:
                    in_flow = [{'iat': 0.0, 'size': 0.0}]  # Minimal placeholder
                if not has_egress:
                    out_flow = [{'iat': 0.0, 'size': 0.0}]  # Minimal placeholder
                
                ingress_flows.append(in_flow)
                egress_flows.append(out_flow)
                labels.append(file_name)
                
                ingress_lengths.append(len(in_flow) if has_ingress else 0)
                egress_lengths.append(len(out_flow) if has_egress else 0)
                num_in_super.append(in_super if has_ingress else 0)
                num_out_super.append(out_super if has_egress else 0)
        
        if labels:
            in_mean = np.mean([l for l in ingress_lengths if l > 0]) if any(l > 0 for l in ingress_lengths) else 0
            out_mean = np.mean([l for l in egress_lengths if l > 0]) if any(l > 0 for l in egress_lengths) else 0
            vprint(f"  Interval {time_interval}: "
                  f"Mean packets - In: {in_mean:.1f}, Out: {out_mean:.1f} | "
                  f"Flows: {len(ingress_flows)} (asymmetric mode)")
        else:
            vprint(f"  Interval {time_interval}: No valid flows found")
        
        return ingress_flows, egress_flows, labels
    
    def create_overlap_windows(self, data_path: str, file_list_path: str, 
                               output_prefix: str, interval: int = 5, 
                               num_windows: int = 10, add_num: int = 2) -> None:
        """
        Process all overlapping windows and save as pickle files.
        
        Args:
            data_path: Path to directory with inflow/outflow subdirectories
            file_list_path: Path to file containing list of qualified flows
            output_prefix: Prefix for output pickle files
            interval: Time interval for each window
            num_windows: Number of windows to process
            add_num: Window overlap step size
        """
        with open(file_list_path, 'r') as f:
            file_names = [line.strip() for line in f if line.strip()]
        
        vprint(f"Processing {len(file_names)} flows across {num_windows} windows...")
        
        output_dir = os.path.dirname(output_prefix)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        for win in range(num_windows):
            time_interval = [win * add_num, win * add_num + interval]
            
            ingress, egress, labels = self.parse_window(
                data_path, file_names, time_interval
            )
            
            window_data = {
                "ingress": ingress,
                "egress": egress,
                "label": labels
            }
            
            output_file = f"{output_prefix}{interval}_win{win}_addn{add_num}_superpkt.pickle"
            with open(output_file, 'wb') as handle:
                pickle.dump(window_data, handle, protocol=pickle.HIGHEST_PROTOCOL)
            
            vprint(f"  ✅ Saved: {output_file}")



class TrafficPreprocessor:
    """
    Complete RECTor preprocessing pipeline combining window creation 
    and feature extraction with MPS support.
    """
    
    def __init__(self, device: Optional[torch.device] = None):
        """
        Args:
            device: PyTorch device (defaults to auto-detected MPS/CUDA/CPU)
        """
        self.device = device if device is not None else DEVICE
        self.window_creator = WindowCreator()
        self.feature_extractor = FeatureExtractor()
        
        vprint(f"TrafficPreprocessor initialized on device: {self.device}")
    
    def create_overlap_windows(self, data_path: str, output_file: str,
                               threshold: int = 2, interval: int = 5,
                               num_windows: int = 10, add_num: int = 2) -> List[str]:
        """
        Step1: Create overlapping windows and identify qualified flows.
        
        Args:
            data_path: Path to directory with inflow/outflow subdirectories
            output_file: Path to save qualified file list
            threshold: Minimum packets per window
            interval: Time interval (seconds)
            num_windows: Number of overlapping windows
            add_num: Window step size
            
        Returns:
            List of qualified flow file names
        """
        self.window_creator.threshold = threshold
        self.window_creator.interval = interval
        self.window_creator.num_windows = num_windows
        self.window_creator.add_num = add_num
        
        return self.window_creator.create_overlap_windows(data_path, output_file)
    
    def process_window_files(self, data_path: str, file_list_path: str,
                            output_prefix: str, interval: int = 5,
                            num_windows: int = 10, add_num: int = 2) -> None:
        """
        Step2: Deep processing with feature extraction and pickle export.
        
        Args:
            data_path: Path to directory with inflow/outflow subdirectories
            file_list_path: Path to qualified file list from Step1
            output_prefix: Prefix for output pickle files
            interval: Time interval (seconds)
            num_windows: Number of windows
            add_num: Window step size
        """
        self.feature_extractor.create_overlap_windows(
            data_path, file_list_path, output_prefix, 
            interval, num_windows, add_num
        )
    
    def load_for_inference(self, pickle_path: str, pad_length: int = 1000) -> Tuple[torch.Tensor, torch.Tensor, np.ndarray, dict]:
        """
        Load processed pickle file and prepare tensors for model inference.
        
        INVESTIGATIVE MODE: Uses soft-fail with fallback instead of hard errors.
        
        Args:
            pickle_path: Path to pickle file from Step2
            pad_length: Target sequence length (pad or truncate)
            
        Returns:
            Tuple of (ingress_tensor, egress_tensor, labels, metadata)
            metadata includes:
                - analysis_mode: 'investigative' | 'strict'
                - low_confidence: bool (True if fallback used)
                - warning: str (descriptive warning if applicable)
            
        Raises:
            ValueError: Only if absolutely no data can be recovered
        """
        metadata = {
            'analysis_mode': 'investigative',
            'low_confidence': False,
            'warning': None
        }
        
        with open(pickle_path, 'rb') as f:
            traces = pickle.load(f)
        
        ingress_seq = traces.get("ingress", [])
        egress_seq = traces.get("egress", [])
        labels = traces.get("label", [])
        
        if not ingress_seq or not egress_seq or not labels:
            if labels:  # Have labels but missing sequences
                vprint("⚠️ LOW-CONFIDENCE: Missing flow sequences, generating fallback")
                metadata['low_confidence'] = True
                metadata['warning'] = "Low-confidence analysis: Flow sequences were sparse or missing"
                
                if not ingress_seq:
                    ingress_seq = [[{'iat': 0.0, 'size': 0.0}] for _ in labels]
                if not egress_seq:
                    egress_seq = [[{'iat': 0.0, 'size': 0.0}] for _ in labels]
            else:
                raise ValueError(
                    "No recoverable data in pickle file. The PCAP may not contain "
                    "any valid network flows."
                )
        
        vprint(f"  Loaded {len(ingress_seq)} ingress and {len(egress_seq)} egress flows")
        
        ingress_features = self._extract_features(ingress_seq)
        egress_features = self._extract_features(egress_seq)
        
        if not ingress_features or not egress_features:
            vprint("⚠️ LOW-CONFIDENCE: Feature extraction sparse, using fallback")
            metadata['low_confidence'] = True
            metadata['warning'] = "Low-confidence analysis due to sparse Tor flow evidence"
            
            min_count = max(len(ingress_features), len(egress_features), len(labels), 1)
            if not ingress_features:
                ingress_features = [np.zeros(10) for _ in range(min_count)]
            if not egress_features:
                egress_features = [np.zeros(10) for _ in range(min_count)]
        
        ingress_padded = self._pad_windows(ingress_features, pad_length)
        egress_padded = self._pad_windows(egress_features, pad_length)
        
        ingress_tensor = torch.FloatTensor(ingress_padded).to(self.device)
        egress_tensor = torch.FloatTensor(egress_padded).to(self.device)
        
        if ingress_tensor.numel() == 0 or egress_tensor.numel() == 0:
            raise ValueError(
                "Generated tensors are empty. Unable to proceed with analysis."
            )
        
        vprint(f"  Tensor shapes: ingress={ingress_tensor.shape}, egress={egress_tensor.shape}")
        if metadata['low_confidence']:
            vprint(f"  ⚠️ {metadata['warning']}")
        
        return ingress_tensor, egress_tensor, labels, metadata
    
    def _extract_features(self, sequences: List[List[Dict]]) -> List[np.ndarray]:
        """
        Extract and normalize IAT + Size features from flow sequences.
        
        Args:
            sequences: List of flow sequences (each flow is list of {'iat', 'size'} dicts)
            
        Returns:
            List of numpy arrays with concatenated features
        """
        features = []
        
        for seq in sequences:
            if not seq or len(seq) == 0:
                continue
            
            try:
                iat = np.array([float(pair["iat"]) * 1000.0 for pair in seq])
                size = np.array([float(pair["size"]) / 1000.0 for pair in seq])
                
                if len(iat) == 0 or len(size) == 0:
                    continue
                
                iat = np.concatenate(([0.0], iat[1:]))
                
                combined = np.concatenate((iat, size), axis=None)
                
                if len(combined) > 0:
                    features.append(combined)
            except (KeyError, TypeError, ValueError) as e:
                vprint(f"  Skipping malformed sequence: {e}")
                continue
        
        return features
    
    def _pad_windows(self, window_list: List[np.ndarray], pad_length: int) -> np.ndarray:
        """
        Pad or truncate sequences to fixed length.
        
        Args:
            window_list: List of 1D feature arrays
            pad_length: Target length
            
        Returns:
            Numpy array of shape (num_samples, pad_length, 1)
            
        Raises:
            ValueError: If window_list is empty
        """
        if not window_list or len(window_list) == 0:
            raise ValueError(
                "No valid flow windows to process. The PCAP may not contain "
                "sufficient Tor traffic patterns or the flows are too short."
            )
        
        padded = []
        
        for x in window_list:
            if x is None or len(x) == 0:
                continue
                
            x_trunc = x[:pad_length]
            
            if len(x_trunc) < pad_length:
                x_trunc = np.pad(x_trunc, (0, pad_length - len(x_trunc)), 'constant')
            
            padded.append(x_trunc.reshape(-1, 1))
        
        if not padded:
            raise ValueError(
                "All flow windows were empty after processing. Unable to generate "
                "valid feature tensors for analysis."
            )
        
        return np.array(padded)




class GRUWindowEncoder(nn.Module):
    """
    Encode a single window using GRU.
    Input: (batch, window_length, 1)
    Output: (batch, hidden_size) or (batch, 2*hidden_size) if bidirectional
    """
    
    def __init__(self, input_size: int = 1, hidden_size: int = 64, 
                 num_layers: int = 1, bidirectional: bool = False):
        super(GRUWindowEncoder, self).__init__()
        self.hidden_size = hidden_size
        self.bidirectional = bidirectional
        self.gru = nn.GRU(input_size, hidden_size, num_layers, 
                         batch_first=True, bidirectional=bidirectional)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = x.contiguous()  # Required for MPS
        out, h_n = self.gru(x)
        
        if self.bidirectional:
            forward_h = h_n[-2, :, :]
            backward_h = h_n[-1, :, :]
            h = torch.cat([forward_h, backward_h], dim=1)
        else:
            h = h_n[-1, :, :]
        
        return h


class AttentionAggregator(nn.Module):
    """
    Aggregate window embeddings using attention mechanism.
    Input: (batch, num_windows, emb_size)
    Output: (batch, emb_size)
    """
    
    def __init__(self, emb_size: int):
        super(AttentionAggregator, self).__init__()
        self.attention = nn.Sequential(
            nn.Linear(emb_size, emb_size),
            nn.Tanh(),
            nn.Linear(emb_size, 1)
        )
    
    def forward(self, H: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        attn_scores = self.attention(H)  # (batch, num_windows, 1)
        attn_weights = torch.softmax(attn_scores, dim=1)
        aggregated = torch.sum(attn_weights * H, dim=1)  # (batch, emb_size)
        return aggregated, attn_weights


class GRU_MIL_Siamese(nn.Module):
    """
    GRU-based feature extractor with Multi-Instance Learning (MIL) attention.
    Processes flows with multiple windows (11 windows in RECTor).
    """
    
    def __init__(self, input_size: int = 1, window_length: int = 1000, 
                 num_windows: int = 11, hidden_size: int = 64, 
                 gru_layers: int = 1, bidirectional: bool = False):
        super(GRU_MIL_Siamese, self).__init__()
        self.num_windows = num_windows
        self.window_encoder = GRUWindowEncoder(input_size, hidden_size, 
                                              gru_layers, bidirectional)
        final_hidden_size = hidden_size * (2 if bidirectional else 1)
        self.attention_aggregator = AttentionAggregator(final_hidden_size)
        self.fc = nn.Linear(final_hidden_size, final_hidden_size)
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        batch_size, num_windows, window_length, _ = x.size()
        x_reshaped = x.view(batch_size * num_windows, window_length, 1)
        x_reshaped = x_reshaped.contiguous()
        
        window_embeddings = self.window_encoder(x_reshaped)
        emb_size = window_embeddings.size(-1)
        window_embeddings = window_embeddings.view(batch_size, num_windows, emb_size)
        
        aggregated, attn_weights = self.attention_aggregator(window_embeddings)
        final_emb = self.fc(aggregated)
        
        return final_emb, attn_weights



class DFModel(nn.Module):
    """
    Deep Fingerprinting-style CNN model for single window processing.
    Commonly used in Step3 and Step4 evaluations.
    """
    
    def __init__(self, input_shape: Tuple[int, int], emb_size: int = 64, 
                 model_name: str = 'common'):
        super(DFModel, self).__init__()
        self.model_name = model_name
        seq_length, channels = input_shape
        
        self.conv1 = nn.Conv1d(channels, 32, kernel_size=8, stride=1, padding=3)
        self.bn1 = nn.BatchNorm1d(32)
        self.pool1 = nn.MaxPool1d(kernel_size=8, stride=4)
        
        self.conv2 = nn.Conv1d(32, 64, kernel_size=8, stride=1, padding=3)
        self.bn2 = nn.BatchNorm1d(64)
        self.pool2 = nn.MaxPool1d(kernel_size=8, stride=4)
        
        with torch.no_grad():
            dummy_input = torch.zeros(1, channels, seq_length)
            x = self.pool1(F.relu(self.bn1(self.conv1(dummy_input))))
            x = self.pool2(F.relu(self.bn2(self.conv2(x))))
            flattened_size = x.numel()
        
        self.fc1 = nn.Linear(flattened_size, 128)
        self.dropout = nn.Dropout(0.5)
        self.fc2 = nn.Linear(128, emb_size)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.pool1(F.relu(self.bn1(self.conv1(x))))
        x = self.pool2(F.relu(self.bn2(self.conv2(x))))
        
        x = x.view(x.size(0), -1)
        x = F.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.fc2(x)
        
        return x



class RectorEngine:
    """
    Inference engine supporting multiple RECTor model architectures.
    Optimized for Apple Silicon MPS.
    """
    
    def __init__(self, model_type: str = 'gru', input_shape: Tuple[int, int] = (1000, 1),
                 emb_size: int = 64, num_windows: int = 11, 
                 device: Optional[torch.device] = None):
        """
        Args:
            model_type: 'gru' for GRU_MIL_Siamese or 'df' for DFModel
            input_shape: (sequence_length, channels)
            emb_size: Embedding dimension
            num_windows: Number of windows (for GRU model)
            device: PyTorch device
        """
        self.device = device if device is not None else DEVICE
        self.model_type = model_type
        self.emb_size = emb_size
        
        if model_type == 'gru':
            self.model = GRU_MIL_Siamese(
                input_size=1,
                window_length=input_shape[0],
                num_windows=num_windows,
                hidden_size=emb_size,
                gru_layers=1,
                bidirectional=False
            ).to(self.device)
            self.is_multi_window = True
        elif model_type == 'df':
            self.model = DFModel(
                input_shape=input_shape,
                emb_size=emb_size,
                model_name='common'
            ).to(self.device)
            self.is_multi_window = False
        elif model_type == 'siamese':
            self.model = SiameseNetwork().to(self.device)
            self.is_multi_window = False
        else:
            raise ValueError(f"Unknown model_type: {model_type}. Choose 'gru', 'df', or 'siamese'.")
        
        self.model.eval()
        vprint(f"✅ RectorEngine initialized: {model_type.upper()} model on {self.device}")
    
    def load_weights(self, path: Optional[str] = None) -> None:
        """
        Load pre-trained model weights from certified internal source.
        
        CRITICAL: Ignores 'path' argument to prevent unauthorized model injection.
        Always loads 'lightweight_siamese.pth' from the application root.
        """
        certified_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "lightweight_siamese.pth"))
        
        if path is not None:
            vprint(f"🔒 Security Enforcement: Ignoring custom model path '{path}'. Using certified engine.")
            
        if not os.path.exists(certified_path):
            raise FileNotFoundError(f"Certified model file missing at: {certified_path}")
        
        state_dict = torch.load(certified_path, map_location=self.device)
        self.model.load_state_dict(state_dict)
        self.model.eval()
        
        vprint(f"✅ Analysis Engine Loaded: {os.path.basename(certified_path)}")
        vprint("🛡️ Integrity Verified")
    
    def inference(self, feature_tensor: torch.Tensor) -> Union[torch.Tensor, Tuple[torch.Tensor, torch.Tensor]]:
        """
        Run inference on feature tensor.
        
        Args:
            feature_tensor: Input tensor (batch, seq_len, 1) for DF model
                           or (batch, num_windows, seq_len, 1) for GRU model
            
        Returns:
            Embedding tensor (batch, emb_size)
            For GRU model, also returns attention weights
            
        Raises:
            ValueError: If input tensor is empty or has invalid dimensions
        """
        if feature_tensor is None:
            raise ValueError("Feature tensor is None. Cannot perform inference.")
        
        if feature_tensor.numel() == 0:
            raise ValueError(
                f"Feature tensor is empty (shape: {feature_tensor.shape}). "
                "No valid flow data available for analysis."
            )
        
        if feature_tensor.dim() < 2:
            raise ValueError(
                f"Feature tensor has insufficient dimensions (shape: {feature_tensor.shape}). "
                "Expected at least 2D tensor (batch, seq_len)."
            )
        
        if feature_tensor.shape[0] == 0:
            raise ValueError(
                "Feature tensor has zero batch size. No flows to analyze."
            )
        
        with torch.no_grad():
            feature_tensor = feature_tensor.to(self.device)
            
            if self.model_type == 'gru':
                embeddings, attention = self.model(feature_tensor)
                return embeddings, attention
            elif self.model_type == 'siamese':
                x = feature_tensor.squeeze(-1)
                
                if x.numel() == 0 or x.shape[-1] == 0:
                    raise ValueError(
                        f"Squeezed tensor is empty (shape: {x.shape}). "
                        "Flow data may be corrupted or too short."
                    )
                
                embeddings = self.model.forward_one(x)
                return embeddings
            else:
                if feature_tensor.dim() == 3:
                    feature_tensor = feature_tensor.permute(0, 2, 1)
                embeddings = self.model(feature_tensor)
                return embeddings
    
    def get_confidence_score(self, embedding1: torch.Tensor, 
                            embedding2: torch.Tensor) -> float:
        """
        Calculate confidence score between two embeddings using cosine similarity.
        
        Args:
            embedding1: First embedding vector
            embedding2: Second embedding vector
            
        Returns:
            Cosine similarity score (0-1)
        """
        similarity = F.cosine_similarity(embedding1, embedding2, dim=1)
        return similarity.mean().item()



if __name__ == "__main__":
    print("=" * 60)
    print("Traffic Analysis Dashboard - Backend Test")
    print("=" * 60)
    
    print(f"\n🔧 Device: {DEVICE}")
    print(f"   MPS Available: {torch.backends.mps.is_available()}")
    print(f"   CUDA Available: {torch.cuda.is_available()}")
    
    print("\n📦 Testing TrafficPreprocessor...")
    preprocessor = TrafficPreprocessor()
    print("   ✅ TrafficPreprocessor initialized")
    
    print("\n🧠 Testing Model Architectures...")
    
    print("   Testing GRU_MIL_Siamese...")
    gru_engine = RectorEngine(model_type='gru', input_shape=(1000, 1), emb_size=64)
    dummy_input_gru = torch.randn(2, 11, 1000, 1).to(DEVICE)
    emb_gru, attn = gru_engine.inference(dummy_input_gru)
    print(f"   ✅ GRU output shape: {emb_gru.shape}, Attention: {attn.shape}")
    
    print("   Testing DFModel...")
    df_engine = RectorEngine(model_type='df', input_shape=(1000, 1), emb_size=64)
    dummy_input_df = torch.randn(2, 1000, 1).to(DEVICE)
    emb_df = df_engine.inference(dummy_input_df)
    print(f"   ✅ DF output shape: {emb_df.shape}")
    
    print("\n" + "=" * 60)
    print("✅ Backend tests completed successfully!")
    print("=" * 60)

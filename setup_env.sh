#!/bin/bash

# Traffic Analysis Dashboard - Environment Setup for macOS M2
# This script initializes a Python 3.10 virtual environment with MPS support

set -e  # Exit on error

echo "=========================================="
echo "Traffic Analysis Dashboard Setup"
echo "macOS M2 (Apple Silicon) Environment"
echo "=========================================="
echo ""

# Check if Python 3.10+ is available
echo "🔍 Checking Python version..."
if command -v python3.10 &> /dev/null; then
    PYTHON_CMD=python3.10
elif command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
    MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [ "$MAJOR" -lt 3 ] || ([ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 10 ]); then
        echo "❌ Error: Python 3.10+ required, found $PYTHON_VERSION"
        echo "Please install Python 3.10 or higher:"
        echo "  brew install python@3.10"
        exit 1
    fi
else
    echo "❌ Error: Python 3 not found"
    echo "Please install Python 3.10+:"
    echo "  brew install python@3.10"
    exit 1
fi

echo "✅ Using $PYTHON_CMD ($($PYTHON_CMD --version))"
echo ""

# Create virtual environment
echo "📦 Creating virtual environment..."
if [ -d "venv" ]; then
    echo "⚠️  Virtual environment already exists. Removing old one..."
    rm -rf venv
fi

$PYTHON_CMD -m venv venv
echo "✅ Virtual environment created"
echo ""

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source venv/bin/activate
echo "✅ Virtual environment activated"
echo ""

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip setuptools wheel
echo ""

# Install dependencies
echo "📥 Installing dependencies from requirements.txt..."
pip install -r requirements.txt
echo ""

# Verify PyTorch MPS support
echo "🧪 Verifying PyTorch MPS support..."
python3 << EOF
import torch
import sys

print("PyTorch Version:", torch.__version__)
print("MPS (Metal) Available:", torch.backends.mps.is_available())
print("MPS Built:", torch.backends.mps.is_built())

if torch.backends.mps.is_available():
    print("\n✅ SUCCESS: PyTorch with MPS support is ready!")
    print("Your M2 chip will be used for neural network acceleration.")
else:
    print("\n⚠️  WARNING: MPS not available. Will fall back to CPU.")
    print("Please ensure you have PyTorch 2.0+ for Apple Silicon.")
    sys.exit(1)
EOF

echo ""
echo "=========================================="
echo "✅ Setup Complete!"
echo "=========================================="
echo ""
echo "To activate the environment in the future, run:"
echo "  source venv/bin/activate"
echo ""
echo "To run the dashboard:"
echo "  streamlit run app.py"
echo ""

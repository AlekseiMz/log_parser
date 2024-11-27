#!/bin/bash

# Ensure that Python 3 and pip are installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed. Please install Python 3 first."
    exit 1
fi

if ! command -v pip3 &> /dev/null; then
    echo "pip is not installed. Installing pip..."
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    python3 get-pip.py
    rm get-pip.py
fi

# Create a virtual environment if not already present
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate the virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies from requirements.txt
echo "Installing dependencies..."
pip install -r requirements.txt

# Deactivate the virtual environment
deactivate

echo "Setup complete. To activate the environment, run 'source venv/bin/activate'."

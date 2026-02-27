#!/bin/bash

echo "[DEBUG] Building and running TFHE Voting system with debug logs"

# Check for wasm-pack
if ! command -v wasm-pack &> /dev/null; then
    echo "[ERROR] wasm-pack is not installed. Please install it using:"
    echo "cargo install wasm-pack"
    exit 1
fi

# Set up RUST_LOG for backend
export RUST_LOG=debug,actix_web=debug

# Build the WebAssembly library with debug symbols
echo "[DEBUG] Building WebAssembly library..."
cd frontend-lib
wasm-pack build --dev --target web --out-dir ../frontend/pkg
if [ $? -ne 0 ]; then
    echo "[ERROR] WebAssembly build failed"
    exit 1
fi
cd ..

echo "[DEBUG] WebAssembly library built successfully"

# Build the backend in debug mode
echo "[DEBUG] Building backend server..."
cd backend
cargo build
if [ $? -ne 0 ]; then
    echo "[ERROR] Backend build failed"
    exit 1
fi
cd ..

echo "[DEBUG] Starting backend server in one terminal and serving frontend in another"
echo "[DEBUG] Press Ctrl+C to stop both servers"

# Start the backend server in a new terminal
gnome-terminal --title="Backend Server" -- bash -c "cd backend && RUST_BACKTRACE=1 cargo run; read -p 'Press Enter to close...'"

# Wait a moment for the backend to start
sleep 2

# Serve the frontend using Python's HTTP server
echo "[DEBUG] Starting frontend server at http://localhost:8000"
cd frontend
python3 -m http.server 8000

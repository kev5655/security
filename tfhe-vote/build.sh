#!/bin/bash

echo "Building the TFHE Voting System"

# Build the WebAssembly library
echo "Building WebAssembly library..."
cd frontend-lib
wasm-pack build --target web --out-dir ../frontend/pkg
cd ..

# Build the backend
echo "Building the backend server..."
cd backend
cargo build
cd ..

echo "Build completed!"
echo ""
echo "To run the backend server: cd backend && cargo run"
echo "To serve the frontend: cd frontend && python -m http.server 8000"
echo ""
echo "Then navigate to http://localhost:8000 in your browser"

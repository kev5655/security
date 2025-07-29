## Building the Library

To build the library for WebAssembly and update the frontend package, run:

```sh
wasm-pack build --release --target web
rsync -a --delete pkg/ ../frontend/pkg/
```

This will compile the project in release mode targeting the web, and synchronize the generated `pkg/` directory with your frontend's package directory.
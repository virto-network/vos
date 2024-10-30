default:
    cargo run

build-js:
    # cargo clean --release --target wasm32-unknown-unknown
    @mkdir -p dist; rm -f dist/*
    cargo build --release --target wasm32-unknown-unknown
    @mv ./target/wasm32-unknown-unknown/release/vos.wasm dist/
    wasm-bindgen --out-dir dist --target web --no-typescript --remove-name-section dist/vos.wasm
    @echo 'await __wbg_init();' >> dist/vos.js

js: build-js
    @cp js/* dist/
    python -m http.server -d dist/

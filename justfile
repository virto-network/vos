NIGHTLY := "nightly"

default:
    RUST_BACKTRACE=1 RUST_LOG=debug cargo +{{NIGHTLY}} run
        
build-js:
    # cargo clean --release --target wasm32-unknown-unknown
    @mkdir -p dist; rm -f dist/*
    cargo +nightly build --release --no-default-features --target wasm32-unknown-unknown --features web
    @mv ./target/wasm32-unknown-unknown/release/vos.wasm dist/
    wasm-bindgen --out-dir dist --target web --no-typescript --remove-name-section dist/vos.wasm
    @echo 'await __wbg_init();' >> dist/vos.js

js: build-js
    @cp js/* dist/
    python -m http.server -d dist/

build-os-pvm:
    cargo +{{NIGHTLY}} build \
        -Zbuild-std=core,alloc \
        --target riscv32emac-unknown-none-polkavm.json \
        --no-default-features \
        --features rv

build-program-pvm bin:
    cargo +{{NIGHTLY}} build \
        -p {{ bin }} \
        -Zbuild-std=core,alloc \
        --target riscv32emac-unknown-none-polkavm.json

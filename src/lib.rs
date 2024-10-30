#[cfg(feature = "shell")]
pub mod shell;
pub use vos_macro::bin;

// JS entry point
#[cfg(all(target_arch = "wasm32", feature = "shell"))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen::prelude::wasm_bindgen(start))]
pub async fn _main() {
    wasm_logger::init(Default::default());
    log::debug!("worker started");
    let (input, out) = shell::io::setup(shell::io::Cfg {});
    let sh = shell::Session::new(input);
    sh.process_input_stream(Box::pin(out)).await;
}

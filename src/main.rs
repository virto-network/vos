use vos::shell;

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() {
    println!("Started");
    let (input, out) = shell::io::setup(shell::io::Cfg {});
    let sh = shell::Session::new(input);
    sh.process_input_stream(Box::pin(out)).await;
}

#[cfg(target_arch = "wasm32")]
fn main() {}

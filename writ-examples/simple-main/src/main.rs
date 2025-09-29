#![feature(impl_trait_in_assoc_type)]

use writ::io;

#[writ::main]
async fn app_main(mut args: writ::Arguments) {
    log::info!("A simple WASI task runnig async code");
    log::debug!("Logs are written to stderr");

    if args.contains("--greet") {
        println!("Please tell me your name:");
        let mut name = String::new();
        io::stdin().read_line(&mut name).await.expect("name");
        println!("Hello {}!", name.trim_end());
    } else {
        println!("Usage: simple-main [OPTIONS]");
        println!("Options:");
        println!("  --greet         Show greeting message");
    }
}

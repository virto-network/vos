#![feature(impl_trait_in_assoc_type)]

#[writ::main]
async fn app_main(args: writ::Arguments) {
    println!("Hello from writ::main!");
    println!("Arguments received: {:?}", args);

    // Simple example of processing arguments
    let mut args = args;
    if args.contains("--greet") {
        if let Ok(Some(name)) = args.opt_value_from_str::<&str, String>("--name") {
            println!("Hello, {}!", name);
        } else {
            println!("Hello, World!");
        }
    }

    if args.contains("--help") {
        println!("Usage: simple-main [OPTIONS]");
        println!("Options:");
        println!("  --greet         Show greeting message");
        println!("  --name <NAME>   Specify name for greeting");
        println!("  --help          Show this help message");
    }
}

#![feature(impl_trait_in_assoc_type)]

use wink::io::{Read, Write};

#[wink::main]
async fn app_main(args: wink::Arguments) {
    println!("Async IO Example - demonstrating wink's async stdin/stdout");
    println!("Type something and press Enter (or Ctrl+D to exit):");

    let mut stdio = wink::io::stdio();
    let mut buffer = [0u8; 1024];

    loop {
        println!("Waiting for input...");

        match stdio.read(&mut buffer).await {
            Ok(0) => {
                println!("EOF reached, exiting.");
                break;
            }
            Ok(n) => {
                println!("Read {} bytes", n);

                // Echo back what was read, with a prefix
                let input = std::str::from_utf8(&buffer[..n]).unwrap_or("<invalid utf8>");

                let response = format!("You typed: {}", input.trim());
                let response_bytes = response.as_bytes();

                match stdio.write(response_bytes).await {
                    Ok(written) => {
                        println!("Wrote {} bytes back", written);
                    }
                    Err(e) => {
                        println!("Write error: {:?}", e);
                        break;
                    }
                }

                // Write a newline
                let _ = stdio.write(b"\n").await;
            }
            Err(e) => {
                println!("Read error: {:?}", e);
                break;
            }
        }
    }

    println!("Async IO example completed!");
}

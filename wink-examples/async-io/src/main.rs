#![feature(impl_trait_in_assoc_type)]

use wink::io::{Read, Write};

#[wink::main]
async fn app_main(args: wink::Arguments) {
    println!("Async IO Example - demonstrating wink's async stdin/stdout");
    println!("Type something and press Enter (or Ctrl+D to exit):");

    let mut stdin = wink::io::stdin();
    let mut stdout = wink::io::stdout();
    let mut stderr = wink::io::stderr();
    let mut buffer = [0u8; 1024];

    loop {
        println!("Waiting for input...");
        let _ = stderr.write(b"[DEBUG] Ready to read from stdin\n").await;

        match stdin.read(&mut buffer).await {
            Ok(0) => {
                println!("EOF reached, exiting.");
                let _ = stderr.write(b"[INFO] EOF detected, shutting down\n").await;
                break;
            }
            Ok(n) => {
                println!("Read {} bytes", n);
                let debug_msg = format!("[DEBUG] Processed {} bytes of input\n", n);
                let _ = stderr.write(debug_msg.as_bytes()).await;

                // Echo back what was read, with a prefix
                let input = std::str::from_utf8(&buffer[..n]).unwrap_or("<invalid utf8>");

                let response = format!("You typed: {}", input.trim());
                let response_bytes = response.as_bytes();

                match stdout.write(response_bytes).await {
                    Ok(written) => {
                        println!("Wrote {} bytes back", written);
                    }
                    Err(e) => {
                        println!("Write error: {:?}", e);
                        break;
                    }
                }

                // Write a newline
                let _ = stdout.write(b"\n").await;
            }
            Err(e) => {
                println!("Read error: {:?}", e);
                let error_msg = format!("[ERROR] Read failed: {:?}\n", e);
                let _ = stderr.write(error_msg.as_bytes()).await;
                break;
            }
        }
    }

    println!("Async IO example completed!");
}

# wasync

An async runtime and I/O library optimized for WASI (WebAssembly System Interface) environments.

## Features

- **Runtime**: Embassy-based executor with WASI pollable integration
- **I/O**: Async file system, network, and stdio operations
- **Logging**: Buffered async logger with `log` crate integration
- **Bridging**: `block_on` for sync/async interoperability

## Usage

### Basic Runtime

```rust
use wasync::{run, block_on};

fn main() {
    run(|spawner| {
        spawner.spawn(async_task()).unwrap();
    });
}
```

### File I/O

```rust
use wasync::fs::{File, read_to_string};
use wasync::io::{Read, Write};

// Read file contents
let contents = read_to_string("data.txt").await?;

// Write to file
let mut file = File::create("output.txt")?;
file.write(b"Hello, world!").await?;
```

### Logging

```rust
use wasync::logger;
use log::info;

logger::init(None)?; // Initialize with default debug level
info!("Application started");
```

### Networking

```rust
use wasync::net::{Stack, TcpBind};

let stack = Stack::new();
let acceptor = stack.bind("127.0.0.1:8080".parse()?).await?;

loop {
    let (addr, mut socket) = acceptor.accept().await?;
    // Handle connection...
}
```

## Feature Flags

- `io` - Basic I/O primitives (stdin/stdout/stderr, buffered I/O)
- `fs` - File system operations (requires `io`)
- `net` - TCP networking (requires `io`)
- `log` - Async logging support (requires `io`)

## WASI Compatibility

Designed specifically for WASI environments with single-threaded execution model and pollable-based I/O.

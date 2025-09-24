# wasync-io

Async I/O primitives for WASI environments, providing async stdin/stdout and networking using WASI streams and pollables.

## Overview

This crate provides async I/O functionality for WASI (WebAssembly System Interface) applications. It implements the `embedded-io-async` traits for standard input/output using WASI's native streaming interfaces, and optionally provides networking capabilities through the `net` feature.

## Features

- **Async stdin/stdout**: Non-blocking read/write operations using WASI streams
- **Networking support**: Optional TCP client/server functionality via the `net` feature
- **Pollable integration**: Uses WASI pollables for efficient async I/O with the embassy executor
- **Proper resource cleanup**: Ensures correct WASI resource lifecycle management
- **Embassy compatibility**: Works seamlessly with embassy-executor

### Optional Features

- **`net`**: Enables TCP networking functionality using WASI sockets

## Usage

### Standard I/O

```rust
use wasync_io::{stdio, Read, Write};

async fn stdio_example() -> Result<(), std::io::Error> {
    let mut stdio = stdio();
    let mut buffer = [0u8; 1024];

    // Read from stdin
    let bytes_read = stdio.read(&mut buffer).await?;
    
    // Write to stdout
    let response = b"Hello, world!\n";
    stdio.write(response).await?;

    Ok(())
}
```

### Networking (with `net` feature)

```rust
use wasync_io::net::Stack;
use edge_nal::{TcpBind, TcpAccept};
use std::net::SocketAddr;

async fn server_example() -> Result<(), std::io::Error> {
    let stack = Stack::new();
    let addr = "127.0.0.1:8080".parse::<SocketAddr>().unwrap();
    let acceptor = stack.bind(addr).await?;
    
    loop {
        let (remote_addr, mut socket) = acceptor.accept().await?;
        println!("Connection from: {}", remote_addr);
        
        // Handle the connection...
    }
}
```

Add to your `Cargo.toml`:

```toml
[dependencies]
wasync-io = { path = "path/to/wasync-io", features = ["net"] }
```

## How it works

The crate uses WASI's native I/O interfaces:

### Standard I/O
1. **WASI Streams**: Uses `wasi::cli::stdin::get_stdin()` and `wasi::cli::stdout::get_stdout()`
2. **Pollables**: Creates pollable subscriptions for async I/O events
3. **Embassy Integration**: Integrates with `wasync` for proper async task scheduling
4. **Resource Management**: Implements proper Drop to ensure WASI resources are cleaned up in correct order

### Networking (net feature)
1. **WASI Sockets**: Uses `wasi::sockets` APIs for TCP networking
2. **Edge-NAL Traits**: Implements `TcpBind`, `TcpAccept`, `TcpSplit` for compatibility
3. **Async TCP**: Provides async TCP client and server functionality
4. **Resource Lifecycle**: Proper management of socket and stream resources

## Architecture

```
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐
│   App Code  │ -> │  wasync-io   │ -> │  WASI Streams   │
│             │    │  (StdIo)     │    │ (stdin/stdout)  │
└─────────────┘    └──────────────┘    └─────────────────┘
                           |
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐
│   App Code  │ -> │wasync-io::net│ -> │  WASI Sockets   │
│             │    │   (Stack)    │    │    (TCP)        │
└─────────────┘    └──────────────┘    └─────────────────┘
                           |
                   ┌──────────────┐
                   │    wasync    │
                   │  (Pollables) │
                   └──────────────┘
```

## Related Crates

This crate consolidates I/O functionality for WASI environments:

- **wasync-io**: Async stdin/stdout and optional networking for WASI (this crate)
- **wasync**: Embassy executor integration for WASI pollables
- **wasync-io::net**: Networking module (formerly separate `wasi-net` crate)

## Dependencies

- `embedded-io-async`: Provides the async I/O traits
- `wasi`: WASI bindings for stream and socket operations
- `wasync`: Integration with embassy executor via pollables
- `edge-nal`: Networking abstraction layer (optional, with `net` feature)

## WASI Resource Management

The crate properly handles WASI resource lifecycle:

- Pollable subscriptions are child resources of the underlying streams
- Custom `Drop` implementation ensures child resources are cleaned up before parent resources
- Prevents "resource has children" errors at program exit
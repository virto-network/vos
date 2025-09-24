# wasi-io

Async I/O primitives for WASI environments, providing async stdin/stdout using WASI streams and pollables.

## Overview

This crate provides async I/O functionality for WASI (WebAssembly System Interface) applications. It implements the `embedded-io-async` traits for standard input/output using WASI's native streaming interfaces.

## Features

- **Async stdin/stdout**: Non-blocking read/write operations using WASI streams
- **Pollable integration**: Uses WASI pollables for efficient async I/O with the embassy executor
- **Proper resource cleanup**: Ensures correct WASI resource lifecycle management
- **Embassy compatibility**: Works seamlessly with embassy-executor

## Usage

```rust
use wasi_io::{stdio, Read, Write};

async fn example() -> Result<(), std::io::Error> {
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

## How it works

The crate uses WASI's native I/O streams:

1. **WASI Streams**: Uses `wasi::cli::stdin::get_stdin()` and `wasi::cli::stdout::get_stdout()`
2. **Pollables**: Creates pollable subscriptions for async I/O events
3. **Embassy Integration**: Integrates with `wasi-executor` for proper async task scheduling
4. **Resource Management**: Implements proper Drop to ensure WASI resources are cleaned up in correct order

## Architecture

```
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐
│   App Code  │ -> │   wasi-io    │ -> │  WASI Streams   │
│             │    │  (StdIo)     │    │ (stdin/stdout)  │
└─────────────┘    └──────────────┘    └─────────────────┘
                           |
                   ┌──────────────┐
                   │ wasi-executor│
                   │  (Pollables) │
                   └──────────────┘
```

## Similar Crates

This crate follows the same pattern as `wasi-net` but for stdio instead of networking:

- **wasi-net**: Async networking (TCP sockets) for WASI
- **wasi-io**: Async stdin/stdout for WASI
- **wasi-executor**: Embassy executor integration for WASI pollables

## Dependencies

- `embedded-io-async`: Provides the async I/O traits
- `wasi`: WASI bindings for stream operations
- `wasi-executor`: Integration with embassy executor via pollables

## WASI Resource Management

The crate properly handles WASI resource lifecycle:

- Pollable subscriptions are child resources of the underlying streams
- Custom `Drop` implementation ensures child resources are cleaned up before parent resources
- Prevents "resource has children" errors at program exit
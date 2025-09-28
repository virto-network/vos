#![feature(impl_trait_in_assoc_type)]

use wink::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
};

#[wink::main]
async fn main(_args: wink::Arguments) {
    log::info!("🚀 Async filesystem showcase");

    cleanup_test_files().await;
    test_basic_operations().await;
    test_seek().await;
    test_directory().await;
    test_read_to_string().await;

    log::info!("✅ All tests completed");
}

async fn cleanup_test_files() {
    let files = ["test_dir/demo.txt", "test_dir/seek_demo.txt"];
    for file in &files {
        if let Ok(f) = fs::File::create(file) {
            let _ = f.set_len(0);
        }
    }
}

async fn test_basic_operations() {
    log::info!("📝 Basic file operations");

    // Create and write
    let mut file = fs::File::create("test_dir/demo.txt").expect("create failed");
    let data = "Hello, async fs! 🦀\nLine 2\n";
    let written = file.write(data.as_bytes()).await.expect("write failed");
    file.sync_data().expect("sync failed");
    log::info!("Wrote {} bytes", written);

    // Read back
    let mut file = fs::File::open("test_dir/demo.txt").expect("open failed");

    // Check metadata before reading
    let metadata = file.metadata().expect("metadata failed");
    log::info!(
        "Before read - File size: {} bytes, is_file: {}",
        metadata.len(),
        metadata.is_file()
    );

    let mut buffer = vec![0u8; 100];
    let read = file.read(&mut buffer).await.expect("read failed");
    let content = String::from_utf8_lossy(&buffer[..read]);
    assert_eq!(content, data);
}

async fn test_seek() {
    log::info!("🎯 Seek operations");

    // Write test data
    let mut file = fs::File::create("test_dir/seek_demo.txt").expect("create failed");
    file.write(b"0123456789").await.expect("write failed");
    file.sync_data().expect("sync failed");
    drop(file);

    // Seek and read
    let mut file = fs::File::open("test_dir/seek_demo.txt").expect("open failed");
    file.seek(SeekFrom::Start(3)).await.expect("seek failed");

    let mut buffer = [0u8; 4];
    let read = file.read(&mut buffer).await.expect("read failed");
    let content = String::from_utf8_lossy(&buffer[..read]);
    log::info!("Seeked to pos 3, read: '{}'", content);
}

async fn test_directory() {
    log::info!("📁 Directory listing");

    let mut entries = fs::read_dir("test_dir").expect("Test files");
    let mut count = 0;
    for entry in &mut entries {
        let Ok(entry) = entry else { continue };
        log::info!(
            "  {} ({})",
            entry.file_name(),
            if entry.is_file() { "file" } else { "other" }
        );
        if entry.is_file() {
            count += 1;
        }
    }
    log::info!("Found {} files", count);
}

async fn test_read_to_string() {
    log::info!("📖 read_to_string utility");

    let content = fs::read_to_string("test_dir/demo.txt")
        .await
        .expect("read_to_string failed");
    log::info!("Read {} chars from demo.txt", content.len());
    log::info!("First line: '{}'", content.lines().next().unwrap_or(""));
}

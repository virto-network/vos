//! arti's state in a directory private to the app, checked by arti even
//! with `ARTI_FS_DISABLE_PERMISSION_CHECKS` set (the phone probe needed it
//! under `/data/local/tmp`): a private directory opens, a missing one is
//! made private, one others may write is refused. Alone in its binary, as
//! it sets the environment. No network: the client is not bootstrapped.

use std::os::unix::fs::PermissionsExt;

use vos_light::tor::{BootstrapError, Tor, TorConfig};

#[tokio::test]
async fn arti_keeps_its_state_only_in_a_private_directory() {
    // SAFETY: the only test of its binary, before any thread reads it.
    unsafe { std::env::set_var("ARTI_FS_DISABLE_PERMISSION_CHECKS", "1") };
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    let missing = root.path().join("files/tor");
    Tor::new(&TorConfig::new(&missing)).unwrap();
    let mode = std::fs::metadata(&missing).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
    assert!(missing.join("state").is_dir() || missing.join("cache").is_dir());

    let private = root.path().join("private");
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    Tor::new(&TorConfig::new(&private)).unwrap();

    let open = root.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
    match Tor::new(&TorConfig::new(&open)) {
        Err(BootstrapError::State(why)) => assert!(!why.is_empty()),
        Err(other) => panic!("{other:?}"),
        Ok(_) => panic!("a directory others may write was taken"),
    }
}

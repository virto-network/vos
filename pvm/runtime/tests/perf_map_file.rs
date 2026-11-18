//! perf's map file is created afresh by this process: a symbolic link left
//! at its path is replaced, never followed. Turning the map on is
//! process-wide, so this test binary holds this test alone.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[test]
fn the_perf_map_never_follows_a_link_left_at_its_path() {
    let path = format!("/tmp/perf-{}.map", std::process::id());
    let target = std::env::temp_dir().join(format!("perf-map-target-{}", std::process::id()));
    std::fs::write(&target, b"untouched").unwrap();
    let _ = std::fs::remove_file(&path);
    std::os::unix::fs::symlink(&target, &path).unwrap();

    vos_pvm::perf_map::enable().unwrap();
    vos_pvm::recompiler::compile_code(&[0], &[1], &[]).unwrap();

    assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
    let map = std::fs::symlink_metadata(&path).unwrap();
    assert!(map.file_type().is_file(), "a file of its own, not the link");
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(&target).unwrap();
}

//! Smoke tests for the AI extension. These deliberately avoid
//! the model-loading + inference path — that needs ~400MB of
//! network fetch and several seconds of CPU even on the smallest
//! quantized model, which makes it unfriendly for default `cargo
//! test` runs. A separate `#[ignore]`d test handles the real
//! end-to-end if/when someone wants to drive it manually.
//!
//! Covers:
//!
//! - Default `InitConfig` populates the expected Qwen2.5-Coder
//!   defaults.
//! - `InitConfig::from_args` overlays present keys from an rkyv-
//!   encoded `Args` map.
//! - Unknown keys are silently ignored (forward-compat).
//! - Empty args == defaults.

use ai_extension::InitConfig;
use vos::Encode;
use vos::value::Args;

#[test]
fn default_config_has_qwen_defaults() {
    let cfg = InitConfig::default();
    assert!(
        cfg.model_repo.starts_with("Qwen/"),
        "default model_repo should be a Qwen variant, got {}",
        cfg.model_repo,
    );
    assert!(
        cfg.model_file.ends_with(".gguf"),
        "default model_file should be GGUF, got {}",
        cfg.model_file,
    );
    assert!(
        cfg.max_seq_len >= 512,
        "default max_seq_len should be at least 512 to be useful, got {}",
        cfg.max_seq_len,
    );
}

#[test]
fn from_args_empty_is_defaults() {
    let cfg = InitConfig::from_args(&[]);
    let dflt = InitConfig::default();
    assert_eq!(cfg.model_repo, dflt.model_repo);
    assert_eq!(cfg.model_file, dflt.model_file);
    assert_eq!(cfg.max_seq_len, dflt.max_seq_len);
}

#[test]
fn from_args_overlays_present_keys() {
    let args = Args::new()
        .with("model_repo", "custom/repo".to_string())
        .with("model_file", "custom.gguf".to_string())
        .with("max_seq_len", 4096u32);
    let bytes = args.encode();
    let cfg = InitConfig::from_args(&bytes);
    assert_eq!(cfg.model_repo, "custom/repo");
    assert_eq!(cfg.model_file, "custom.gguf");
    assert_eq!(cfg.max_seq_len, 4096);
    // Untouched keys stay at defaults.
    let dflt = InitConfig::default();
    assert_eq!(cfg.tokenizer_repo, dflt.tokenizer_repo);
    assert_eq!(cfg.tokenizer_file, dflt.tokenizer_file);
}

#[test]
fn from_args_ignores_unknown_keys() {
    let args = Args::new()
        .with("not_a_real_key", "ignored".to_string())
        .with("model_repo", "valid/override".to_string());
    let bytes = args.encode();
    let cfg = InitConfig::from_args(&bytes);
    assert_eq!(cfg.model_repo, "valid/override");
}

#[test]
fn from_args_malformed_falls_back_to_defaults() {
    // Garbage bytes — neither rkyv nor anything else recognises
    // them. The extension should not panic and should not refuse
    // to start; defaults are the fallback so an operator with a
    // bad init blob still gets a working extension.
    let cfg = InitConfig::from_args(&[0xFF, 0xFE, 0xFD]);
    let dflt = InitConfig::default();
    assert_eq!(cfg.model_repo, dflt.model_repo);
}

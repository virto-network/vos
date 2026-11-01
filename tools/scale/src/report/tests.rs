use super::{Summary, compare, host_summary, text};
use crate::check::Facts;
use crate::sample::{Disk, Process, Sample, Thread};

fn facts() -> Facts {
    let mut facts = Facts {
        name: "a".into(),
        role: "node".into(),
        cores: Some("0-3".into()),
        ..Facts::default()
    };
    for (key, value) in [("clk_tck", "100"), ("iface", "eth0"), ("link_mbps", "1000")] {
        facts.probe.insert(key.into(), value.into());
    }
    facts
}

fn sample(t_ms: u64, busy: u64, ticks: u64, io_ms: u64, tx: u64) -> Sample {
    Sample {
        t_ms,
        cpu: [("user", busy), ("idle", 10_000 - busy), ("iowait", 0)]
            .into_iter()
            .map(|(kind, value)| (kind.to_string(), value))
            .collect(),
        process: Some(Process {
            pid: 7,
            utime: ticks,
            rss_kb: 1 << 20,
            threads: vec![Thread {
                tid: 8,
                comm: "vos runtime".into(),
                utime: ticks,
                ..Thread::default()
            }],
            ..Process::default()
        }),
        disk: Some(Disk {
            io_ms,
            ..Disk::default()
        }),
        rx_bytes: Some(0),
        tx_bytes: Some(tx),
        freq_khz: Some(2_000_000),
        freq_max_khz: Some(4_000_000),
    }
}

#[test]
fn a_saturated_thread_binds_on_an_idle_host() {
    // Over 10 s one thread used 950 ticks: 95% of a core, a quarter of
    // the four the node may use, the disk idle.
    let first = sample(0, 0, 0, 0, 0);
    let last = sample(10_000, 950, 950, 0, 0);
    let summary = host_summary(&facts(), &[&first, &last]);
    assert!(
        (summary.process_cpu_pct - 23.75).abs() < 1e-6,
        "{}",
        summary.process_cpu_pct
    );
    assert_eq!(summary.binding, "thread vos runtime (8)");
    assert!((summary.binding_pct - 95.0).abs() < 1e-6);
    assert_eq!(summary.clock_pct, Some(50.0));
}

#[test]
fn the_binding_resource_is_the_most_used() {
    // Over 10 s: the node's thread used 200 ticks (2 s of a core: 5% of
    // four), the disk was busy 9 s (90%), the link sent 100 MB (8% of
    // 1 GbE).
    let first = sample(0, 0, 0, 0, 0);
    let last = sample(10_000, 1_000, 200, 9_000, 100_000_000);
    let summary = host_summary(&facts(), &[&first, &last]);
    assert!(
        (summary.process_cpu_pct - 5.0).abs() < 1e-6,
        "{}",
        summary.process_cpu_pct
    );
    assert!(
        (summary.link_util_pct.unwrap() - 8.0).abs() < 1e-6,
        "{:?}",
        summary.link_util_pct
    );
    assert_eq!(summary.binding, "disk");
    assert!((summary.binding_pct - 90.0).abs() < 1e-6);
    assert_eq!(summary.threads[0].0, "vos runtime");
    assert_eq!(summary.rss_mib, 1024.0);
}

/// The window is the drivers' load past its ramp: the drain's lines,
/// written while the last answers come, are left out; a pool that made
/// requests wait is warned of; reads at a cut left open by the run's
/// end are reported apart from the errors.
#[test]
fn the_window_is_the_load_not_the_drain() {
    let dir = tempfile::tempdir().unwrap();
    let run = crate::runs::Run {
        id: "r".into(),
        dir: dir.path().to_path_buf(),
    };
    let driver = Facts {
        name: "d".into(),
        role: "driver".into(),
        ..Facts::default()
    };
    std::fs::write(
        run.file("hosts.json"),
        serde_json::to_string(&vec![driver]).unwrap(),
    )
    .unwrap();
    let mut lines = String::new();
    for t in (110_000..=400_000).step_by(10_000) {
        lines += &format!("{{\"t_ms\":{t},\"total\":false,\"kind\":\"all\",\"sent\":1}}\n");
    }
    lines += "{\"t_ms\":400000,\"total\":true,\"kind\":\"cut_read\",\"sent\":0,\"ok\":5,\"errors\":1,\"by_error\":{\"Workflow(Attesting)\":1},\"not_closed\":3}\n";
    lines += "{\"t_ms\":400000,\"total\":true,\"kind\":\"all\",\"sent\":1000,\"conn_waits\":50,\"load_from_ms\":100000,\"load_to_ms\":160000}\n";
    let hosts = run.dir.join("hosts").join("d");
    std::fs::create_dir_all(&hosts).unwrap();
    std::fs::write(hosts.join("r.drive.jsonl"), lines).unwrap();
    let summary = super::report(&run, None, Some(10)).unwrap();
    assert_eq!(summary.window_ms, (110_000, 160_000));
    let reads = &summary.drivers[0].kinds["cut_read"];
    assert_eq!((reads.ok, reads.errors, reads.not_closed), (5, 1, 3));
    assert!(text(&summary).contains("1 errors {\"Workflow(Attesting)\": 1}"));
    assert!(text(&summary).contains("; 3 not closed in the run"));
    assert!(
        summary
            .warnings
            .iter()
            .any(|warning| warning.contains("the pool bound")),
        "{:?}",
        summary.warnings
    );
}

#[test]
fn every_report_states_what_it_does_not_model_and_t2s_assumption() {
    let summary = Summary {
        not_modeled: super::NOT_MODELED.into(),
        t2: super::T2.into(),
        agents: 64,
        ..Summary::default()
    };
    let text = text(&summary);
    assert!(text.contains("not modeled"));
    assert!(text.contains("K >= 128"));
    assert!(text.contains("K = 64"));
    assert!(compare(&summary, &summary).contains("calls/s"));
}

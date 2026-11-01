use super::{Facts, judge, judge_machines, kernel_at_least, size_kb};
use crate::inventory::Inventory;

fn inventory() -> Inventory {
    Inventory::parse(
        r#"
            [[host]]
            name = "a"
            ssh = "me@10.0.0.1"
            address = "10.0.0.1"
            role = "node"
            dir = "/data/a"
            api = 7001
            peer = 7101
            [[host]]
            name = "b"
            ssh = "localhost"
            address = "127.0.0.1"
            role = "node"
            dir = "/srv/b"
            api = 7002
            peer = 7102
            [[host]]
            name = "c"
            ssh = "localhost"
            address = "127.0.0.1"
            role = "node"
            dir = "/srv/c"
            api = 7003
            peer = 7103
            "#,
    )
    .unwrap()
}

fn good() -> Facts {
    let mut facts = Facts::default();
    for (key, value) in [
        ("arch", "x86_64"),
        ("kernel", "6.12.9-arch1"),
        ("cpus", "16"),
        ("governors", "performance"),
        ("mem_available_kb", "33554432"),
        ("disk_free_kb", "104857600"),
        ("disk", "nvme0n1"),
        ("disk_rotational", "0"),
        ("iface", "enp3s0"),
        ("wireless", "0"),
        ("link_mbps", "2500"),
        ("user_manager", "1"),
        ("linger", "yes"),
        ("ntp_synchronized", "yes"),
    ] {
        facts.probe.insert(key.into(), value.into());
    }
    facts
}

fn judged(change: impl FnOnce(&mut Facts)) -> Facts {
    let inventory = inventory();
    let mut facts = good();
    change(&mut facts);
    judge(&mut facts, &inventory.hosts[0], &inventory.harness);
    facts
}

#[test]
fn a_wired_host_with_a_steady_clock_passes() {
    let facts = judged(|_| {});
    assert!(facts.refused.is_empty(), "{:?}", facts.refused);
    assert!(facts.warnings.is_empty(), "{:?}", facts.warnings);
}

#[test]
fn wifi_an_old_kernel_a_skewed_clock_or_another_arch_is_refused() {
    let refused = |change: fn(&mut Facts), word: &str| {
        let facts = judged(change);
        assert!(
            facts.refused.iter().any(|refusal| refusal.contains(word)),
            "{word}: {:?}",
            facts.refused
        );
    };
    refused(
        |facts| {
            facts.probe.insert("wireless".into(), "1".into());
        },
        "Wi-Fi",
    );
    refused(
        |facts| {
            facts.probe.insert("kernel".into(), "6.6.30".into());
        },
        "6.7",
    );
    refused(|facts| facts.clock_offset_ms = -150.0, "100 ms");
    refused(
        |facts| {
            facts.probe.insert("arch".into(), "aarch64".into());
        },
        "x86_64",
    );
    refused(
        |facts| {
            facts.probe.insert("linger".into(), "no".into());
        },
        "enable-linger",
    );
    refused(
        |facts| {
            facts.probe.insert("missing".into(), "rsync".into());
        },
        "rsync",
    );
    refused(
        |facts| {
            facts.probe.insert("taken".into(), "tcp/7001".into());
        },
        "tcp/7001",
    );
}

#[test]
fn a_slow_link_a_rotating_disk_or_a_saving_governor_is_warned_of() {
    let facts = judged(|facts| {
        facts.probe.insert("link_mbps".into(), "100".into());
        facts.probe.insert("disk_rotational".into(), "1".into());
        facts.probe.insert("governors".into(), "powersave".into());
    });
    assert!(facts.refused.is_empty(), "{:?}", facts.refused);
    assert_eq!(facts.warnings.len(), 3, "{:?}", facts.warnings);
}

#[test]
fn a_usb_or_unknown_disk_or_an_unsynchronised_clock_is_warned_of() {
    for (change, word) in [
        (("disk_transport", "usb"), "USB"),
        (("disk_rotational", ""), "unknown"),
        (("ntp_synchronized", "no"), "NTP"),
    ] {
        let facts = judged(|facts| {
            facts.probe.insert(change.0.into(), change.1.into());
        });
        assert!(facts.refused.is_empty(), "{:?}", facts.refused);
        assert!(
            facts.warnings.iter().any(|warning| warning.contains(word)),
            "{word}: {:?}",
            facts.warnings
        );
    }
}

#[test]
fn a_machine_whose_caps_do_not_fit_or_that_mixes_roles_is_refused() {
    let text = r#"
            [harness]
            memory_max = "8G"
            [[host]]
            name = "a"
            ssh = "me@10.0.0.1"
            address = "10.0.0.1"
            role = "node"
            dir = "/data/a"
            api = 7001
            peer = 7101
            [[host]]
            name = "b"
            ssh = "me@10.0.0.1"
            address = "10.0.0.1"
            role = "node"
            dir = "/data/b"
            api = 7002
            peer = 7102
            [[host]]
            name = "c"
            ssh = "me@10.0.0.3"
            address = "10.0.0.3"
            role = "node"
            dir = "/data/c"
            api = 7001
            peer = 7101
            [[host]]
            name = "d"
            ssh = "me@10.0.0.3"
            address = "10.0.0.3"
            role = "driver"
            dir = "/data/d"
        "#;
    let mut inventory = Inventory::parse(text).unwrap();
    let machines = ["m1", "m1", "m3", "m3"];
    let judged = |inventory: &Inventory, free_gib: u64, coordinator: &str| {
        let mut facts: Vec<Facts> = machines
            .iter()
            .map(|machine| {
                let mut facts = good();
                facts.probe.insert("machine_id".into(), machine.to_string());
                facts
                    .probe
                    .insert("mem_available_kb".into(), (free_gib << 20).to_string());
                facts
            })
            .collect();
        judge_machines(
            &mut facts,
            &inventory.hosts,
            &inventory.harness,
            coordinator,
        );
        facts
    };
    // Two 8 GiB caps and the reserve need 18 GiB on m1.
    let facts = judged(&inventory, 17, "none");
    assert!(
        facts[0]
            .refused
            .iter()
            .any(|refusal| refusal.contains("memory caps")),
        "{:?}",
        facts[0].refused
    );
    assert!(judged(&inventory, 64, "none")[0].refused.is_empty());
    // A driver beside a node, and the coordinator on a node's machine.
    let facts = judged(&inventory, 64, "m1");
    assert!(
        facts[2]
            .refused
            .iter()
            .any(|refusal| refusal.contains("a node and a driver"))
    );
    assert!(
        facts[0]
            .refused
            .iter()
            .any(|refusal| refusal.contains("the coordinator"))
    );
    inventory.harness.smoke = true;
    let facts = judged(&inventory, 64, "m1");
    assert!(facts.iter().all(|facts| facts.refused.is_empty()));
    assert!(
        facts[2]
            .warnings
            .iter()
            .any(|warning| warning.contains("smoke"))
    );
}

/// Three nodes on one machine (each its dir and ports, their caps
/// summed), the drivers and the coordinator on another that holds no
/// node: the two machines a scale run has.
#[test]
fn three_nodes_on_one_machine_and_the_drivers_on_the_coordinator_pass() {
    let mut text = String::from("[harness]\nmemory_max = \"8G\"\n");
    for at in 1..=3 {
        text += &format!(
            "[[host]]\nname = \"c{at}\"\nssh = \"owner@10.0.0.2\"\naddress = \"10.0.0.2\"\nrole = \"node\"\ndir = \"/srv/vos-scale/n{at}\"\ncores = \"{}-{}\"\napi = {}\npeer = {}\n",
            4 * (at - 1),
            4 * at - 1,
            7700 + at,
            7800 + at
        );
    }
    for at in 1..=2 {
        text += &format!(
            "[[host]]\nname = \"d{at}\"\nssh = \"localhost\"\naddress = \"10.0.0.1\"\nrole = \"driver\"\ndir = \"/var/tmp/vos-scale/d{at}\"\nmemory_max = \"2G\"\n"
        );
    }
    let inventory = Inventory::parse(&text).unwrap();
    let judged = |free_gib: u64, disk_free_gib: u64| {
        let mut facts: Vec<Facts> = inventory
            .hosts
            .iter()
            .map(|host| {
                let mut facts = good();
                let machine = if host.is_local() { "desk" } else { "compumax" };
                facts.probe.insert("machine_id".into(), machine.into());
                facts
                    .probe
                    .insert("mem_available_kb".into(), (free_gib << 20).to_string());
                facts
                    .probe
                    .insert("disk_source".into(), "/dev/nvme0n1p2".into());
                facts
                    .probe
                    .insert("disk_free_kb".into(), (disk_free_gib << 20).to_string());
                judge(&mut facts, host, &inventory.harness);
                facts
            })
            .collect();
        judge_machines(&mut facts, &inventory.hosts, &inventory.harness, "desk");
        facts
    };
    let facts = judged(32, 100);
    assert!(
        facts.iter().all(|facts| facts.refused.is_empty()),
        "{:?}",
        facts.iter().map(|facts| &facts.refused).collect::<Vec<_>>()
    );
    assert!(facts.iter().all(|facts| facts.warnings.is_empty()));
    // Three 8 GiB caps and the reserve need 26 GiB on compumax.
    let facts = judged(25, 100);
    assert!(
        facts[0]
            .refused
            .iter()
            .any(|refusal| refusal.contains("memory caps"))
    );
    assert!(
        facts[3].refused.is_empty(),
        "the drivers' machine: {:?}",
        facts[3].refused
    );
    // Three nodes on one disk need its free space thrice.
    let facts = judged(32, 25);
    assert!(
        facts[0]
            .refused
            .iter()
            .any(|refusal| refusal.contains("share its data disk"))
    );
    assert!(facts[3].refused.is_empty());
}

#[test]
fn a_driver_on_wifi_is_warned_of_and_a_node_on_wifi_refused() {
    let mut text = String::new();
    for at in 1..=3 {
        text += &format!(
            "[[host]]\nname = \"n{at}\"\nssh = \"me@10.0.0.2\"\naddress = \"10.0.0.2\"\nrole = \"node\"\ndir = \"/srv/n{at}\"\napi = {}\npeer = {}\n",
            7000 + at,
            7100 + at
        );
    }
    text += r#"
            [[host]]
            name = "d"
            ssh = "localhost"
            address = "10.0.0.1"
            role = "driver"
            dir = "/var/tmp/d"
            "#;
    let inventory = Inventory::parse(&text).unwrap();
    let judged = |at: usize| {
        let mut facts = good();
        facts.probe.insert("wireless".into(), "1".into());
        judge(&mut facts, &inventory.hosts[at], &inventory.harness);
        facts
    };
    let node = judged(0);
    assert!(node.refused.iter().any(|refusal| refusal.contains("Wi-Fi")));
    let driver = judged(3);
    assert!(driver.refused.is_empty(), "{:?}", driver.refused);
    assert!(
        driver
            .warnings
            .iter()
            .any(|warning| warning.contains("Wi-Fi"))
    );
}

#[test]
fn a_link_is_measured_by_its_round_trips() {
    let inventory = inventory();
    let link = super::link(&inventory.hosts[1], "127.0.0.1", 3).unwrap();
    assert_eq!((link.sent, link.lost), (3, 0));
    assert!(link.p50_ms <= link.p99_ms && link.p99_ms <= link.max_ms);
    assert!(link.max_ms < 50.0, "{link:?}");
}

#[test]
fn this_machines_clock_reads_over_one_session() {
    let inventory = inventory();
    let (offset, rtt) = super::clock(&inventory.hosts[1]).unwrap();
    assert!(offset.abs() < 50.0 && rtt < 50.0, "{offset} {rtt}");
}

#[test]
fn kernels_and_sizes_read() {
    assert!(kernel_at_least("6.7.0", (6, 7)));
    assert!(kernel_at_least("7.1.13-2-MANJARO", (6, 7)));
    assert!(!kernel_at_least("6.6.87-1-lts", (6, 7)));
    assert!(!kernel_at_least("5.15.0", (6, 7)));
    assert_eq!(size_kb("16G"), Some(16 << 20));
    assert_eq!(size_kb("512M"), Some(512 << 10));
    assert_eq!(size_kb("lots"), None);
}

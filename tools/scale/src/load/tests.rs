use super::{Kind, Model, Plan, Readers, Shares, Users, Zipf, stride};
use crate::agents::Mix;
use std::collections::{BTreeMap, HashMap};

fn model(users: u64, rate: f64) -> Model {
    Model {
        users,
        active: 0.05,
        per_user: rate / (users as f64 * 0.05),
        active_s: 60.0,
        shares: Shares::default(),
        cross: Model::random_cross(16),
        zipf: 1.0,
        identity_hz: 10.0,
        readers: 0.0,
        seed: 3,
    }
}

#[test]
fn one_rate_drives_the_load() {
    let model = model(1_000_000, 0.0);
    let model = Model {
        per_user: 0.1,
        ..model
    };
    assert!((model.rate() - 5_000.0).abs() < 1e-6);
    assert!((Model::random_cross(64) - 0.984_375).abs() < 1e-9);
}

#[test]
fn reads_at_a_cut_need_the_representative() {
    let mixed = model(1_000, 10.0);
    assert!(mixed.shares.cut > 0.0, "the default mix reads at a cut");
    let refused = mixed.check_representative(false).unwrap_err();
    assert!(refused.contains("--representative"), "{refused}");
    assert!(mixed.check_representative(true).is_ok());
    let none = Model {
        shares: Shares::parse("transfer=0.8,query=0.15,workflow=0.05,cut=0").unwrap(),
        ..model(1_000, 10.0)
    };
    assert!(none.check_representative(false).is_ok());
    let readers = Model {
        readers: 0.01,
        ..none.clone()
    };
    assert!(readers.check_representative(false).is_err());
    assert!(readers.check_representative(true).is_ok());
}

#[test]
fn the_mix_parses_whole_or_not_at_all() {
    let shares = Shares::parse("transfer=0.7,query=0.2,workflow=0.05,cut=0.05").unwrap();
    assert_eq!(shares.query, 0.2);
    for bad in [
        "transfer=0.7,query=0.2,workflow=0.05",
        "transfer=0.7,query=0.2,workflow=0.05,cut=0.06",
        "transfer=0.7,transfer=0.2,workflow=0.05,cut=0.05",
        "transfer=0.7,query=0.2,workflow=0.05,reads=0.05",
    ] {
        assert!(Shares::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn zipf_draws_rank_k_in_proportion_to_its_inverse() {
    let zipf = Zipf::new(1_000, 1.0);
    let mut mix = Mix(9);
    let mut counts = vec![0u64; 1_001];
    let draws = 400_000;
    for _ in 0..draws {
        counts[zipf.sample(&mut mix) as usize] += 1;
    }
    let harmonic: f64 = (1..=1_000).map(|k| 1.0 / k as f64).sum();
    for k in [1usize, 2, 10, 100] {
        let expected = draws as f64 / (k as f64 * harmonic);
        let seen = counts[k] as f64;
        assert!(
            (seen - expected).abs() < 5.0 * expected.sqrt() + 0.02 * expected,
            "rank {k}: {seen} against {expected}"
        );
    }
    assert_eq!(counts[0], 0);
}

#[test]
fn ranks_map_to_every_user_once() {
    for users in [1u64, 2, 10, 64, 1_000, 999_983] {
        let step = stride(users, 5);
        let mut seen = std::collections::HashSet::new();
        for rank in 0..users.min(5_000) {
            assert!(seen.insert((u128::from(rank) * u128::from(step) % u128::from(users)) as u64));
        }
    }
}

/// The plan's arrivals keep the rate, the mix and the cross-shard
/// share within a hundredth of their targets, and each active user
/// makes about `r` calls a second.
#[test]
fn a_plan_offers_the_rate_the_mix_and_the_cross_share() {
    let model = model(20_000, 2_000.0);
    let users = Users::new(model.seed, model.users, 16);
    let plan = Plan::new(&model, &users, 0, 1);
    assert_eq!(plan.slots(), 1_000);
    let secs = 60.0;
    let mut kinds: BTreeMap<Kind, u64> = BTreeMap::new();
    let (mut transfers, mut cross) = (0u64, 0u64);
    let mut by_user: HashMap<u64, u64> = HashMap::new();
    let mut last = 0.0;
    for planned in plan.take_while(|planned| planned.t < secs) {
        assert!(planned.t >= last);
        last = planned.t;
        *kinds.entry(planned.kind).or_default() += 1;
        if let Some((payee, other)) = planned.payee {
            transfers += 1;
            cross += u64::from(other);
            assert_eq!(
                other,
                users.shard(payee) != users.shard(planned.user),
                "{planned:?}"
            );
        }
        if planned.kind != Kind::Identity {
            *by_user.entry(planned.user).or_default() += 1;
        }
    }
    let identity = kinds.remove(&Kind::Identity).unwrap_or(0);
    assert!((599..=601).contains(&identity), "{identity}");
    let calls: u64 = kinds.values().sum();
    let rate = calls as f64 / secs;
    assert!((rate / 2_000.0 - 1.0).abs() < 0.01, "{rate}");
    for kind in Kind::MIX {
        let share = kinds.get(&kind).copied().unwrap_or(0) as f64 / calls as f64;
        assert!(
            (share - model.shares.of(kind)).abs() < 0.01,
            "{kind:?}: {share}"
        );
    }
    let share = cross as f64 / transfers as f64;
    assert!((share - model.cross).abs() < 0.01, "{share}");
    // Zipf: the hottest user acts far more than the median one, yet
    // no user goes past a few times `r` while active.
    let most = by_user.values().max().copied().unwrap_or(0) as f64;
    assert!(most / secs < 10.0 * model.per_user, "{most}");
}

/// A tenth of 100 agents read each two-minute window, each once, at
/// times within it; the reads go beside the mix, which keeps its rate.
#[test]
fn a_share_of_the_agents_reads_once_a_window() {
    let model = Model {
        readers: 0.1,
        identity_hz: 0.0,
        ..model(10_000, 100.0)
    };
    let users = Users::new(model.seed, model.users, 4);
    let start_ms = 1_000_000;
    let readers = Readers {
        agents: 100,
        origin_ms: start_ms - 30_000,
        length_ms: 120_000,
        start_ms,
    };
    let plan = Plan::new(&model, &users, 0, 1).with_readers(readers);
    let mut by_window: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    let mut calls = 0u64;
    let mut last = 0.0;
    for planned in plan.take_while(|planned| planned.t < 330.0) {
        assert!(planned.t >= last, "{planned:?}");
        last = planned.t;
        match planned.kind {
            Kind::Reader => {
                let at = start_ms as f64 + planned.t * 1e3;
                let window = ((at - readers.origin_ms as f64) / 120_000.0) as u64;
                by_window
                    .entry(window)
                    .or_default()
                    .push(planned.agent.unwrap());
            }
            _ => calls += 1,
        }
    }
    // Windows 1 and 2 whole; window 0 began before the load.
    for window in [1, 2] {
        let mut agents = by_window[&window].clone();
        assert_eq!(agents.len(), 10, "window {window}");
        agents.sort_unstable();
        agents.dedup();
        assert_eq!(agents.len(), 10);
    }
    assert!(by_window[&0].len() < 10);
    assert!((calls as f64 / 330.0 / 100.0 - 1.0).abs() < 0.05, "{calls}");
}

#[test]
fn drivers_split_the_users_and_the_rate() {
    let model = model(10_000, 1_000.0);
    let users = Users::new(model.seed, model.users, 4);
    for driver in 0..3u64 {
        let plan = Plan::new(&model, &users, driver, 3);
        let mut calls = 0u64;
        for planned in plan.take_while(|planned| planned.t < 30.0) {
            if planned.kind != Kind::Identity {
                assert_eq!(planned.user % 3, driver);
                calls += 1;
            } else {
                assert_eq!(driver, 0, "the first driver writes identities alone");
            }
        }
        let rate = calls as f64 / 30.0;
        assert!((rate / (1_000.0 / 3.0) - 1.0).abs() < 0.03, "{rate}");
    }
}

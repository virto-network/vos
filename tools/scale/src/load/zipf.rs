use crate::agents::Mix;

/// Zipf over ranks `1..=n` with exponent `s`, by rejection-inversion
/// (Hörmann and Derflinger): constant time a draw, whatever `n`.
pub struct Zipf {
    n: f64,
    s: f64,
    h_x1: f64,
    h_n: f64,
    cut: f64,
}

/// `ln(1 + x) / x`, continuous at 0.
fn helper1(x: f64) -> f64 {
    if x.abs() > 1e-8 {
        x.ln_1p() / x
    } else {
        1.0 - x * (0.5 - x * (1.0 / 3.0 - 0.25 * x))
    }
}

/// `(e^x − 1) / x`, continuous at 0.
fn helper2(x: f64) -> f64 {
    if x.abs() > 1e-8 {
        x.exp_m1() / x
    } else {
        1.0 + x * 0.5 * (1.0 + x * (1.0 / 3.0) * (1.0 + 0.25 * x))
    }
}

impl Zipf {
    pub fn new(n: u64, s: f64) -> Self {
        let mut zipf = Self {
            n: n as f64,
            s,
            h_x1: 0.0,
            h_n: 0.0,
            cut: 0.0,
        };
        zipf.h_x1 = zipf.big_h(1.5) - 1.0;
        zipf.h_n = zipf.big_h(n as f64 + 0.5);
        zipf.cut = 2.0 - zipf.big_h_inv(zipf.big_h(2.5) - zipf.h(2.0));
        zipf
    }

    fn h(&self, x: f64) -> f64 {
        (-self.s * x.ln()).exp()
    }

    fn big_h(&self, x: f64) -> f64 {
        let log = x.ln();
        helper2((1.0 - self.s) * log) * log
    }

    fn big_h_inv(&self, x: f64) -> f64 {
        let t = (x * (1.0 - self.s)).max(-1.0);
        (helper1(t) * x).exp()
    }

    /// A rank in `1..=n`, rank `k` drawn in proportion to `k^−s`.
    pub fn sample(&self, mix: &mut Mix) -> u64 {
        loop {
            let u = self.h_n + mix.unit() * (self.h_x1 - self.h_n);
            let x = self.big_h_inv(u);
            let k = (x + 0.5).floor().clamp(1.0, self.n);
            if k - x <= self.cut || u >= self.big_h(k + 0.5) - self.h(k) {
                return k as u64;
            }
        }
    }
}

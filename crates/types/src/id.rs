use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

#[derive(Serialize, Deserialize, Hash, Clone, Copy, Debug)]
pub enum Id {
    Univariate(usize),
    Bivariate(usize, usize),
}

impl PartialOrd for Id {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Id {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Id::Univariate(a), Id::Univariate(b)) => a.cmp(b),
            (Id::Bivariate(a, b), Id::Bivariate(c, d)) => {
                if a < c {
                    Ordering::Less
                } else if a > c {
                    Ordering::Greater
                } else {
                    b.cmp(d)
                }
            }
            (Id::Bivariate(_, _), Id::Univariate(_)) => Ordering::Greater,
            (Id::Univariate(_), Id::Bivariate(_, _)) => Ordering::Less,
        }
    }
}

impl PartialEq for Id {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Id::Univariate(a), Id::Univariate(b)) => a == b,
            (Id::Bivariate(a, b), Id::Bivariate(c, d)) => a == c && b == d,
            _ => false,
        }
    }
}

impl Eq for Id {}

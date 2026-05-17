use rand::distributions::{Alphanumeric, DistString};

pub(crate) fn alphanumeric(len: usize) -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), len)
}

pub(crate) fn is_alphanumeric(s: &str) -> bool {
    s.chars().all(|c| c.is_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rand_alphanumeric() {
        let lengths = [4, 8, 16, 32, 64, 128];

        for length in lengths {
            let s = alphanumeric(length);

            assert_eq!(s.len(), length);
            assert_eq!(is_alphanumeric(&s), true);
        }
    }

    #[test]
    fn test_is_alphanumeric() {
        let alphanumerics = [("Alphanumeric101", true), ("Non-alphanumeric-101", false)];

        for (alphanumeric, b) in alphanumerics {
            assert_eq!(is_alphanumeric(alphanumeric), b);
        }
    }
}

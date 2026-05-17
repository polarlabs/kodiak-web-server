use std::fs;
use std::path;

struct File(Box<path::Path>);

impl File {
    pub fn new(path: &path::Path) -> Option<Self> {
        match fs::metadata(path) {
            Ok(m) => {
                if m.is_file() {
                    Some(File(path.into()))
                } else {
                    None
                }
            }
            Err(e) => {
                log::error!("{}", e);
                None
            }
        }
    }

    pub fn has_extension(&self, extension: &str) -> bool {
        match self.0.extension() {
            None => false,
            Some(ext) => extension == ext,
        }
    }

    pub fn is_rw(&self) -> bool {
        !self.metadata().permissions().readonly()
    }

    fn metadata(&self) -> fs::Metadata {
        fs::metadata(&self.0).unwrap_or_else(|e| {
            log::error!("{}", e);
            unreachable!()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::distributions::Alphanumeric;
    use rand::Rng;
    use std::fs;

    const RAND_LENGTH: usize = 5;
    const TEST_DIR: &str = "test_data";
    const TEST_FILE_EXISTING: &str = "test.txt";
    const TEST_FILE_NOT_EXISTING: &str = "not-existing-test.txt";
    const TEST_FILE_RO: &str = "readonly.txt";
    const TEST_FILE_RW: &str = "readwrite.txt";
    const TEST_SYMLINK_EXISTING: &str = "link-to-test.txt";

    fn init() -> String {
        let s: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(RAND_LENGTH)
            .map(char::from)
            .collect();
        let test_path = format!("{}/{}", TEST_DIR, s);

        fs::create_dir_all(&test_path).unwrap();
        create_test_files(&test_path);

        test_path
    }

    fn create_test_files(path: &str) {
        let file = format!("{}/{}", path, TEST_FILE_EXISTING);
        let file_ro = format!("{}/{}", path, TEST_FILE_RO);
        let file_rw = format!("{}/{}", path, TEST_FILE_RW);
        let symlink = format!("{}/{}", path, TEST_SYMLINK_EXISTING);

        fs::File::create(&file).expect("Create test fs failed.");

        let _ = fs::File::create(&file_ro).unwrap();
        let mut perms = fs::metadata(&file_ro).unwrap().permissions();
        perms.set_readonly(true);
        let _ = fs::set_permissions(&file_ro, perms);

        let _ = fs::File::create(&file_rw).unwrap();

        std::os::unix::fs::symlink(TEST_FILE_EXISTING, symlink)
            .expect("Create test symlink failed.");
    }

    fn cleanup(path: &str) {
        let _ = fs::remove_dir_all(path);
        let _ = fs::remove_dir(path);
    }

    #[test]
    fn test_file_new_some_with_file() {
        let test_dir = init();

        let file = File::new(path::Path::new(&format!(
            "{}/{}",
            test_dir, TEST_FILE_EXISTING
        )));
        assert!(file.is_some());

        cleanup(&test_dir);
    }

    #[test]
    fn test_file_new_some_with_symlink() {
        let test_dir = init();

        let file = File::new(path::Path::new(&format!(
            "{}/{}",
            test_dir, TEST_SYMLINK_EXISTING
        )));
        assert!(file.is_some());

        cleanup(&test_dir);
    }

    #[test]
    fn test_file_new_none_with_dir() {
        let test_dir = init();

        let file = File::new(path::Path::new(&test_dir));
        assert!(file.is_none());

        cleanup(&test_dir);
    }

    #[test]
    fn test_file_new_none_with_file() {
        let test_dir = init();

        let file = File::new(path::Path::new(&format!(
            "{}/{}",
            test_dir, TEST_FILE_NOT_EXISTING
        )));
        assert!(file.is_none());

        cleanup(&test_dir);
    }

    #[test]
    fn test_file_has_extension_true() {
        let test_dir = init();

        let file = File::new(path::Path::new(&format!(
            "{}/{}",
            test_dir, TEST_FILE_EXISTING
        )))
        .unwrap();
        assert_eq!(file.has_extension("txt"), true);

        cleanup(&test_dir);
    }

    #[test]
    fn test_file_has_extension_false() {
        let test_dir = init();

        let file = File::new(path::Path::new(&format!(
            "{}/{}",
            test_dir, TEST_FILE_EXISTING
        )))
        .unwrap();
        assert_eq!(file.has_extension("log"), false);

        cleanup(&test_dir);
    }

    #[test]
    fn test_is_rw_true() {
        let test_dir = init();

        let file = File::new(path::Path::new(&format!("{}/{}", test_dir, TEST_FILE_RW))).unwrap();
        assert_eq!(file.is_rw(), true);

        cleanup(&test_dir);
    }

    #[test]
    fn test_is_rw_false() {
        let test_dir = init();

        let file = File::new(path::Path::new(&format!("{}/{}", test_dir, TEST_FILE_RO))).unwrap();
        assert_eq!(file.is_rw(), false);

        cleanup(&test_dir);
    }
}

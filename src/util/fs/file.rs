use std::fmt::{Display, Formatter};
// Imports from Std
use std::fs::{Metadata, OpenOptions};
use std::path;

// Wrapper for Path, uses Box to allocate on the heap.
pub struct File(Box<path::Path>);

impl File {
    pub fn new(path: &path::Path) -> Self {
        File(path.into())
    }

    pub fn exists(&self) -> bool {
        match self.metadata() {
            Some(_) => {
                log::info!("Path {self} exists.");
                true
            }
            None => false,
        }
    }

    pub fn is_dir(&self) -> bool {
        match self.metadata() {
            Some(metadata) => {
                if metadata.is_dir() {
                    log::info!("Path {self} is a directory.");
                    true
                } else {
                    log::info!("Path {self} is not a directory.");
                    false
                }
            }
            None => false,
        }
    }

    pub fn is_file(&self) -> bool {
        match self.metadata() {
            Some(metadata) => {
                if metadata.is_file() {
                    log::info!("Path {self} is a file.");
                    true
                } else {
                    log::info!("Path {self} is not a file.");
                    false
                }
            }
            None => false,
        }
    }

    pub fn is_readable(&self) -> bool {
        if self.is_dir() {
            if std::fs::read_dir(&self.0).is_ok() {
                log::info!("Directory {self} is readable.");
                true
            } else {
                log::info!("Directory {self} is not readable.");
                false
            }
        } else if self.is_file() {
            // Opens file in read-only mode.
            if std::fs::File::open(&self.0).is_ok() {
                log::info!("File {self} is readable.");
                true
            } else {
                log::info!("File {self} is not readable.");
                false
            }
        } else {
            log::info!("Path {self} is neither directory nor file.");
            self.exists();
            false
        }
    }

    pub fn is_writeable(&self) -> bool {
        if self.is_dir() {
            let mut temporary_filename = crate::util::rand::alphanumeric(8);
            temporary_filename.push_str(".tmp");

            let path = self.0.as_ref().join(temporary_filename);

            let r = match std::fs::File::options().read(true).write(true).open(&path) {
                Ok(_) => {
                    let _ = std::fs::remove_file(path);
                    true
                }
                Err(_) => false,
            };

            r
        } else if self.is_file() {
            // Opens file in write mode.
            if OpenOptions::new().write(true).open(&self.0).is_ok() {
                log::info!("File {self} is writeable.");
                true
            } else {
                log::info!("File {self} is not writeable.");
                false
            }
        } else {
            self.exists();
            false
        }
    }

    // Traverses symbolic links to get information from the destination file.
    fn metadata(&self) -> Option<Metadata> {
        match std::fs::metadata(&self.0) {
            Ok(metadata) => Some(metadata),
            Err(e) => {
                log::error!("Error {e} occurred on accessing path {self}.");
                None
            }
        }
    }
}

impl Display for File {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
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
    fn test_metadata() {
        // todo
    }

    #[test]
    fn file_exists_true() {
        let test_dir = init();

        let file = File::new(path::Path::new(&format!(
            "{}/{}",
            test_dir, TEST_FILE_EXISTING
        )));
        assert_eq!(file.exists(), true);

        cleanup(&test_dir);
    }

    #[test]
    fn file_exists_false() {
        let test_dir = init();

        let file = File::new(path::Path::new(&format!(
            "{}/{}",
            test_dir, TEST_FILE_NOT_EXISTING
        )));
        assert_eq!(file.exists(), false);

        cleanup(&test_dir);
    }

    #[test]
    fn test_is_dir() {
        // todo
    }

    #[test]
    fn test_is_file() {
        // todo
    }

    #[test]
    fn test_is_writeable() {
        // todo
    }
}

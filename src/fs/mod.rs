mod file;

use std::path;

pub fn create_parent_dirs<P: AsRef<path::Path>>(path: P) {
    let parent_dir = path::Path::new(path.as_ref()).parent();
    match parent_dir {
        Some(parent_dir) => {
            std::fs::create_dir_all(parent_dir)
                .expect("Could not create parent directory of {path}");
        }
        None => {}
    }
}

/*
pub fn files_matching<P: AsRef<Path>>(path: P) -> Files {
    let path = Path::new(path.as_ref());
    if path.is_dir() {
        match fs::read_dir(path) {
            Ok(entry) => {
                entry.map(|result| result.map(|entry| entry.f.))
                let mut entries = fs::read_dir(".")?
                    .map(|res| res. map(|e| e. path()))
                    .collect::<Result<Vec<_>, io::Error>>()?;
                entry.iter
                for path in entry {

                }
            }
            Err(_) => {}
        }

    } else {
        log::error!("Must be directory.")
    }
    let paths = fs::read_dir("./").unwrap();

    for path in paths {
        println!("Name: {}", path.unwrap().path().display())
    }

    if dir. is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry. path();
            if path. is_dir() {
                visit_dirs(&path, cb)?;
            } else {
                cb(&entry);
            }
        }
    }
    Ok(())
}
*/

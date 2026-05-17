use semver::Version as SemVer;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::{fs, io, path};

// Get an ascending sorted Vec of relative paths whose directory names are compliant to SemVer.
// Non-compliant directories are silently ignored.
//
// Returns
// - a Vec of paths if there are matching directories in path.
// - an empty Vec if there are no such directories.
// - an error if path is not a directory, directory is not readable or does not exist.
pub fn dirs_sorted_by_version<P: AsRef<path::Path>>(path: P) -> Result<Vec<PathBuf>, io::Error> {
    // The order in which `read_dir` returns entries is not guaranteed. If reproducible
    // ordering is required the entries should be explicitly sorted.
    let entries = fs::read_dir(path)?;

    let mut entries = entries
        .filter(|r| r.as_ref().unwrap().path().is_dir())
        .filter(|r| SemVer::parse(r.as_ref().unwrap().file_name().to_str().unwrap()).is_ok())
        .map(|r| r.map(|e| e.path()))
        .collect::<Result<Vec<PathBuf>, io::Error>>()?;

    // Sorting is done by a key. For migration directories the name is the sorting key.
    // Naming convention for migration directories is: SemVer compliant version.
    entries.sort_by_key(|r| SemVer::parse(r.file_name().unwrap().to_str().unwrap()).unwrap());

    Ok(entries)
}

// Get a relative path to a subdirectory in path which matches exactly name.
//
// Returns
// - Some(path) if a subdirectory with a matching name exists.
// - None if there is no such subdirectory.
// - an error if path is not a directory, directory is not readable or does not exist.
pub fn dir_filtered_by<P: AsRef<path::Path>>(
    path: P,
    name: &str,
) -> Result<Option<PathBuf>, io::Error> {
    let entries = fs::read_dir(path)?;

    let entry = entries
        .filter(|r| r.as_ref().unwrap().path().is_dir())
        .filter(|r| r.as_ref().unwrap().file_name().to_str() == Some(name))
        .map(|r| r.map(|e| e.path()))
        .collect::<Result<Vec<PathBuf>, io::Error>>()?
        .first()
        .map(|p| p.clone());

    Ok(entry)
}

// Get an ascending sorted Vec of relative paths to SQL scripts compliant to Kodiak's
// naming convention for SQL migration scripts. Non-compliant files are silently ignored.
//
// Returns
// - a Vec of paths if there are matching files in the directory.
// - an empty Vec if there are no such files.
// - an error if path is not a directory, directory is not readable or does not exist.
pub fn sql_scripts_sorted_by_rank<P: AsRef<path::Path>>(
    path: P,
) -> Result<Vec<PathBuf>, io::Error> {
    // The order in which `read_dir` returns entries is not guaranteed. If reproducible
    // ordering is required the entries should be explicitly sorted.
    let entries = fs::read_dir(path)?;

    let mut entries = entries
        .filter(|r| r.as_ref().unwrap().path().is_file())
        .filter(|r| r.as_ref().unwrap().path().extension() == Some(OsStr::new("sql")))
        .filter(|r| {
            if let Some((rank, _)) = r
                .as_ref()
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .split_once('-')
            {
                rank.parse::<u32>().is_ok()
            } else {
                false
            }
        })
        .map(|r| r.map(|e| e.path()))
        .collect::<Result<Vec<PathBuf>, io::Error>>()?;

    // Sorting is done by a key. For SQL scripts the rank, which is the first part of the filename, is the sorting key.
    // File naming convention for SQL scripts is: <rank>-....sql, so rank is before the first '-'.
    entries.sort_by_key(|p| {
        let file_name = p.file_name().unwrap().to_str().unwrap();
        if let Some((rank, _)) = file_name.split_once('-') {
            rank.parse::<u32>().unwrap()
        } else {
            unreachable!()
        }
    });

    Ok(entries)
}

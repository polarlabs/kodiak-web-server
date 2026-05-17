use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use data_encoding::{HEXLOWER};
use ring::digest::{Context, Digest, SHA256};
use semver::Version as SemVer;

use crate::db::{sqlite, util};

#[derive(Debug)]
pub struct Migrations(Vec<Migration>);

impl Migrations {
    pub fn from_path<P: AsRef<path::Path>>(path: P) -> Result<Self, std::io::Error> {
        let versions = util::dirs_sorted_by_version(path)?;

        let mut migrations = Vec::new();
        for version in versions {
            match util::dir_filtered_by(&version, "up")? {
                None => {}
                Some(direction) => {
                    let migration = Migration::from_path(direction)?;
                    migrations.push(migration);
                }
            }

            match util::dir_filtered_by(version, "down")? {
                None => {}
                Some(direction) => {
                    let migration = Migration::from_path(direction)?;
                    migrations.push(migration);
                }
            }
        }

        Ok(Migrations(migrations))
    }

    pub fn all(&self) -> &Vec<Migration> {
        &self.0
    }

    pub fn all_mut(&mut self) -> &mut Vec<Migration> {
        &mut self.0
    }
}

#[derive(Debug)]
pub struct Migration {
    driver: Driver,
    version: SemVer,
    direction: Direction,
    scripts: Scripts,
    progress: Progress
}

impl Migration {
    fn from_path<P: AsRef<path::Path>>(path: P) -> Result<Self, std::io::Error> {
        let dirs: Vec<&str> = Path::new(path.as_ref()).to_str().unwrap().split('/').rev().collect();
        let direction = dirs[0];
        let version = dirs[1];
        let driver = dirs[3];
        let scripts = Scripts::from_path(&path)?;
        let scripts_len = scripts.len() as u32;

        let migration = Migration {
            driver: Driver::from_str(driver).unwrap(),
            version: SemVer::parse(version).unwrap(),
            direction: Direction::from_str(direction).unwrap(),
            scripts,
            progress: Progress::new(0, scripts_len),
        };

        Ok(migration)
    }

    pub fn driver(&self) -> Driver {
        self.driver.to_owned()
    }

    pub fn version(&self) -> SemVer {
        self.version.to_owned()
    }

    pub fn direction(&self) -> Direction {
        self.direction.to_owned()
    }

    pub fn scripts(&self) -> &Scripts {
        &self.scripts
    }

    pub fn progress(&self) -> &Progress
    {
        &Progress::new(
            self.scripts.0.iter().filter(|&s| s.resolution.is_none()).count() as u32,
            self.scripts.len() as u32
        )
    }

    pub fn update(&mut self, progress: Progress) -> &mut Self {
        self.progress = progress;

        self
    }
}

impl Display for Migration {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.driver(), self.version(), self.direction())
    }
}

#[derive(Debug, Clone)]
pub enum Driver {
    Sqlite,
}

impl Driver {
    fn from_str(driver: &str) -> Option<Self> {
        match driver {
            "sqlite" => Some(Driver::Sqlite),
            _ => None
        }
    }

    pub fn to_str(&self) -> &'static str {
        match &self {
            Driver::Sqlite => "sqlite"
        }
    }
}

impl Display for Driver {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Direction {
    Up,
    Down,
}

impl Direction {
    fn from_str(direction: &str) -> Option<Self> {
        match direction {
            "up" => Some(Direction::Up),
            "down" => Some(Direction::Down),
            _ => None
        }
    }

    pub fn to_str(&self) -> &'static str {
        match &self {
            Direction::Up => "up",
            Direction::Down => "down"
        }
    }

    pub fn to_string(&self) -> String {
        match &self {
            Direction::Up => String::from("up"),
            Direction::Down => String::from("down"),
        }
    }
}

impl Display for Direction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[derive(Debug)]
pub struct Scripts(Vec<Script>);

fn sha256_digest<P: AsRef<path::Path>>(path: P) -> Result<Digest, std::io::Error> {
    let input = File::open(path)?;
    let mut reader = BufReader::new(input);
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 1024];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    Ok(context.finish())
}

impl Scripts {
    fn from_path<P: AsRef<path::Path>>(path: P) -> Result<Self, std::io::Error> {
        let files = util::sql_scripts_sorted_by_rank(path)?;

        let mut scripts = Vec::new();
        for file in files {
            match Script::from_str(file.file_name().unwrap().to_str().unwrap()) {
                None => {}
                Some(mut script) => {
                    script.hash = Some(format!("sha256:{}", HEXLOWER.encode(sha256_digest(file)?.as_ref())));
                    scripts.push(script);
                }
            }
        }

        Ok(Scripts(scripts))
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    pub fn all(&self) -> &Vec<Script> {
        &self.0
    }

    pub fn all_mut(&mut self) -> &mut Vec<Script> {
        &mut self.0
    }
}

#[derive(Debug, Clone)]
pub struct Script {
    rank: u32,
    filename: String,
    hash: Option<String>,
    status: Status,
    resolution: Option<Resolution>,
    timestamp: DateTime<Utc>
}

impl Script {
    fn from_str(filename: &str) -> Option<Self> {
        match filename.split_once('-') {
            None => None,
            Some((rank, _)) => {
                let script = Script {
                    rank: rank.parse::<u32>().unwrap(),
                    filename: String::from(filename),
                    hash: None,
                    status: Status::Created,
                    resolution: None,
                    timestamp: Utc::now()
                };

                Some(script)
            }
        }
    }

    pub fn rank(&self) -> u32 {
        self.rank
    }

    pub fn filename(&self) -> String {
        self.filename.to_owned()
    }

    pub fn hash(&self) -> Option<String> {
        self.hash.to_owned()
    }

    pub fn status(&self) -> Status {
        self.status.clone()
    }

    pub fn resolution(&self) -> Option<Resolution> {
        self.resolution.clone()
    }

    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    pub fn update(&mut self, status: Status, resolution: Option<Resolution>) -> &mut Self {
        self.status = status;
        self.resolution = resolution;
        self.timestamp = Utc::now();

        self
    }
}

#[derive(Debug, Clone)]
pub enum Status {
    Created,
    Running,
    Done
}

impl Status {
    pub fn to_str(&self) -> &'static str {
        match self {
            Status::Created => "created",
            Status::Running => "running",
            Status::Done => "done"
        }
    }
}

#[derive(Debug, Clone)]
pub enum Resolution {
    Succeeded,
    Canceled,
    Failed
}

impl Resolution {
    pub fn to_str(&self) -> &str {
        match self {
            Resolution::Succeeded => "succeeded",
            Resolution::Canceled => "canceled",
            Resolution::Failed => "failed"
        }
    }
}

#[derive(Debug)]
pub struct Progress {
    rank: u32,
    power: u32,
}

impl Progress {
    pub(crate) fn new(rank: u32, power: u32) -> Self {
        Progress {
            rank,
            power
        }
    }

    pub fn to_percent(&self) -> f32 {
        if self.power != 0 {
            self.rank as f32 / self.power as f32
        } else {
            1.0
        }
    }

    pub fn next(&mut self) -> &mut Self {
        self.rank += 1;
        self
    }
}

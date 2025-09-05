use std::{
    fs::File,
    io::{self, Read},
    path::Path,
    str,
};

use xenia::Gid;

type Result<T = ()> = core::result::Result<T, GroupParseError>;

enum State {
    SearchingForNameEnd,
    SearchingForUserList,
    GoingThroughPassword,
    SearchingForGid,
}

pub struct GroupEntry<'a> {
    name: &'a str,
    password: Option<&'a str>,
    userlist: &'a str,
    gid: Gid,
}

impl GroupEntry<'_> {
    pub fn group_name(&self) -> &str {
        self.name
    }

    pub fn group_password(&self) -> Option<&str> {
        self.password
    }

    pub fn userlist(&self) -> impl IntoIterator<Item = &str> {
        self.userlist.split(",")
    }

    pub fn userlist_raw(&self) -> &str {
        self.userlist
    }

    pub fn gid(&self) -> Gid {
        self.gid
    }
}

/// Holds the `/etc/group` file.
///
/// This struct allows handing out `GroupEntry` instances
/// which are tied by lifetime to this `GroupEntries`
/// which in turn allows us to omit allocations.
pub struct GroupEntries {
    data: Vec<u8>,
    last_index: usize,
}

/// Represents an error during parsing
#[derive(Debug)]
pub enum GroupParseError {
    InvalidUtf8(str::Utf8Error),
    InvalidDigits(std::num::ParseIntError),
    IoError(io::Error),
    Eof,
}

impl core::fmt::Display for GroupParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GroupParseError::InvalidUtf8(err) => write!(f, "{err}"),
            GroupParseError::IoError(err) => write!(f, "{err}"),

            GroupParseError::InvalidDigits(err) => write!(f, "{err}"),
            GroupParseError::Eof => write!(f, "end-of-file"),
        }
    }
}

impl core::error::Error for GroupParseError {}

impl From<io::Error> for GroupParseError {
    fn from(value: io::Error) -> Self {
        GroupParseError::IoError(value)
    }
}

impl From<std::num::ParseIntError> for GroupParseError {
    fn from(value: std::num::ParseIntError) -> Self {
        GroupParseError::InvalidDigits(value)
    }
}

impl From<str::Utf8Error> for GroupParseError {
    fn from(value: str::Utf8Error) -> Self {
        GroupParseError::InvalidUtf8(value)
    }
}

impl GroupEntries {
    /// Creates a `GroupEntries` from a given path.
    ///
    /// The parser will be unpredictable if the file is not an actual `/etc/group`-esque file.
    pub fn new_path<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let mut data = Vec::new();

        File::open(path)?.read_to_end(&mut data)?;

        let entries = Self {
            last_index: 0,
            data,
        };

        Ok(entries)
    }

    /// Creates a `GroupEntries`
    /// from the `/etc/group` file explicitly.
    pub fn new() -> Result<Self> {
        Self::new_path("/etc/group")
    }

    /// Yields the next entry to be parsed
    ///
    /// Returns `Err(GroupParseError::Eof)`
    /// if the input has ended.
    pub fn next_entry(&mut self) -> Result<GroupEntry<'_>> {
        if self.last_index >= self.data.len() {
            return Err(GroupParseError::Eof);
        };

        let mut state = State::SearchingForNameEnd;

        let mut group_name_end: usize = 0;

        let mut group_password_start: usize = 0;
        let mut group_password_end: usize = 0;

        let mut group_id_start: usize = 0;
        let mut group_id: u32 = 0;

        let mut user_list_start: usize = 0;
        let mut user_list_end: usize = 0;

        let vec = &self.data[self.last_index..];

        for (index, byte) in vec.iter().enumerate() {
            match state {
                State::SearchingForNameEnd => {
                    if *byte == b':' {
                        state = State::GoingThroughPassword;
                        group_password_start = index + 1;
                        group_name_end = index;
                    }
                }

                State::GoingThroughPassword => {
                    if *byte == b':' {
                        state = State::SearchingForGid;
                        group_password_end = index;
                        group_id_start = index + 1;
                    }
                }

                State::SearchingForGid => {
                    if *byte == b':' {
                        group_id = str::from_utf8(&vec[group_id_start..index])?.parse::<u32>()?;

                        state = State::SearchingForUserList;
                        user_list_start = index + 1;
                    }
                }

                State::SearchingForUserList => {
                    let newline = *byte == b'\n';

                    if newline {
                        user_list_end = index;
                        self.last_index = index;
                        break;
                    }
                }
            }
        }

        let name = str::from_utf8(&vec[0..group_name_end])?;
        let password = group_passwd(&vec[group_password_start..group_password_end])?;
        let userlist = str::from_utf8(&vec[user_list_start..user_list_end])?;

        Ok(GroupEntry {
            name,
            password,
            gid: unsafe { Gid::from_raw(group_id) },
            userlist,
        })
    }
}

fn group_passwd(data: &[u8]) -> Result<Option<&str>> {
    if data == b"x" {
        return Ok(None);
    };

    str::from_utf8(data).map(Some).map_err(Into::into)
}

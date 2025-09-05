use std::{
    fs::File,
    io::{self, BufRead, BufReader},
};

use xenia::{Gid, Uid};

pub fn getpwuid(uid: Uid) -> Option<Passwd> {
    let mut parser = PasswdEntries::new().ok()?;

    while let Some(entry) = parser.next_entry().ok()? {
        if entry.uid == uid {
            return Some(entry);
        }
    }

    None
}

#[allow(unused)]
#[derive(Debug)]
pub struct Passwd {
    pub name: String,
    pub passwd: String,
    pub uid: Uid,
    pub gid: Gid,
    pub gecos: String,
    pub dir: String,
    pub shell: String,
}

impl Passwd {
    pub fn entries() -> Result<PasswdEntries, io::Error> {
        PasswdEntries::new()
    }

    fn from_buf(buf: &str) -> Option<Self> {
        let mut entries = buf.splitn(7, |s| s == ':');

        let name = entries.next()?.to_string();
        let passwd = entries.next()?.to_string();

        let uid = entries
            .next()?
            .parse()
            .map(|uid| unsafe { Uid::from_raw(uid) })
            .ok()?;
        let gid = entries
            .next()?
            .parse()
            .map(|gid| unsafe { Gid::from_raw(gid) })
            .ok()?;

        let gecos = entries.next()?.to_string();
        let dir = entries.next()?.to_string();
        let shell = entries.next()?.to_string();

        Some(Passwd {
            name,
            passwd,
            uid,
            gid,
            gecos,
            dir,
            shell,
        })
    }
}

pub struct PasswdEntries {
    reader: BufReader<File>,
    buf: String,
}

impl PasswdEntries {
    pub fn new() -> Result<Self, io::Error> {
        let file = File::open("/etc/passwd")?;
        let reader = BufReader::new(file);

        Ok(Self {
            reader,
            buf: String::new(),
        })
    }

    pub fn next_entry(&mut self) -> Result<Option<Passwd>, io::Error> {
        self.buf.clear();

        self.reader.read_line(&mut self.buf)?;

        Ok(Passwd::from_buf(&self.buf))
    }
}

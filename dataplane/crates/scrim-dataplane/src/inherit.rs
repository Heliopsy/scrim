// SPDX-License-Identifier: AGPL-3.0-only

//! Adopting the socket the control plane passed down.

// Taking ownership of an inherited file descriptor is inherently unsafe in
// Rust: only the caller can know nothing else owns it. This module is the one
// place that does it, after checking the descriptor is an open socket.
#![allow(unsafe_code)]

use std::fmt;
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use rustix::fs::FileType;
use rustix::io::FdFlags;

/// Why the inherited socket cannot be used.
#[derive(Debug)]
pub enum Error {
    /// No `--fd` argument and no `SCRIM_DP_FD`.
    Missing,
    /// The value is not a descriptor number above stderr.
    Invalid(String),
    /// The descriptor is closed.
    Closed(rustix::io::Errno),
    /// The descriptor is not a socket.
    NotSocket,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("pass the socket as --fd <n> or SCRIM_DP_FD"),
            Self::Invalid(v) => write!(f, "{v:?} is not a file descriptor above 2"),
            Self::Closed(e) => write!(f, "descriptor is not open: {e}"),
            Self::NotSocket => f.write_str("descriptor is not a socket"),
        }
    }
}

impl std::error::Error for Error {}

/// Reads the descriptor number from `--fd <n>` / `--fd=<n>` in `args`, or
/// from the `SCRIM_DP_FD` value `env`. The argument wins.
pub fn fd_from(
    args: impl IntoIterator<Item = String>,
    env: Option<String>,
) -> Result<RawFd, Error> {
    let mut args = args.into_iter();
    let mut raw = None;
    while let Some(a) = args.next() {
        if a == "--fd" {
            raw = args.next();
        } else if let Some(v) = a.strip_prefix("--fd=") {
            raw = Some(v.to_owned());
        }
    }
    let raw = raw.or(env).ok_or(Error::Missing)?;
    match raw.parse::<RawFd>() {
        Ok(fd) if fd > 2 => Ok(fd),
        _ => Err(Error::Invalid(raw)),
    }
}

/// Takes ownership of `fd`, checks it is an open socket and marks it
/// close-on-exec.
pub fn adopt(fd: RawFd) -> Result<UnixStream, Error> {
    // SAFETY: the borrow is used only for the two checks below, while fd is
    // still open; it does not outlive this function.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let flags = rustix::io::fcntl_getfd(borrowed).map_err(Error::Closed)?;
    let stat = rustix::fs::fstat(borrowed).map_err(Error::Closed)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Socket {
        return Err(Error::NotSocket);
    }
    rustix::io::fcntl_setfd(borrowed, flags | FdFlags::CLOEXEC).map_err(Error::Closed)?;
    // SAFETY: fd is open (checked above) and was passed to this process for
    // its exclusive use by the control plane; nothing else in this process
    // refers to it, so taking ownership cannot double-close.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(UnixStream::from(owned))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_fd() {
        assert_eq!(fd_from(args(&["--fd", "3"]), None).ok(), Some(3));
        assert_eq!(fd_from(args(&["--fd=7"]), Some("3".into())).ok(), Some(7));
        assert_eq!(fd_from(args(&[]), Some("4".into())).ok(), Some(4));
        assert!(matches!(fd_from(args(&[]), None), Err(Error::Missing)));
        assert!(matches!(
            fd_from(args(&["--fd", "1"]), None),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            fd_from(args(&["--fd", "x"]), None),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn rejects_non_socket() {
        let file = std::fs::File::open("/dev/null").ok();
        let fd = file.as_ref().map(std::os::fd::AsRawFd::as_raw_fd);
        assert!(matches!(fd.map(adopt), Some(Err(Error::NotSocket))));
    }
}

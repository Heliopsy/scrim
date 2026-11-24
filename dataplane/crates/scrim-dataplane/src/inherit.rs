// SPDX-License-Identifier: AGPL-3.0-only

//! Adopting the socket the control plane passed down (Unix; see [`crate::transport`] for how
//! it is named and for the stdio transport Windows uses).

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
    /// The descriptor is closed.
    Closed(rustix::io::Errno),
    /// The descriptor is not a socket.
    NotSocket,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(e) => write!(f, "descriptor is not open: {e}"),
            Self::NotSocket => f.write_str("descriptor is not a socket"),
        }
    }
}

impl std::error::Error for Error {}

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

    #[test]
    fn rejects_non_socket() {
        let file = std::fs::File::open("/dev/null").ok();
        let fd = file.as_ref().map(std::os::fd::AsRawFd::as_raw_fd);
        assert!(matches!(fd.map(adopt), Some(Err(Error::NotSocket))));
    }
}

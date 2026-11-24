// SPDX-License-Identifier: AGPL-3.0-only

//! How the control plane connection reaches the data plane.
//!
//! - Unix: one end of a socketpair inherited as a descriptor, named by `--fd <n>` or
//!   `SCRIM_DP_FD=<n>` (the control plane passes 3), adopted by [`crate::inherit`].
//! - Windows (and accepted on Unix, for tests): `--stdio` or `SCRIM_DP_STDIO=1`. The gRPC
//!   connection is the process's stdin (control plane to data plane) and stdout (data plane to
//!   control plane), anonymous pipes private to the two processes. Nothing else may write to
//!   stdout in this mode; logs stay on stderr.
//!
//! Either way, the control plane closing its end (EOF) shuts the data plane down.

use std::fmt;

/// The connection the control plane handed down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// An inherited socket descriptor (Unix only; refused on Windows by `main`).
    Fd(i32),
    /// stdin and stdout.
    Stdio,
}

/// Why the connection cannot be named.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Neither `--fd`/`SCRIM_DP_FD` nor `--stdio`/`SCRIM_DP_STDIO`.
    Missing,
    /// The descriptor value is not a number above stderr.
    InvalidFd(String),
    /// `SCRIM_DP_STDIO` is neither `1`, `true`, `0`, `false` nor empty.
    InvalidStdio(String),
    /// Both a descriptor and stdio were given at the same level (two arguments or two
    /// variables).
    Ambiguous,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str(
                "pass the control plane connection as --fd <n> or SCRIM_DP_FD (an inherited \
                 socket, Unix), or as --stdio or SCRIM_DP_STDIO=1 (stdin and stdout)",
            ),
            Self::InvalidFd(v) => write!(f, "{v:?} is not a file descriptor above 2"),
            Self::InvalidStdio(v) => write!(f, "SCRIM_DP_STDIO must be 1 or 0, not {v:?}"),
            Self::Ambiguous => f.write_str("pass either --fd/SCRIM_DP_FD or --stdio, not both"),
        }
    }
}

impl std::error::Error for Error {}

/// Reads the transport from `args` (`--fd <n>`, `--fd=<n>`, `--stdio`) or, when no argument
/// names one, from the values of `SCRIM_DP_FD` (`fd_env`) and `SCRIM_DP_STDIO` (`stdio_env`).
/// Arguments win over the environment.
pub fn from(
    args: impl IntoIterator<Item = String>,
    fd_env: Option<String>,
    stdio_env: Option<&str>,
) -> Result<Transport, Error> {
    let mut args = args.into_iter();
    let mut fd = None;
    let mut stdio = false;
    while let Some(a) = args.next() {
        if a == "--fd" {
            fd = args.next();
        } else if let Some(v) = a.strip_prefix("--fd=") {
            fd = Some(v.to_owned());
        } else if a == "--stdio" {
            stdio = true;
        }
    }
    if fd.is_none() && !stdio {
        fd = fd_env;
        stdio = match stdio_env {
            None | Some("" | "0" | "false") => false,
            Some("1" | "true") => true,
            Some(other) => return Err(Error::InvalidStdio(other.to_owned())),
        };
    }
    match (fd, stdio) {
        (Some(_), true) => Err(Error::Ambiguous),
        (None, true) => Ok(Transport::Stdio),
        (None, false) => Err(Error::Missing),
        (Some(raw), false) => match raw.parse::<i32>() {
            Ok(n) if n > 2 => Ok(Transport::Fd(n)),
            _ => Err(Error::InvalidFd(raw)),
        },
    }
}

/// The process's stdin and stdout as one stream, for [`Transport::Stdio`]. Must be called inside
/// a tokio runtime.
pub fn stdio() -> tokio::io::Join<tokio::io::Stdin, tokio::io::Stdout> {
    tokio::io::join(tokio::io::stdin(), tokio::io::stdout())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_fd() {
        assert_eq!(from(args(&["--fd", "3"]), None, None), Ok(Transport::Fd(3)));
        assert_eq!(
            from(args(&["--fd=7"]), Some("3".into()), None),
            Ok(Transport::Fd(7))
        );
        assert_eq!(
            from(args(&[]), Some("4".into()), None),
            Ok(Transport::Fd(4))
        );
        assert_eq!(from(args(&[]), None, None), Err(Error::Missing));
        assert!(matches!(
            from(args(&["--fd", "1"]), None, None),
            Err(Error::InvalidFd(_))
        ));
        assert!(matches!(
            from(args(&["--fd", "x"]), None, None),
            Err(Error::InvalidFd(_))
        ));
    }

    #[test]
    fn parses_stdio() {
        assert_eq!(from(args(&["--stdio"]), None, None), Ok(Transport::Stdio));
        assert_eq!(from(args(&[]), None, Some("1")), Ok(Transport::Stdio));
        assert_eq!(from(args(&[]), None, Some("true")), Ok(Transport::Stdio));
        assert_eq!(from(args(&[]), None, Some("0")), Err(Error::Missing));
        assert_eq!(from(args(&[]), None, Some("")), Err(Error::Missing));
        assert_eq!(
            from(args(&[]), None, Some("yes")),
            Err(Error::InvalidStdio("yes".into()))
        );
        // The control plane on Windows passes both the flag and the variable.
        assert_eq!(
            from(args(&["--stdio"]), None, Some("1")),
            Ok(Transport::Stdio)
        );
    }

    #[test]
    fn arguments_win_over_the_environment() {
        assert_eq!(
            from(args(&["--stdio"]), Some("3".into()), None),
            Ok(Transport::Stdio)
        );
        assert_eq!(
            from(args(&["--fd", "3"]), None, Some("1")),
            Ok(Transport::Fd(3))
        );
        // An unreadable SCRIM_DP_STDIO is ignored when an argument decides.
        assert_eq!(
            from(args(&["--fd", "3"]), None, Some("yes")),
            Ok(Transport::Fd(3))
        );
    }

    #[test]
    fn refuses_both() {
        assert_eq!(
            from(args(&["--fd", "3", "--stdio"]), None, None),
            Err(Error::Ambiguous)
        );
        assert_eq!(
            from(args(&[]), Some("3".into()), Some("1")),
            Err(Error::Ambiguous)
        );
    }

    #[test]
    fn missing_names_both_options() {
        let msg = Error::Missing.to_string();
        assert!(msg.contains("--fd") && msg.contains("SCRIM_DP_FD"));
        assert!(msg.contains("--stdio") && msg.contains("SCRIM_DP_STDIO"));
    }
}

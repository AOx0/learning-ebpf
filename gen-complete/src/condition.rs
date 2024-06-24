use std::{fmt::Display, ops::Not};

use itertools::Itertools;

#[derive(Default)]
pub(crate) struct Condition<'a> {
    pub(crate) parents: &'a [&'a str],
    pub(crate) peers: &'a [(&'a str, &'a str)],
    pub(crate) requires_peers: bool,
    pub(crate) conflicts: &'a [&'a str],
    pub(crate) extras: &'a [&'a str],
    pub(crate) token_position: Position,
}

#[derive(Default, Clone, Copy)]
pub enum Position {
    #[default]
    Any,
    Eq(usize),
    Ne(usize),
    Gt(usize),
    Ge(usize),
    Lt(usize),
    Le(usize),
}

impl std::ops::Add<usize> for Position {
    type Output = Self;

    fn add(self, rhs: usize) -> Self::Output {
        match self {
            Position::Any => Position::Any,
            Position::Eq(n) => Position::Eq(n + rhs),
            Position::Ne(n) => Position::Ne(n + rhs),
            Position::Gt(n) => Position::Gt(n + rhs),
            Position::Ge(n) => Position::Ge(n + rhs),
            Position::Lt(n) => Position::Lt(n + rhs),
            Position::Le(n) => Position::Le(n + rhs),
        }
    }
}

impl Position {
    fn is_any(&self) -> bool {
        matches!(self, Position::Any)
    }
}

impl Display for Position {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Position::Any => Ok(()),
            Position::Eq(n) => write!(f, "-eq {n}"),
            Position::Ne(n) => write!(f, "-ne {n}"),
            Position::Gt(n) => write!(f, "-gt {n}"),
            Position::Ge(n) => write!(f, "-ge {n}"),
            Position::Lt(n) => write!(f, "-lt {n}"),
            Position::Le(n) => write!(f, "-le {n}"),
        }
    }
}

impl Condition<'_> {
    pub(crate) fn empty() -> Self {
        Self::default()
    }
}

impl<'a> Display for Condition<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.parents.is_empty()
            && self.peers.is_empty()
            && self.conflicts.is_empty()
            && self.extras.is_empty()
            && self.token_position.is_any()
        {
            write!(f, r#"complete -c bpftool"#)
        } else {
            write!(f, r#"complete -c bpftool -n ""#)?;

            for (i, parent) in self.parents.iter().enumerate() {
                write!(f, r#"__fish_seen_subcommand_from {parent}"#)?;
                if i < self.parents.len() - 1 {
                    write!(f, "; and ")?;
                }
            }

            if self.peers.is_empty().not() {
                write!(
                    f,
                    r#"{chain}{seen} __fish_seen_subcommand_from {commands}"#,
                    chain = if self.parents.is_empty().not() {
                        "; and "
                    } else {
                        ""
                    },
                    seen = if self.requires_peers { "" } else { "not" },
                    commands = self.peers.iter().map(|a| a.0).join(" "),
                )?;
            }

            if self.conflicts.is_empty().not() {
                write!(
                    f,
                    "{chain}not __fish_seen_subcommand_from {commands}",
                    chain = if self.parents.is_empty().not() || self.peers.is_empty().not() {
                        "; and "
                    } else {
                        ""
                    },
                    commands = self.conflicts.join(" ")
                )?
            }

            if self.extras.is_empty().not() {
                write!(
                    f,
                    "{chain}{extras}",
                    chain = if self.parents.is_empty().not()
                        || self.peers.is_empty().not()
                        || self.conflicts.is_empty().not()
                    {
                        "; and "
                    } else {
                        ""
                    },
                    extras = self.extras.join("; and ")
                )?
            }

            if self.token_position.is_any().not() {
                write!(
                    f,
                    "{chain}test (__fish_bpftool_count_commands) {pos}",
                    chain = if self.parents.is_empty().not()
                        || self.peers.is_empty().not()
                        || self.conflicts.is_empty().not()
                        || self.extras.is_empty().not()
                    {
                        "; and "
                    } else {
                        ""
                    },
                    pos = self.token_position
                )?
            }

            write!(f, r#"""#)
        }
    }
}

use itertools::Itertools;
use std::fmt::Display;
use std::ops::Not;

#[derive(Default)]
pub struct Condition<'a> {
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

impl Position {
    pub fn get_value(&self) -> Option<usize> {
        match *self {
            Position::Any => None,
            Position::Eq(v) => Some(v),
            Position::Ne(v) => Some(v),
            Position::Gt(v) => Some(v),
            Position::Ge(v) => Some(v),
            Position::Lt(v) => Some(v),
            Position::Le(v) => Some(v),
        }
    }
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

impl std::ops::Sub<usize> for Position {
    type Output = Self;

    fn sub(self, rhs: usize) -> Self::Output {
        match self {
            Position::Any => Position::Any,
            Position::Eq(n) => Position::Eq(n.checked_sub(rhs).unwrap_or_default()),
            Position::Ne(n) => Position::Ne(n.checked_sub(rhs).unwrap_or_default()),
            Position::Gt(n) => Position::Gt(n.checked_sub(rhs).unwrap_or_default()),
            Position::Ge(n) => Position::Ge(n.checked_sub(rhs).unwrap_or_default()),
            Position::Lt(n) => Position::Lt(n.checked_sub(rhs).unwrap_or_default()),
            Position::Le(n) => Position::Le(n.checked_sub(rhs).unwrap_or_default()),
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

pub trait Codegen {
    fn generate(&self) -> String;
}

pub struct Command<'a> {
    pub condition: Condition<'a>,
    pub prog: (&'a str, &'a str),
}

impl<'a> Display for Command<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.condition)?;
        writeln!(f, r#" -ka {} -d "{}""#, self.prog.0, self.prog.1)?;

        Ok(())
    }
}

#[derive(Default)]
pub struct Help<'a> {
    pub condition: Condition<'a>,
    pub help: (char, &'a str, &'a str),
}

impl<'a> Display for Help<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let condition = Condition {
            token_position: self.condition.token_position - 1,
            ..self.condition
        };
        writeln!(
            f,
            r#"{condition} -s {short} -l {long} -d "{desc}""#,
            condition = self.condition,
            short = self.help.0,
            long = self.help.1,
            desc = self.help.2.replace('"', "'")
        )
    }
}

#[derive(Default)]
pub struct File<'a> {
    pub condition: Condition<'a>,
}

impl<'a> Display for File<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} -F", self.condition)
    }
}

#[derive(Default)]
pub struct Prog<'a> {
    pub condition: Condition<'a>,
}

#[derive(Default)]
pub struct Map<'a> {
    pub condition: Condition<'a>,
}

#[derive(Default)]
pub struct Path<'a> {
    pub condition: Condition<'a>,
    pub extensions: &'a [&'static str],
    pub source: Option<&'a str>,
}

impl<'a> Display for Path<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            Condition {
                extras: &["not __fish_should_complete_switches",],
                ..self.condition
            }
        )?;

        writeln!(
            f,
            " -f -x -a \"(__fish_bpftool_complete_file {source} {filter})\"",
            source = self
                .source
                .map(|s| format!("--source='{s}'"))
                .unwrap_or_default(),
            filter = self
                .extensions
                .is_empty()
                .not()
                .then(|| format!("--filters='|{}'", &self.extensions.join("|")))
                .unwrap_or_default()
        )?;

        Ok(())
    }
}

impl<'a> Display for Map<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let selectors = ["id" /* "pinned" */];
        for selector in selectors {
            write!(f, "{}", Condition { ..self.condition })?;
            writeln!(f, " -a {selector}", selector = selector)?;
        }

        for selector in selectors {
            write!(
                f,
                "{}",
                Condition {
                    parents: &self
                        .condition
                        .parents
                        .iter()
                        .chain([selector].iter())
                        .copied()
                        .collect_vec(),
                    token_position: self.condition.token_position + 1,
                    extras: &[
                        "__fish_bpftool_prog_profile_needs_completion",
                        &format!(
                            "test (__fish_bpftool_get_last_token) = '{selector}'",
                            selector = selector,
                        )
                    ],
                    ..self.condition
                }
            )?;
            writeln!(
                f,
                " -ka '(__fish_bpftool_complete_map_{selector})'",
                selector = selector
            )?;
        }

        Ok(())
    }
}

impl<'a> Display for Prog<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let selectors = ["id", "tag", "name" /* "pinned" */];
        for selector in selectors {
            write!(f, "{}", Condition { ..self.condition })?;
            writeln!(f, " -a {selector}", selector = selector)?;
        }

        for selector in selectors {
            write!(
                f,
                "{}",
                Condition {
                    parents: &self
                        .condition
                        .parents
                        .iter()
                        .chain([selector].iter())
                        .copied()
                        .collect_vec(),
                    token_position: self.condition.token_position + 1,
                    extras: &[
                        "__fish_bpftool_prog_profile_needs_completion",
                        &format!(
                            "test (__fish_bpftool_get_last_token) = '{selector}'",
                            selector = selector,
                        )
                    ],
                    ..self.condition
                }
            )?;
            writeln!(
                f,
                " -ka '(__fish_bpftool_complete_progs_{selector})'",
                selector = selector
            )?;
        }

        Ok(())
    }
}

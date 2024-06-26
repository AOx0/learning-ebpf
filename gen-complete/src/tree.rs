use crate::codegen;
use crate::codegen::Codegen;
use itertools::Itertools;
use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::rc::{Rc, Weak};

#[derive(Clone, Default)]
pub struct ArgInfo {
    parent: RefCell<Weak<Command>>,
    position: RefCell<codegen::Position>,
}

impl ArgInfo {
    fn new(parent: RefCell<Weak<Command>>) -> Self {
        ArgInfo {
            parent,
            ..Default::default()
        }
    }

    fn get_position(&self) -> codegen::Position {
        *self.position.borrow()
    }

    fn get_parent(&self) -> Rc<Command> {
        self.parent.borrow().upgrade().unwrap()
    }
}

#[derive(Clone)]
pub enum Args {
    // Repeatable(Rc<Arg>),
    Lit(&'static str),
    DLit(&'static str, &'static str),
    Prog,
    Map,
    Path,
    PathO,
    PathBpffs,
    Event(&'static str, &'static str),
    OneOf(Vec<Args>),
    Sequential(Vec<Args>),
}

impl AArgs {
    fn from(value: Args, parent: RefCell<Weak<Command>>) -> Self {
        match value {
            Args::Lit(lit) => AArgs::Lit(ArgInfo::new(parent), lit),
            Args::Prog => AArgs::Prog(ArgInfo::new(parent)),
            Args::Map => AArgs::Map(ArgInfo::new(parent)),
            Args::Path => AArgs::Path(ArgInfo::new(parent)),
            Args::PathO => AArgs::PathO(ArgInfo::new(parent)),
            Args::PathBpffs => AArgs::PathBpffs(ArgInfo::new(parent)),
            Args::Event(name, fun) => AArgs::Event(ArgInfo::new(parent), name, fun),
            Args::OneOf(variants) => {
                let variants = variants
                    .into_iter()
                    .map(|a| AArgs::from(a, parent.clone()))
                    .collect_vec();
                AArgs::OneOf(ArgInfo::new(parent), variants)
            }
            Args::Sequential(seq) => {
                let seq = seq
                    .into_iter()
                    .map(|a| AArgs::from(a, parent.clone()))
                    .collect_vec();
                AArgs::Sequential(ArgInfo::new(parent), seq)
            }
            Args::DLit(lit, docs) => AArgs::DLit(ArgInfo::new(parent), lit, docs),
        }
    }
}

#[derive(Clone)]
pub enum AArgs {
    Repeatable(ArgInfo, Rc<AArgs>),
    Lit(ArgInfo, &'static str),
    DLit(ArgInfo, &'static str, &'static str),
    Prog(ArgInfo),
    Map(ArgInfo),
    Path(ArgInfo),
    PathBpffs(ArgInfo),
    PathO(ArgInfo),
    Event(ArgInfo, &'static str, &'static str),
    OneOf(ArgInfo, Vec<AArgs>),
    Sequential(ArgInfo, Vec<AArgs>),
}

impl AArgs {
    fn get_info(&self) -> &ArgInfo {
        match self {
            AArgs::Lit(info, _) => info,
            AArgs::Prog(info) => info,
            AArgs::Map(info) => info,
            AArgs::Path(info) => info,
            AArgs::PathO(info) => info,
            AArgs::Event(info, _, _) => info,
            AArgs::OneOf(info, _) => info,
            AArgs::Sequential(info, _) => info,
            AArgs::Repeatable(info, _) => info,
            AArgs::DLit(info, _, _) => info,
            AArgs::PathBpffs(info) => info,
        }
    }
}

impl Codegen for AArgs {
    fn generate(&self) -> String {
        match self {
            AArgs::Lit(info, lit) => codegen::Command {
                condition: codegen::Condition {
                    parents: &info.get_parent().get_parents_with_self(),
                    token_position: info.get_position(),

                    ..Default::default()
                },
                prog: (lit, ""),
            }
            .to_string(),
            AArgs::Prog(info) => codegen::Prog {
                condition: codegen::Condition {
                    parents: &info.get_parent().get_parents_with_self(),
                    token_position: info.get_position(),
                    ..Default::default()
                },
            }
            .to_string(),
            AArgs::Map(info) => codegen::Map {
                condition: codegen::Condition {
                    parents: &info.get_parent().get_parents_with_self(),
                    token_position: info.get_position(),
                    ..Default::default()
                },
            }
            .to_string(),
            AArgs::Path(info) => codegen::Path {
                condition: codegen::Condition {
                    parents: &info.get_parent().get_parents_with_self(),
                    token_position: info.get_position(),
                    ..Default::default()
                },
                ..Default::default()
            }
            .to_string(),
            AArgs::PathO(info) => codegen::Path {
                condition: codegen::Condition {
                    parents: &info.get_parent().get_parents_with_self(),
                    token_position: info.get_position(),
                    ..Default::default()
                },
                extensions: &["\\.o"],
                ..Default::default()
            }
            .to_string(),
            AArgs::PathBpffs(info) => codegen::Path {
                condition: codegen::Condition {
                    parents: &info.get_parent().get_parents_with_self(),
                    token_position: info.get_position(),
                    ..Default::default()
                },
                source: Some("/sys/fs/bpf/"),
                ..Default::default()
            }
            .to_string(),
            AArgs::Event(_, _, _) => todo!(),
            AArgs::OneOf(info, variants) => {
                let mut res = String::new();
                for variant in variants {
                    let var_info = variant.get_info();
                    *var_info.position.borrow_mut() = info.get_position();
                    res += &variant.generate();
                }

                res
            }
            AArgs::Sequential(info, seq) => {
                let mut res = String::new();
                let mut contador = Some(info.get_position());
                let mut last = info.get_position();

                for arg in seq.iter() {
                    // Emit absolute position while possible
                    if let Some(c) = contador {
                        *arg.get_info().position.borrow_mut() = c;
                        contador = if let Some(len) = arg.get_token_size() {
                            last = c + len;
                            Some(last)
                        } else {
                            None
                        };
                    } else {
                        *arg.get_info().position.borrow_mut() =
                            codegen::Position::Gt(last.get_value().unwrap());
                    }

                    res += &arg.generate();
                }

                res
            }
            AArgs::Repeatable(_, _) => todo!(),
            AArgs::DLit(info, lit, doc) => codegen::Command {
                condition: codegen::Condition {
                    parents: &info.get_parent().get_parents_with_self(),
                    token_position: info.get_position(),

                    ..Default::default()
                },
                prog: (lit, doc),
            }
            .to_string(),
        }
    }
}

impl AArgs {
    fn get_token_size(&self) -> Option<usize> {
        match self {
            AArgs::Lit(_, _) => Some(1),
            AArgs::Prog(_) => Some(2),
            AArgs::Map(_) => Some(2),
            AArgs::Path(_) => Some(1),
            AArgs::PathO(_) => Some(1),
            AArgs::Event(_, _, _) => Some(2),
            AArgs::OneOf(_, seq) => {
                let sizes = seq
                    .iter()
                    .map(|arg| arg.get_token_size())
                    .collect::<HashSet<Option<usize>>>();

                if sizes.len() == 1 {
                    sizes.iter().flatten().next().copied()
                } else {
                    None
                }
            }
            AArgs::Sequential(_, seq) => seq.iter().map(|arg| arg.get_token_size()).sum(),
            AArgs::Repeatable(_, _) => None,
            AArgs::DLit(_, _, _) => Some(1),
            AArgs::PathBpffs(_) => Some(1),
        }
    }
}

pub struct Command {
    pub name: &'static str,
    pub description: &'static str,
    pub parent: RefCell<Weak<Command>>,
    pub children: RefCell<Vec<Rc<Command>>>,
    pub flags: RefCell<Vec<(char, &'static str, &'static str)>>,
    pub include_in_codegen: bool,
    pub args: RefCell<Option<Args>>,
    pub aargs: RefCell<Option<AArgs>>,
}

impl Command {
    pub fn rcd(name: &'static str, description: &'static str) -> Rc<Self> {
        Rc::new(Self {
            name,
            description,
            ..Default::default()
        })
    }

    pub fn set_children_parents(self: &Rc<Self>) {
        for child in self.children.borrow().iter() {
            child.set_parent(self);
            child.set_children_parents();
        }
    }

    pub fn with_flags(self: Rc<Self>, help: &[(char, &'static str, &'static str)]) -> Rc<Self> {
        self.flags.borrow_mut().extend_from_slice(help);
        self
    }

    pub fn with_args(self: Rc<Self>, args: &[Args]) -> Rc<Self> {
        let args = Args::Sequential(args.to_vec());

        *self.args.borrow_mut() = Some(args);
        self
    }

    pub fn setup_args(self: &Rc<Self>) {
        if let Some(args) = self.args.borrow_mut().take() {
            let aargs = AArgs::from(args, RefCell::new(Rc::downgrade(&self)));
            *aargs.get_info().position.borrow_mut() =
                codegen::Position::Eq(self.get_parents_with_self().len() + 1);
            *self.aargs.borrow_mut() = Some(aargs);
        }

        for chid in self.children.borrow().iter() {
            chid.setup_args();
        }
    }

    pub fn with_children(self: Rc<Self>, children: &[Rc<Command>]) -> Rc<Self> {
        self.children.borrow_mut().extend_from_slice(children);
        self
    }

    pub fn set_parent(&self, parent: &Rc<Self>) {
        *self.parent.borrow_mut() = Rc::downgrade(parent);
    }

    pub fn to_rc(self) -> Rc<Self> {
        Rc::new(self)
    }

    pub fn get_parents(&self) -> Vec<&'static str> {
        let mut parents = VecDeque::new();
        let mut curr = self.parent.borrow().upgrade();

        while let Some(parent) = curr {
            if parent.include_in_codegen {
                parents.push_front(parent.name);
            }
            curr = parent.parent.borrow().upgrade();
        }

        parents.into_iter().collect_vec()
    }

    pub fn get_parents_with_self(&self) -> Vec<&'static str> {
        let mut parents = VecDeque::from_iter([self.name]);
        let mut curr = self.parent.borrow().upgrade();

        while let Some(parent) = curr {
            if parent.include_in_codegen {
                parents.push_front(parent.name);
            }
            curr = parent.parent.borrow().upgrade();
        }

        parents.into_iter().collect_vec()
    }

    pub fn get_level(&self) -> usize {
        let mut level = 0;
        let mut curr = self.parent.borrow().upgrade();

        while let Some(parent) = curr {
            level += 1;
            curr = parent.parent.borrow().upgrade();
        }

        level
    }
}

impl Default for Command {
    fn default() -> Self {
        Self {
            name: "",
            description: "",
            children: RefCell::default(),
            parent: RefCell::default(),
            flags: RefCell::default(),
            include_in_codegen: true,
            args: RefCell::default(),
            aargs: RefCell::default(),
        }
    }
}

impl From<(&'static str, &'static str)> for Command {
    fn from((name, description): (&'static str, &'static str)) -> Self {
        Self {
            name: name.to_string().leak(),
            description: description.to_string().leak(),
            ..Default::default()
        }
    }
}

impl Codegen for Command {
    fn generate(&self) -> String {
        let mut res = String::new();

        for help in self.flags.borrow().iter().copied() {
            res += &codegen::Help {
                help,
                condition: codegen::Condition {
                    parents: &self.get_parents(),
                    token_position: codegen::Position::Eq(self.get_level()),
                    ..Default::default()
                },
            }
            .to_string();
        }

        if self.include_in_codegen {
            res += &codegen::Command {
                condition: codegen::Condition {
                    parents: &self.get_parents(),
                    token_position: codegen::Position::Eq(self.get_level()),
                    ..Default::default()
                },
                prog: (self.name, self.description),
            }
            .to_string();

            res += &self
                .aargs
                .borrow()
                .as_ref()
                .map(|args| args.generate())
                .unwrap_or_default();
        }

        for child in self.children.borrow().iter().rev() {
            res += &child.generate();
        }

        res
    }
}

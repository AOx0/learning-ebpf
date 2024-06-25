use crate::codegen;
use crate::codegen::Codegen;
use itertools::Itertools;
use std::borrow::{Borrow, BorrowMut};
use std::cell::{RefCell, RefMut};
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::{Rc, Weak};

#[derive(Clone, Default)]
pub struct ArgInfo {
    parent: RefCell<Weak<Command>>,
    fixed_position: RefCell<codegen::Position>,
}

impl ArgInfo {
    fn new(parent: RefCell<Weak<Command>>) -> Self {
        ArgInfo {
            parent,
            ..Default::default()
        }
    }

    fn get_parent_mut(&self) -> RefMut<'_, Weak<Command>> {
        self.parent.borrow_mut()
    }

    fn get_parent(&self) -> Rc<Command> {
        self.parent.borrow().upgrade().unwrap()
    }
}

#[derive(Clone)]
pub enum Args {
    // Repeatable(Rc<Arg>),
    Lit(&'static str),
    Prog,
    Map,
    Path,
    Path_o,
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
            Args::Path_o => AArgs::PathO(ArgInfo::new(parent)),
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
        }
    }
}

#[derive(Clone)]
pub enum AArgs {
    // Repeatable(Rc<Arg>),
    Lit(ArgInfo, &'static str),
    Prog(ArgInfo),
    Map(ArgInfo),
    Path(ArgInfo),
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
        }
    }
}

impl Codegen for AArgs {
    fn generate(&self) -> String {
        match self {
            AArgs::Lit(info, lit) => codegen::Command {
                condition: codegen::Condition {
                    parents: &info.get_parent().get_parents_with_self(),
                    token_position: *info.fixed_position.borrow(),

                    ..Default::default()
                },
                prog: (lit, ""),
            }
            .to_string(),
            AArgs::Prog(info) => codegen::Prog {
                condition: codegen::Condition {
                    parents: &info.get_parent().get_parents_with_self(),
                    token_position: *info.fixed_position.borrow(),
                    ..Default::default()
                },
                allow_repetition: true,
            }
            .to_string(),
            AArgs::Map(info) => codegen::Map {
                condition: codegen::Condition {
                    parents: &info.get_parent().get_parents_with_self(),
                    token_position: *info.fixed_position.borrow(),
                    ..Default::default()
                },
                allow_repetition: true,
            }
            .to_string(),
            AArgs::Path(_) => todo!(),
            AArgs::PathO(_) => todo!(),
            AArgs::Event(_, _, _) => todo!(),
            AArgs::OneOf(info, variants) => {
                let mut res = String::new();
                for variant in variants {
                    let var_info = variant.get_info();
                    *var_info.fixed_position.borrow_mut() = *info.fixed_position.borrow();
                    res += &variant.generate();
                }

                res
            }
            AArgs::Sequential(info, seq) => {
                let mut res = String::new();
                let mut contador = info.parent.borrow().upgrade().unwrap().get_level() + 1;

                for arg in seq.iter() {
                    *arg.get_info().fixed_position.borrow_mut() = codegen::Position::Eq(contador);
                    contador += arg.get_token_size();
                    res += &arg.generate();
                }

                res
            }
        }
    }
}

impl AArgs {
    fn get_token_size(&self) -> usize {
        match self {
            AArgs::Lit(_, _) => 1,
            AArgs::Prog(_) => 2,
            AArgs::Map(_) => 2,
            AArgs::Path(_) => 1,
            AArgs::PathO(_) => 1,
            AArgs::Event(_, _, _) => 2,
            AArgs::OneOf(_, seq) => {
                let sizes = seq
                    .iter()
                    .map(|arg| arg.get_token_size())
                    .collect::<HashSet<usize>>();

                assert!(
                    sizes.len() == 1,
                    "Error: El tamaño de las variants debe ser el mismo"
                );

                *sizes.iter().next().unwrap()
            }
            AArgs::Sequential(_, seq) => seq.iter().map(|arg| arg.get_token_size()).sum(),
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
    pub args: RefCell<Option<AArgs>>,
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
        let aargs = AArgs::from(args, RefCell::new(Rc::downgrade(&self)));

        *self.args.borrow_mut() = Some(aargs);
        self
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
                .args
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

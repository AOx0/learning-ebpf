use crate::codegen;
use crate::codegen::Codegen;
use itertools::Itertools;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::{Rc, Weak};

pub struct Command {
    pub name: &'static str,
    pub description: &'static str,
    pub parent: RefCell<Weak<Command>>,
    pub children: Vec<Rc<Command>>,
    pub help: RefCell<Vec<(char, &'static str, &'static str)>>,
    pub include_in_codegen: bool,
}

impl Command {
    pub fn new(name: &'static str, description: &'static str, children: Vec<Rc<Command>>,
    ) -> Self {
        Self {
            name,
            description,
            children,
            ..Default::default()
        }
    }

    pub fn rcd(
        name: &'static str,
        description: &'static str,
        children: Vec<Rc<Command>>,
    ) -> Rc<Self> {
        Rc::new(Self::new(name, description, children))
    }

    pub fn set_children_parents(self: &Rc<Self>) {
        for child in &self.children {
            child.set_parent(self);
            child.set_children_parents();
        }
    }

    pub fn with_help(self: Rc<Self>, help: &[(char, &'static str, &'static str)]) -> Rc<Self> {
        self.help.borrow_mut().extend_from_slice(help);
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
            children: Vec::new(),
            include_in_codegen: true,
            parent: RefCell::new(Weak::default()),
            help: RefCell::new(Vec::new()),
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
        
        for help in self.help.borrow().iter().copied() {
            res += &codegen::Help {
                help,
                condition: codegen::Condition {
                    parents: &self.get_parents(),
                    token_position: codegen::Position::Eq(self.get_level()),
                    ..Default::default()
                },
            }.to_string();
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
        }

        for child in self.children.iter().rev() {
            res += &child.generate();
        }

        res
    }
}

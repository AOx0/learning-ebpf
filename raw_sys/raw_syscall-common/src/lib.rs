#![no_std]

use core::fmt::Debug;

#[repr(C)]
pub struct Args {
    pub ptr: u64,
    pub op: u64,
}

impl Debug for Args {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Reg {{ ptr: 0x{ptr:x}, op: {op} }}",
            ptr = self.ptr,
            op = self.op
        )
    }
}

#![no_std]

use core::fmt::Debug;

use bstr::ByteSlice;

#[repr(C)]
pub struct Data {
    pub uid: u32,
    pub pid: u32,
    pub command: [u8; 16],
    pub message: [u8; 11],
    pub path: [u8; 64],
}

impl Debug for Data {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{uid: <6} {pid: <6} msg: \"{msg}\", cmd: \"{cmd}\", path: \"{path}\"",
            uid = self.uid,
            pid = self.pid,
            msg = self.message.as_bstr(),
            cmd = self.command.as_bstr(),
            path = self.path.as_bstr()
        )
    }
}

#![no_std]
pub struct Data {
    pub pid: u32,
    pub uid : u32,
    pub command: [u8; 16],
    pub message: [u8; 12]
}
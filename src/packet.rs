//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Repr<T: AsRef<[u8]>> {
	pub spi: u32,
	pub seq: u32,
	pub payload: T,
	pub next_header: u8,
}

mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;

    pub const SRC_PORT: Field = 0..2;
    pub const DST_PORT: Field = 2..4;

    pub const LENGTH: Field = 4..6;
    pub const CHECKSUM: Field = 6..8;

    pub const fn PAYLOAD(length: u16) -> Field {
        CHECKSUM.end..(length as usize)
    }
}

impl<T: AsRef<[u8]>> Packet<T> {
	
}

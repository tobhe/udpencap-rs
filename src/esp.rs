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

use crate::util::{Error, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use crypto::aead::{AeadInPlace, Nonce};
use std::convert::TryInto;

// XXX: Dirty Hack
const AUTH_DATA_SIZE: usize = 16;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Repr {
    pub spi: u32,
    pub seq: u32,
    pub next_header: u8,
}

#[allow(non_snake_case)]
mod field {
    pub type Field = ::core::ops::Range<usize>;

    pub const SPI: Field = 0..4;
    pub const SEQ: Field = 4..8;
    pub const IV: Field = 8..16;

    pub const fn NEXT_HEADER(len: usize) -> Field {
        (len - 1)..len
    }

    pub const fn PAD_LENGTH(len: usize) -> Field {
        (len - 2)..(len - 1)
    }

    pub const fn CIPHER_TEXT(len: usize) -> Field {
        16..len
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    buffer: Bytes,
}

#[derive(Debug, Clone)]
pub struct EncryptedPacket {
    buffer: Bytes,
}

impl EncryptedPacket {
    pub fn new_unchecked(buffer: Bytes) -> EncryptedPacket {
        EncryptedPacket { buffer }
    }

    pub fn new_checked(buffer: Bytes) -> Result<EncryptedPacket> {
        let packet = Self::new_unchecked(buffer);
        Ok(packet)
    }

    pub fn into_inner(self) -> Bytes {
        self.buffer
    }

    pub fn spi(&self) -> u32 {
        self.buffer.slice(field::SPI).get_u32()
    }

    pub fn sequence(&self) -> u32 {
        self.buffer.slice(field::SEQ).get_u32()
    }

    pub fn iv(&self) -> [u8; 8] {
        self.buffer.slice(field::IV).as_ref().try_into().unwrap()
    }

    pub fn cipher_text(&self) -> Bytes {
        self.buffer.slice(field::CIPHER_TEXT(self.buffer.len()))
    }

    pub fn decrypt<T>(self, aead: &T, salt: [u8; 4]) -> Result<Packet>
    where
        T: AeadInPlace,
    {
        let mut packet = BytesMut::with_capacity(16 + self.cipher_text().len() + AUTH_DATA_SIZE);
        packet.put_u32(self.spi());
        packet.put_u32(self.sequence());

        let mut crypt_buffer = self.cipher_text().as_ref().to_vec();
        let iv = self.iv();
        packet.extend_from_slice(&self.iv());
        let nonce_material = [
            salt[0], salt[1], salt[2], salt[3], iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6],
            iv[7],
        ];
        let nonce = Nonce::<T>::from_slice(&nonce_material);

        println!("crypt_buffer: {:x?}", crypt_buffer);
        println!("nonce: {:x?}", nonce);

        aead.decrypt_in_place(&nonce, b"", &mut crypt_buffer)
            .map_err(|_| Error::DecryptionFailure)?;
        println!("cipher_dec: {:x?}", crypt_buffer);
        packet.extend_from_slice(&crypt_buffer);
        Packet::new_checked(packet.freeze())
    }
}

impl Packet {
    pub fn new_unchecked(buffer: Bytes) -> Packet {
        Packet { buffer }
    }

    pub fn new_checked(buffer: Bytes) -> Result<Packet> {
        let packet = Self::new_unchecked(buffer);
        println!("pad_len: {:?}", packet.pad_length());
        if packet.pad_length() as usize > packet.buffer.len() - 16 - AUTH_DATA_SIZE {
            return Err(Error::InvalidLength);
        }

        for (pad_val, should_val) in packet.padding().iter().zip(1..=packet.pad_length()) {
            if *pad_val != should_val {
                return Err(Error::InvalidPadding);
            }
        }

        Ok(packet)
    }

    pub fn spi(&self) -> u32 {
        self.buffer.slice(field::SPI).get_u32()
    }

    pub fn sequence(&self) -> u32 {
        self.buffer.slice(field::SEQ).get_u32()
    }

    pub fn next_header(&self) -> u8 {
        self.buffer
            .slice(field::NEXT_HEADER(self.buffer.len()))
            .get_u8()
    }

    pub fn pad_length(&self) -> u8 {
        self.buffer
            .slice(field::PAD_LENGTH(self.buffer.len()))
            .get_u8()
    }

    pub fn padding(&self) -> Bytes {
        let pad = field::PAD_LENGTH(self.buffer.len());
        self.buffer
            .slice((pad.start - self.pad_length() as usize)..pad.end)
    }

    pub fn payload(&self) -> Bytes {
        let pad = field::PAD_LENGTH(self.buffer.len());
        self.buffer
            .slice(16..pad.start - (self.pad_length() as usize))
    }
}

impl Repr {
    pub fn new(spi: u32, sequence: u32, next_header: u8) -> Self {
        Repr {
            spi,
            seq: sequence,
            next_header,
        }
    }

    pub fn parse(enc: EncryptedPacket, aead: &impl AeadInPlace, salt: [u8; 4]) -> Result<Repr> {
        let decrypted = enc.decrypt(aead, salt)?;

        Ok(Repr {
            spi: decrypted.spi(),
            seq: decrypted.sequence(),
            next_header: decrypted.next_header(),
        })
    }

    pub fn emit<T>(
        &self,
        payload_len: usize,
        emit_payload: impl FnOnce(&mut Vec<u8>),
        aead: &T,
        iv: [u8; 8],
        salt: [u8; 4],
    ) -> Result<EncryptedPacket>
    where
        T: AeadInPlace,
    {
        let mut packet = BytesMut::with_capacity(16 + payload_len + AUTH_DATA_SIZE);
        packet.put_u32(self.spi);
        packet.put_u32(self.seq);
        packet.extend_from_slice(&iv);

        let mut payload_buffer = Vec::with_capacity(payload_len);
        emit_payload(&mut payload_buffer);
        let pad_len = (payload_buffer.len() + 2) % 4;
        for pad in 1..=pad_len {
            payload_buffer.put_u8(pad as u8);
        }
        payload_buffer.put_u8(pad_len as u8);
        payload_buffer.put_u8(self.next_header as u8);

        let nonce_material = [
            salt[0], salt[1], salt[2], salt[3], iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6],
            iv[7],
        ];
        let nonce = Nonce::<T>::from_slice(&nonce_material);

        println!("payload_buffer: {:x?}", payload_buffer);
        println!("nonce: {:x?}", nonce);
        aead.encrypt_in_place(&nonce, b"", &mut payload_buffer)
            .map_err(|_| Error::EncryptionFailure)?;

        println!("cipher_enc: {:x?}", payload_buffer);

        packet.extend_from_slice(&payload_buffer);

        println!("packet: {:x?}", packet);

        Ok(EncryptedPacket {
            buffer: packet.freeze(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use aes_gcm::NewAead;

    #[test]
    fn encrypt_decrypt_inverse() {
        let data = Vec::from("Hello World I am around".as_bytes());
        let repr = Repr::new(1, 1, 4);

        let key = aes_gcm::Key::from_slice(b"abcdefghijklopqr");
        let aes = aes_gcm::Aes128Gcm::new(key);
        let salt = [0, 0, 0, 0];
        let encrypted = repr
            .emit(
                data.len(),
                |vec| vec.extend_from_slice(&data),
                &aes,
                [0, 0, 0, 0, 0, 0, 0, 1],
                salt,
            )
            .unwrap();
        let enc2 = encrypted.clone();
        println!("{:x?}", encrypted.buffer);
        let decrypted = encrypted.decrypt(&aes, salt).unwrap();
        assert_eq!(data, decrypted.payload());

        let repr2 = Repr::parse(enc2, &aes, salt).unwrap();
        assert_eq!(repr, repr2);
    }
}

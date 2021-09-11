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

use crate::esp::{EncryptedPacket, Packet, Repr};
use aes_gcm::NewAead;
use bytes::BytesMut;
use mio::net::UdpSocket;
use mio::{unix::SourceFd, Events, Interest, Poll, Token};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::time::Duration;
use tun::{Configuration, Device};

// mod packet;
mod esp;
mod util;

const UDP: Token = Token(0);
const TUN: Token = Token(1);

fn main() {
    let key = aes_gcm::Key::from_slice(b"abcdefghijklopqr");
    let aes = aes_gcm::Aes128Gcm::new(key);
    let salt = [0, 0, 0, 0];

    let mut config = Configuration::default();

    config
        .address((172, 16, 0, 1))
        .netmask((255, 255, 0, 0))
        .destination((172, 16, 0, 2))
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    let mut tun = tun::create(&config).unwrap();
    let tun_mtu = tun.mtu().unwrap() as usize;
    let mut socket = UdpSocket::bind("0.0.0.0:0".parse().unwrap()).unwrap();
    let peer_address = "10.1.0.47:12349".parse().unwrap();

    let mut poll = Poll::new().unwrap();
    poll.registry()
        .register(&mut SourceFd(&tun.as_raw_fd()), TUN, Interest::READABLE)
        .unwrap();
    poll.registry()
        .register(&mut socket, UDP, Interest::READABLE)
        .unwrap();
    let mut events = Events::with_capacity(128);

    loop {
        poll.poll(&mut events, Some(Duration::from_millis(10)))
            .unwrap();
        for event in events.iter() {
            if event.is_error() {
                println!("Error: {:?}", event);
                continue;
            }

            match event.token() {
                UDP if event.is_readable() => {
                    let mut buf = BytesMut::with_capacity(tun_mtu);
                    let num_recv = socket.recv(&mut buf).unwrap();
                    if (num_recv == 0) {
                        println!("recv 0");
                        continue;
                    }
                    let buf = buf.freeze();
                    let encrypted_packet =
                        EncryptedPacket::new_checked(buf.slice(4..num_recv)).unwrap();
                    let decrypted_packet = encrypted_packet.decrypt(&aes, salt).unwrap();
                    tun.write(&decrypted_packet.payload()).unwrap();
                }
                TUN if event.is_readable() => {
                    let mut buf = Vec::with_capacity(tun_mtu);
                    let num_recv = tun.read(&mut buf).unwrap();
                    let repr = Repr::new(1, 1, 4);
                    let encrypted_packet = repr
                        .emit(
                            num_recv,
                            |vec| vec.extend_from_slice(&buf[0..num_recv]),
                            &aes,
                            [0, 0, 0, 0, 0, 0, 0, 1],
                            salt,
                        )
                        .unwrap();
                    socket
                        .send_to(&encrypted_packet.into_inner(), peer_address)
                        .unwrap();
                }
                _ => {
                    println!("Other event: {:?}", event);
                }
            }
        }
    }
}

extern crate pnet;

use pnet::packet::{MutablePacket, Packet};
use pnet::packet::icmp::echo_reply;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::packet::icmp::{echo_request::MutableEchoRequestPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols::Icmp;
use pnet::transport::{TransportChannelType, transport_channel, icmp_packet_iter};
// use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType};
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::time::Duration;

fn main() {
    let (mut tx, mut rx) = 
    match transport_channel(1500, TransportChannelType::Layer4(Ipv4(Icmp))) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("An error occurred when creating transport channel: {}", e),
    };
    let mut payload = [0u8;43];
    let dst = "114.114.114.114".parse::<Ipv4Addr>().unwrap();
    let mut recv = icmp_packet_iter(&mut rx);

    thread::spawn(move || {

        let mut seq = 10000;
        loop {
            thread::sleep(Duration::from_secs(1));
            
            let mut ping = MutableEchoRequestPacket::new(&mut payload).unwrap();
            ping.set_icmp_type(IcmpTypes::EchoRequest);
            ping.set_identifier(0xbabe);
            ping.set_sequence_number(seq);
            ping.set_payload("I do success finally. /(ㄒoㄒ)/~~".as_bytes());
            seq = seq +1;
            let sum = pnet::util::checksum(&ping.packet_mut(),1);
            ping.set_checksum(sum);

            println!("ping packet {:#?}", ping);
            println!("Bytes sent: {}", tx.send_to(ping, IpAddr::V4(dst)).unwrap());
        }

    });

        loop {
        match recv.next() {
            Ok((pkt, addr)) => {
              match pkt.get_icmp_type(){
                IcmpTypes::EchoReply => {
                  let reply = echo_reply::EchoReplyPacket::new(pkt.packet());
                println!("from {} receive icmp reply {:#?}", addr, reply);
                }
                _ => {}
              }
            },
            Err(e) => eprintln!("Error: {} ", e),
        }

    }
}
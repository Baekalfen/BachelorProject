//
// Author: Mads Ynddal
// License: See LICENSE file
// GitHub: https://github.com/Baekalfen/BachelorProjekt.git
//

extern crate ifaces;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

extern crate chrono;
use chrono::{UTC};

extern crate pnet;
use pnet::util::{MacAddr};
use pnet::packet::{Packet};
use pnet::packet::ethernet::{MutableEthernetPacket, EthernetPacket, EtherTypes};
use pnet::datalink::{datalink_channel};
use pnet::datalink::DataLinkChannelType::{Layer2};
use pnet::util::{NetworkInterface, get_network_interfaces};

use std::collections::{HashMap};
use super::{Node, IPv4, IPv6};

// Proxy
use std::thread;
use std::net::{TcpStream, TcpListener, IpAddr};
use std::io::prelude::*;
// use mio::tcp::TcpStream;
use std::time::{Duration};
use bincode::rustc_serialize::{encode, decode};
use rustc_serialize::Encodable;
const PROXY_TIMEOUT : u64 = 10;


pub fn get_interfaces() -> (Vec<IPv4>, Vec<IPv6>){
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();

    for iface in ifaces::Interface::get_all().unwrap().into_iter() {
        match iface.addr{
            Some(ip) => match ip {
                SocketAddr::V4(addr) => {
                    if iface.name.starts_with("en") || iface.name.starts_with("eth"){
                        v4.push(addr.ip().octets());
                        println!("{}\t{:?}\t{:?}", iface.name, iface.kind, addr.ip());
                    }
                },
                SocketAddr::V6(addr) => {
                    if iface.name.starts_with("en") || iface.name.starts_with("eth"){
                        // v6.push(addr.ip().segments());

                        let mut arr = [0u8;16];
                        for (idx, element) in addr.ip().segments().iter().enumerate(){
                            // TODO: Check big/little endian
                            arr[idx*2] += (*element) as u8;
                            arr[idx*2+1] += ((*element) >> 8) as u8;
                        }
                        v6.push(arr);


                        println!("{}\t{:?}\t{:?}", iface.name, iface.kind, addr.ip());
                    }
                }
            },
            None => println!("{}\t{:?}\t IP not provided", iface.name, iface.kind)
        }
    }

    return (v4, v6);
}

fn arp_extract_source_ip(payload: &[u8]) -> [u8; 4]{
    //TODO: Fix when I found out how to take a slice and copy it correctly
    [payload[14], payload[15], payload[16], payload[17]]
    // payload[23..28]
}

fn handle_packet(interface_name: &str, ethernet: &EthernetPacket) -> Option<(MacAddr, [u8; 4])> {
    let our_mac = MacAddr(0xb8, 0xe8, 0x56, 0x4a, 0x63, 0x10);
    match ethernet.get_ethertype() {
        EtherTypes::Arp if ethernet.get_destination() == our_mac => {
            println!("[{}]: ARP packet: {} > {}; length: {}, ethertype: {:?}, sender: {:?}",
                interface_name,
                ethernet.get_source(),
                ethernet.get_destination(),
                ethernet.packet().len(),
                ethernet.get_ethertype(),
                arp_extract_source_ip(ethernet.payload())
            );
            Some((ethernet.get_source(), arp_extract_source_ip(&ethernet.payload())))
        },
        _ => None,
    }
}

pub fn scan_subnet() -> HashMap<MacAddr, [u8; 4]>{
    let iface_name = "en0";
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces : Vec<NetworkInterface>= get_network_interfaces();
    let interface : NetworkInterface = interfaces.into_iter()
                              .filter(interface_names_match)
                              .next()
                              .unwrap();

    // Create a channel to receive on
    let (mut tx, mut rx) = match datalink_channel(&interface, 0, 4096, Layer2) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("packetdump: unable to create channel: {}", e)
    };

    let mut packet = [0u8; 14+28];
    let mut arp_packet = MutableEthernetPacket::new(&mut packet[..]).unwrap();
    arp_packet.set_source(interface.mac.unwrap());
    // arp_packet.set_destination(MacAddr(0xe0,0x3f,0x49,0x07,0x37,0x50));
    arp_packet.set_destination(MacAddr(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF));
    arp_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_payload : Vec<u8> = vec![
        0x00, 0x01, // Ethernet
        0x08, 0x00, // IP protocol
        0x06,       // Hardware size
        0x04,       // Protocol size
        0x00, 0x01  // ARP opcode - request
        ];

    // arp_payload.extend(Vec::new(interface.mac.unwrap().to_primitive_values()));
    arp_payload.extend(vec![0xb8, 0xe8, 0x56, 0x4a, 0x63, 0x10]); // This computers MAC address
    arp_payload.extend(vec![10, 4, 6, 36]); // This computers IP
    // arp_payload.extend(vec![10, 67, 32, 86]); // This computers IP
    // According to RFC 5227: The 'target hardware address' field is ignored and SHOULD be set to all zeroes.
    arp_payload.extend(vec![0, 0, 0, 0, 0, 0]);
    arp_payload.extend(vec![10, 4, 6, 0]); // The masked subnet of the network
    // arp_payload.extend(vec![10, 67, 32, 0]); // The masked subnet of the network

    // 28 bytes

    for n in 1..255 { //255
        // We have to copy the payload, as set_payload consumes it
        arp_payload[27] = n;
        arp_packet.set_payload(arp_payload.clone());
        tx.send_to(&arp_packet.to_immutable(), None);
    }

    let start_time = UTC::now().timestamp();
    let timeout = 3;

    let mut found_mac = HashMap::new();

    let mut iter = rx.iter();
    loop {
        match iter.next() {
            Ok(packet) => {
                match handle_packet(&interface.name[..], &packet){
                    Some((mac, ip)) => found_mac.insert(mac, ip),
                    None => None
                };
            },
            Err(e) => panic!("packetdump: unable to receive packet:\n\t{}", e)
        }
        // println!("Next iteration");
        // We can't set a timeout for the .next() function, so we'll have to wait for a random
        // package and check if we are out of time
        if UTC::now().timestamp() - start_time > timeout{
            break;
        }
    }

    println!("{:?}", found_mac);
    return found_mac;
}

fn tunnel (thread_id : String, mut in_stream : TcpStream, mut out_stream : TcpStream){
    in_stream.set_read_timeout(Some(Duration::new(PROXY_TIMEOUT, 0))).unwrap();
    out_stream.set_write_timeout(Some(Duration::new(PROXY_TIMEOUT, 0))).unwrap();

    let mut buf = [0u8; 16_384];
    let mut timeout_counter = 0;
    loop{
        let bytes = match in_stream.read(&mut buf){
            Ok(b) if b != 0 => {
                b
            },
            Ok(_) => {
                println!("Tunnel thread closing: {}", thread_id);
                return;
            }
            Err(err) => {
                match err.kind() {
                    ::std::io::ErrorKind::WouldBlock => {
                        println!("Tunnel thread timedout: {}", thread_id);
                        return;
                    }
                    _ => panic!("Error in reading from stream:\n\t{:?} - {}\n\t{}",err.kind(), thread_id, err)
                }
            }
        };

        match out_stream.write(&mut buf[..bytes]){
            Ok(b) => {
                if b != bytes{
                    panic!("Mismatch in writing to TCP stream. {} Read {}, Wrote {}", thread_id, bytes, b);
                }
            }
            Err(err) => panic!("Error in writing to stream:\n\t{}\n\t{}", thread_id, err)
        }
    }
}

#[derive(RustcDecodable, RustcEncodable, Clone, Debug)]
pub struct TcpProxy{
    pub target_addr : String, // Includes port
    pub requesting_node : Node,
    pub target_node : Node
}

impl TcpProxy{
    pub fn start(self, listener : TcpListener){
        println!("Starting TcpProxy");
        let (mut requestee_stream, _) = match listener.accept(){
            Ok((stream, addr)) => (stream, addr),
            Err(err) => panic!("Error accepting client connection:\n\t{}", err)
        };
        println!("Connection established to requestee");

        // TODO: Verify the requestee_stream is connected to the requesting node

        let mut target_stream = match TcpStream::connect(&*self.target_addr){
            Ok(s) => s,
            Err(err) => panic!("Error initializing connection:\n\t{}", err)
        };
        println!("Connection established to target");


        println!("Spawning tunnel threads");
        let r_clone = requestee_stream.try_clone().unwrap();
        let t_clone = target_stream.try_clone().unwrap();
        let id = format!("{} requestee to target", self.target_addr);
        thread::Builder::new()
            .name(id.clone())
            .stack_size(32_768)
            .spawn(move|| {
                tunnel(
                    id,
                    r_clone,
                    t_clone
                );
            });

        let id = format!("{} target to requestee", self.target_addr);
        thread::Builder::new()
            .name(id.clone())
            .stack_size(32_768)
            .spawn(move|| {
                tunnel(
                    id,
                    target_stream,
                    requestee_stream
                );
            });
    }
}

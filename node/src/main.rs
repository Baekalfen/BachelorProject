//
// Author: Mads Ynddal
// License: See LICENSE file
// GitHub: https://github.com/Baekalfen/BachelorProjekt.git
//

use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket, SocketAddr};

mod node;
use node::*;

extern crate pnet;
extern crate chrono;
use chrono::{UTC};

extern crate bincode;
extern crate rustc_serialize;
extern crate rusqlite;
extern crate rand;
extern crate ifaces;


// Temp
use std::io::prelude::*;
use std::fs::File;


// Just for the spam test
use std::thread;
use std::time::{Duration,Instant};

fn main() {
    let operator_addrs : Vec<SocketAddr> = vec!(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 24822));

    // Open port receiving data. Could be reinitialized to use UPnP port change?
    let mut found_socket = None;
    let mut found_port = None;
    for p in node::DEFAULT_PORT..node::DEFAULT_PORT + node::PORT_RANGE{
         found_socket = match UdpSocket::bind(&*format!("0.0.0.0:{}", p)){ //TODO: Does this work with IPv6?
            Ok(sock) => {
                found_port = Some(p);
                println!("Using port: {}", found_port.unwrap());
                Some(sock)
            },
            Err(_) => continue
        };
        break;
    }
    let mut socket = found_socket.unwrap(); // Yes, it panics, if no address is bound

    // Enable operator state
    let is_operator : bool;
    if let Some(arg1) = env::args().nth(1) {
        println!("The first argument is {}", arg1);
        // This will panic, if we get an invalid arugment, which is fine
        match arg1.parse::<u8>().ok().unwrap(){
            1 => {
                is_operator = true;
            },
            _ => panic!("You cannot directly start a node in other states than operator.")
        }
    }
    else{
        is_operator = false;
    }

    // In a product, this should be generated and injected per customer. This isn't relevant yet.
    let domain : [u8; 4] = [0, 0, 0, 0];

    // General status and initialization of the node
    let (node, key, _computer_status, operator_nodes, db) = init_node(&domain, &mut socket, is_operator, found_port.unwrap());

    // Fill in with current system details
    let (v4, v6) = node::network_tools::get_interfaces();
    let node_info : NodeInfo = NodeInfo{
        domain : domain.clone(),                  // A value assigned to a company, to verify relations between nodes.
        pub_hash : key.pub_hash.clone(),     // public key hash of the node. This can be used to download the actual certificate from an operator.
        ipv4 : v4,
        ipv6 : v6,
        port : found_port.unwrap(),          // The open receiving port for the node
        super_node : false,
        tunnel_node : false,
        time_stamp : UTC::now().timestamp(), // Used for solving conflicts and finding newest entry
        node_signature : generate_guid(),
    };

    match db.insert_node_info(&node_info){
        Ok(()) => (),
        Err(err) => panic!("Couldn't insert node info into database. Can't continue.\n\t{}", err)
    }

    // for op in operator_nodes{
    for op in &operator_nodes{
        match send_node_info_to_operator(&node_info, &mut socket, &key, &node, &op, &db){
            Ok(()) => (),
            Err(err) => panic!("Couldn't send node info to operator. Can't continue\n\t{}", err)
        }
    }
    //TODO Verify the node_info is received, by doing a query towards the operators

    ////////////////////
    //
    // let command = Command::new_with_payload(CommandType::TunnelRequest, network_tools::TcpProxy{
    //     target_addr : "127.0.0.1:22".to_string(), // Includes port
    //     requesting_node : node.clone(),
    //     target_node : node.clone()
    // }).unwrap();

    // let packet = construct_message_packet(&node.domain, &node.pub_hash, &node, command, &key).unwrap();
    // let mut f = File::create("foo.bin").unwrap();
    // f.write(packet.as_slice());
    // panic!("sdifj");
    ////////////////////


    // Message loop
    socket.set_read_timeout(None);
    let mut buf = [0u8; 16*1024]; // 16k is arbitrary -- slight more than a max-sized UDP packet?


    // This is the spam test!
    if !is_operator{
        ::std::thread::sleep(Duration::new(2,0));

        let start = Instant::now();
        let start2 = start.clone();

        socket.set_read_timeout(Some(Duration::new(2, 0)));
        let mut socket2 = socket.try_clone().unwrap();

        let t = thread::Builder::new()
            .spawn(move|| {
                let op = operator_nodes[0].clone();
                // let cmd = command.clone();
                let cmd = Command::new(CommandType::Ping);
                // let cmd = Command::new(CommandType::GetNode);
                let packet = construct_message_packet(&op.domain, &op.pub_hash, &node, cmd, &key).unwrap();
                let mut src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192,168,1,5)), 24822);

                let mut counter = 0;
                // while counter < 1_000_000{
                while Instant::now().duration_since(start2).as_secs() < 10 {
                    // println!("sdffds");
                    send_udp_packet_to_src(&mut socket2, src, packet.clone()).unwrap();
                    counter += 1;
                    // ::std::thread::sleep(Duration::new(0,200));
                }
                println!("sent out: {}", counter);
            });

        let mut counter = 0;
        // let mut t = Instant::now();
        while Instant::now().duration_since(start).as_secs() < 12 {
        // loop{
            let mut buf = [0; 16*1024]; // 16k is arbitrary -- slight more than a max-sized UDP packet?
            match socket.recv_from(&mut buf){
                Ok(_) => {
                    if counter % 100 == 0{
                        // println!("{},{}",t.elapsed().as_secs(),t.elapsed().subsec_nanos());
                        // t = Instant::now();
                    }
                    counter += 1;
                },
                Err(error) => {
                    break;
                }
            };
        }
        println!("received: {}", counter);
    }
    else{
        loop {
            let (src, cmd, sender) = match receive_command(&mut socket, &node, &key, &db){
                Ok((src, cmd, node)) => (src, cmd, node),
                Err(error) => {
                    println!("Error receiving command: {}", error);
                    continue;
                }
            };
            // Execute the action
            match execute_command(cmd, &mut socket, src, &sender, &node, &key, &db, is_operator){
                Ok(()) => println!("Command served"),
                Err(err) => println!("Error handling command:\n\t{}", err)
            }

            // TODO: Exponentially increasing delay to avoid (accidental) DDoS using up CPU.
        }
    }
}

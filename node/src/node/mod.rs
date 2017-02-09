//
// Author: Mads Ynddal
// License: See LICENSE file
// GitHub: https://github.com/Baekalfen/BachelorProjekt.git
//

// Internal modules
mod DHT;
pub mod network_tools;

// External modules
extern crate chrono;
use chrono::{UTC};

use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::{encode, decode};
use rustc_serialize::Encodable;
// use rustc_serialize::base64::{self, FromBase64, ToBase64};
// use rustc_serialize::hex::{FromHex, ToHex};

extern crate rusqlite;

// Built-in modules
use std::str;
use std::string::String;
use std::collections::{HashMap};
use std::time::{Duration, Instant};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket, SocketAddr};
use std::net::{TcpListener, TcpStream};
use std::cmp::PartialEq;
use std::thread;

extern crate rand;
use rand::Rng;

use std::io;
use std::io::prelude::*;
use std::fs;
use std::fs::File;

// This list should be used as fallback.
// The servers on this list might inform about more servers.
pub const DEFAULT_PORT : u16 = 24822;
pub const PORT_RANGE : u16 = 20;
pub const DEFAULT_PROXY_PORT : u16 = 34822;
pub const PROXY_PORT_RANGE : u16 = 10_000;
const WORKING_DIR : &'static str = "./";
const MESSAGE_LIFE_TIME : i64 = 15; // Should be in seconds


// Central place to modify different sizes
pub type Domain = [u8; 4];
pub type PubHash = [u8; 32];
pub type PubKey = [u8; 32]; // TODO: Placeholder until this is implemented
pub type IPv4 = [u8; 4];
pub type IPv6 = [u8; 16];

pub fn init_node(domain : &[u8;4], socket : &mut UdpSocket, is_operator : bool, port : u16) -> (Node, KeyPair, ComputerStatus, Vec<OperatorNode>, DHT::DB){
    println!("Initializing node");

    println!("\tInitializing database");
    let db : DHT::DB = DHT::DB::new();

    println!("\tChecking for key files");
    let found_private_key : bool = match fs::metadata(format!("{}{}", WORKING_DIR, "my")){
        Ok(metadata) => {metadata.is_file()}, //Check it's a file
        Err(_) => {false}
    };

    let found_public_key : bool = match fs::metadata(format!("{}{}", WORKING_DIR, "my.pub")){
        Ok(metadata) => {metadata.is_file()}, //Check it's a file
        Err(_) => {false}
    };

    println!("\tChecking for key integrity");
    let key : KeyPair;
    if found_public_key && found_private_key && check_key_integrity(){
        println!("\t\tKey pair is working");
        key = match KeyPair::load_file(WORKING_DIR){
            Ok(k) => k,
            Err(error) =>{
                println!("\t\t\tError loading key from file: {}", error);
                println!("\t\t\tTrying to create new pair to recover");
                let key : KeyPair = KeyPair::new();
                key.save_file(WORKING_DIR).unwrap(); // Just panic, if this doesn't work
                key
            }
        }
    }
    else {
        println!("\t\tKeys either didn't work, or were missing");
        key = KeyPair::new();
        key.save_file(WORKING_DIR).unwrap(); // Just panic, if this doesn't work
    }

    // TODO: Send Node object through HTTPS to be signed and get it back


    // Find ourself in the database or submit to the operator
    let node : Node;
    node = match db.retrieve_node(&domain, &key.pub_hash){
        Ok(n) => n, // TODO: What about if our entry is too old? (handle it in the DHT)
        Err(err) => {
            panic!("\tThe Node has to be in the db before initializing: {}", err);
        }
    };

    // Determine, if the node is already at the operator-nodes
    if is_operator{
        // Generate a new key
        let operator_node : OperatorNode = OperatorNode::from_node(&node, &key);

        // Add operator node to database
        match db.insert_operator_node(&operator_node){
            Ok(()) => (),
            Err(error) => println!("\tError inserting ourself as operator node:\n\t{}", error)
        }
    }

    let operator_nodes : Vec<OperatorNode>;
    if !is_operator{
        operator_nodes = match db.fetch_operator_nodes(socket, &node, &key){
            Ok(n) => n,
            Err(err) => panic!("\tCan't continue without any operator nodes!\n\t{}", err)
        };
    }
    else{
        operator_nodes = Vec::new();
    }

    // operator_nodes.iter().map(|n| println!("Operator Node: {:?} {:?}", &n.domain, &n.pub_hash));

    println!("Making hardware status of computer");
    return (node, key, make_computer_status(), operator_nodes, db);
}

// Should take KeyPair as argument
// TODO: Should be part of KeyPair
pub fn check_key_integrity() -> bool{
    return true;
}

#[derive(Clone)]
pub struct KeyPair{
    public : [u8; 32], // Random datatype
    private : [u8; 32], // Random datatype
    pub pub_hash : [u8; 32] // FIXME: Shouldn't be public!!
}

impl KeyPair{
    pub fn new() -> KeyPair{
        panic!("Not implemented!");
        // KeyPair{
        //     public : generate_guid(),
        //     private : generate_guid(),
        //     pub_hash : generate_guid()
        // }
    }

    pub fn load_file(_path : &str) -> Result<KeyPair,String> {
        let mut file = match File::open(format!("{}{}", WORKING_DIR, "my")){
            Ok(f) => f,
            Err(err) => return Err(format!("Error opening key file! {}", err))
        };
        let mut buffer = [0; 32];

        // read 32 bytes
        match file.read(&mut buffer[..]){
            Ok(c) => {
                if c != 32{
                    return Err(format!("Couldn't read key file. Read only: {}", c));
                }
            },
            Err(err) => return Err(format!("Error opening key file! {}", err))
        };

        Ok(KeyPair{
            public : buffer.clone(),
            private : buffer.clone(),
            pub_hash : buffer
        })
    }

    pub fn save_file(&self, path : &str) -> Result<(), String>{
        panic!("Not implemented");
        // println!("Saving key pair to file");
        match File::create(format!("{}{}",path, "my")){
            Ok(_) => (),
            Err(error) => return Err(format!("Error writing to file:\n\t{}", error))
        };
        match File::create(format!("{}{}",path, "my.pub")){
            Ok(_) => (),
            Err(error) => return Err(format!("Error writing to file:\n\t{}", error))
        };
        Ok(())
    }

    pub fn sign_32_bytes(&self, _data : &[u8; 32]) -> [u8; 32]{
        return generate_guid(); //TODO: Implement
    }
}

pub fn decrypt_bytes(_key : &[u8; 32], _data : &[u8; 32]) -> [u8; 32]{
    return generate_guid();
}

pub fn decrypt_string(_key : &[u8; 32], _data : String) -> String{
    return String::from("");
}


#[derive(RustcDecodable, RustcEncodable, Clone, Debug)]
pub struct NodeUnsigned{
    // Persistent values
    domain : [u8; 4], // A value assigned to a company, to verify relations between nodes.
    pub_hash : [u8; 32], // public key hash of the node. This can be used to download the actual certificate from E I.
    public_key : [u8; 32], // TODO: Arbitrary number of bytes
}

#[derive(RustcDecodable, RustcEncodable, Clone, Debug)]
pub struct Node{
    // Persistent values
    pub domain : [u8; 4], // A value assigned to a company, to verify relations between nodes.
    pub pub_hash : [u8; 32], // public key hash of the node. This can be used to download the actual certificate from E I.
    pub public_key : [u8; 32], // TODO: Arbitrary number of bytes
    pub time_stamp : i64,// Used for garbage-collecting old nodes
    pub operator_signature : [u8; 32], // operator-signed hash of the public-key hash and the domain concatinatied. Used to securely verify relations
}

impl Node{
    fn sign(&self, _key : &KeyPair){
        panic!("Not implemeted");
    }

    fn get_addresses(&self, db : &DHT::DB) -> Result<Vec<SocketAddr>, String>{
        let info : NodeInfo = match db.retrieve_node_info(&self.domain, &self.pub_hash){
            Ok(info) => info,
            Err(error) => {
                return Err(format!("Couldn't retrieve addresses because node_info wasn't found:\n\t{}", error));
            }
        };

        // println!("get_addresses: {:?}", info);

        let port : u16 = info.port;

        let mut addrs : Vec<SocketAddr>= Vec::new();

        for ip in info.ipv4{
            addrs.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), port));
        }

        for ip in info.ipv6{
            // We have to store it as u8 to ease SQLite and JSON, but Ipv6Addr needs u16
            let mut arr = [0u16;8];
            for (idx, element) in ip.iter().enumerate(){
                // TODO: Check big/little endian
                if idx%2 == 0{
                    arr[idx/2] += (*element) as u16;
                }
                else{
                    arr[idx/2] += ((*element) as u16) << 8;
                }
            }
            addrs.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::new(arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7])), port));
        }

        if addrs.len() > 0{
            return Ok(addrs);
        }
        else{
            return Err(format!("No addresses defined, although node_info was found"));
        }
    }
}

#[derive(RustcDecodable, RustcEncodable, Clone, Debug)]
pub struct NodeInfo{
    pub domain : [u8; 4], // A value assigned to a company, to verify relations between nodes.
    pub pub_hash : [u8; 32], // public key hash of the node. This can be used to download the actual certificate from E I.
    // pub macs : Option<Vec<[u8; 6]>>, // Can we do a reverse ARP?
                               // Only store first X MAC-addresses, to avoid using excessive RAM as result of an exploit.
    pub ipv4 : Vec<[u8; 4]>, // This is only for helping, it's not necessarily correct - forged, changed
    pub ipv6 : Vec<[u8; 16]>, // This is only for helping, it's not necessarily correct - forged, changed
    pub port : u16, // The open receiving port for the node
    pub super_node : bool,
    pub tunnel_node : bool,
    pub time_stamp : i64, // Used for solving conflicts and finding newest entry

    pub node_signature : [u8; 32],
}

#[derive(RustcDecodable, RustcEncodable, Clone, Debug)]
pub struct SuperNode{
    // Persistent values
    domain : [u8; 4], // A value assigned to a company, to verify relations between nodes.
    pub_hash : [u8; 32], // public key hash of the node. This can be used to download the actual certificate from E I.
    section_from : u8,
    section_to : u8,

    time_stamp : i64,// Used for garbage-collecting old nodes
    operator_signature : [u8; 32], // operator-signed hash of the public-key hash and the domain concatinatied. Used to securely verify relations
}

impl SuperNode{
    fn sign(&self, _key : &KeyPair){
        panic!("Not implemeted");
    }

    pub fn from_node(node : &Node) -> SuperNode{
        SuperNode{
            domain : node.domain.clone(),
            pub_hash : node.pub_hash.clone(),
            section_from : 0, // TODO: Select section
            section_to : 0,
            time_stamp : UTC::now().timestamp(),
            operator_signature : generate_guid(), // TODO: Sign
        }
    }
}

#[derive(RustcDecodable, RustcEncodable, Clone, Debug)]
pub struct OperatorNode{
    // Persistent values
    pub domain : [u8; 4], // A value assigned to a company, to verify relations between nodes.
    pub pub_hash : [u8; 32], // public key hash of the node. This can be used to download the actual certificate from E I.

    pub time_stamp : i64,// Used for garbage-collecting old nodes
    pub operator_signature : [u8; 32], // operator-signed hash of the public-key hash and the domain concatinatied. Used to securely verify relations
}

impl OperatorNode{
    fn sign(&self, _key : &KeyPair){
        panic!("Not implemeted");
    }

    pub fn from_node(node : &Node, _key : &KeyPair) -> OperatorNode{
        OperatorNode{
            domain : node.domain.clone(),
            pub_hash : node.pub_hash.clone(),
            time_stamp : UTC::now().timestamp(),
            operator_signature : generate_guid() // TODO: Sign
        }
    }
}

#[derive(RustcDecodable, RustcEncodable, Clone, Debug)]
pub struct Command{
    pub command_type : CommandType,
    pub payload : Vec<u8>, //serialized content for command. NOT ENCRYPTED
}

impl Command{
    pub fn new(cmd_type : CommandType) -> Command{
        Command{
            command_type : cmd_type,
            payload : Vec::new()
        }
    }

    pub fn new_with_payload<T: Encodable>(cmd_type : CommandType, payload : T) -> Result<Command, String>{
        match encode(&payload, Infinite){
            Ok(data) => Ok(Command{
                command_type : cmd_type,
                payload : data
            }),
            Err(error) => Err(format!("Couldn't encode payload to JSON:\n\t{}", error))
        }
    }
}

#[derive(RustcDecodable, RustcEncodable, Clone, Debug, PartialEq)]
pub enum CommandType{
    GetOperatorNodes = 1,
    OperatorNodes,

    GetSuperNodes,
    SuperNodes,
    SubmitSuperNode,
    TransferPartition,

    GetNode,
    Node,

    GetNodeInfo,
    NodeInfo,

    GetTunnelNodes,
    TunnelRequest,      // Create raw TCP connection through the P2P network, ending on a LAN device
    TunnelOpened,
    // FileRequest,        // Find a file on the network
    // AssessmentRequest,  // Used to get statuses from all nodes
    // NetworkScan,        // Commands a thorough scan of the LAN

    //// Certificate stuff
    // Panic,          // Revokes a public key from a node in a quick fashion
    // Revoke,             // Used to revoke the public key from a Node

    // ONLY FOR TESTING!!
    Ping,
    Reping,
}


#[derive(RustcDecodable, RustcEncodable, Debug)]
pub struct Message{
    receiver_domain : Domain,
    receiver_pub_hash : PubHash,
    sender_domain : Domain,
    sender_pub_hash : PubHash,

    // TODO: Should this be serialized?
    command : Vec<u8>, //not base64, possibly encrypted

    time_stamp : i64,
    signed_checksum : [u8; 32],  // Hash of the variables above and then signed/encrypted by senders private key
}

impl Message {
    pub fn new (receiver_domain : &Domain, receiver_pub_hash : &PubHash, sender : &Node, command : Command, key : &KeyPair) -> Result<Message, String>{
        let serialized_command : Vec<u8> = match encode(&command, Infinite){
            Ok(contents) => contents,
            Err(error) => {
                return Err(format!("Error serializing command:\n\t{}", error));
            }
        };

        // TODO: Encrypt serialized_command
        let encrypted_command : Vec<u8> = encrypt_vec(serialized_command, key);

        let time_stamp = UTC::now().timestamp();

        // Calculate payload checksum and sign it
        let message_checksum : [u8; 32] = calculate_message_checksum(receiver_domain, receiver_pub_hash, sender, &encrypted_command, time_stamp);
        let signed_message_checksum : [u8; 32] = key.sign_32_bytes(&message_checksum);

        return Ok(Message{
            receiver_domain : receiver_domain.clone(),
            receiver_pub_hash : receiver_pub_hash.clone(),
            sender_domain : sender.domain.clone(),
            sender_pub_hash : sender.pub_hash.clone(),

            command : encrypted_command,

            time_stamp : time_stamp,
            signed_checksum : signed_message_checksum,  // Hash of the variables above and then signed/encrypted by senders private key
        });
    }

    pub fn from_buffer (buffer : &[u8]) -> Result<Message, String>{
        // let message_str = match str::from_utf8(buffer) {
        //     Ok(s) => s,
        //     Err(error) => return Err(format!("Error while parsing message:\n\t{}", error))
        // };

        let msg : Message = match decode(buffer){
        // let msg : Message = match decode(message_str){
            Ok(msg) => msg,
            Err(error) => return Err(format!("Error while deserializing message:\n\t{}", error))
        };

        return Ok(msg);
    }

    pub fn unpack(self, receiver : &Node, db : &DHT::DB) -> Result<(Command, Node), (String, bool)>{
        // Check timestamp
        if self.time_stamp > UTC::now().timestamp() + MESSAGE_LIFE_TIME{
            return Err((String::from("Message is too old"), false));
        }

        // Retreive sender node information
        let sender : Node = match db.retrieve_node(&self.sender_domain, &self.sender_pub_hash){
            Ok(node) => node,
            Err(err) => return Err((format!("Couldn't find node in db: domain {:?}, public hash {:?}\n\t{}",&self.sender_domain, &self.sender_pub_hash, err), true))
        };

        // Read the checksum from the message
        let checksum_from_message = decrypt_bytes(&sender.public_key, &self.signed_checksum);

        // Calculate our checksum -- Not to detect errors in data transfer, but if the message has
        // been modified.
        let checksum_calculated = calculate_message_checksum(&sender.domain, &sender.pub_hash, receiver, &self.command, self.time_stamp);

        // If we have a mismatch, discard it.
        if checksum_from_message != checksum_calculated {
            return Err((String::from("Checksum mismatch!"), false));
        }

        // Decrypt command
        let decrypted_payload : Vec<u8> = decrypt_vec(self.command, &sender.public_key);
        // let decrypted_payload = match String::from_utf8(decrypt_vec(self.command, &sender.public_key)){
        //     Ok(s) => s,
        //     Err(error) => return Err((format!("Error decoding command:\n\t{}", error), false))
        // };

        // Deserialize command
        let payload : Command =  match decode(decrypted_payload.as_slice()){
            Ok(m) => m,
            Err(error) => return Err((format!("Error in deserializing inner message:\n\t{}", error), false))
        };

        return Ok((payload, sender));
    }
}

pub fn decrypt_vec(mut encrypted_payload : Vec<u8>, _pub_key : &PubKey) -> Vec<u8>{
    // for n in encrypted_payload.iter_mut(){
    //     *n = *n ^ 0b10101010;
    // }
    return encrypted_payload;
}

pub fn encrypt_vec(mut payload : Vec<u8>, key : &KeyPair) -> Vec<u8>{
    // for n in payload.iter_mut(){
    //     *n = *n ^ 0b10101010;
    // }
    return payload;
}

pub fn calculate_message_checksum(_receiver_domain : &Domain, _receiver_pub_hash : &PubHash, _sender : &Node,  _data : &Vec<u8>, _time_stamp : i64) -> [u8; 32]{
    return generate_guid(); //TODO: Implement
}

pub fn sign_key_pair(_key : &KeyPair, _left : &[u8; 32], _right : &[u8; 32]) -> [u8; 32]{
    return generate_guid(); //TODO: Implement
}

#[derive(RustcDecodable, RustcEncodable)]
pub struct ComputerStatus{
    cpu: String,
    ram: u64,
    os: String,
    node_version: String,
    power: String,
    ethernet: bool, // Connected or not
    wifi: bool, // Connected or not
    subnet: String,
    router_mac: [u8; 6] // Change to byte array or MAC-class
}

pub fn make_computer_status() -> ComputerStatus{
    // sysctl machdep.cpu.brand_string
    // wmic cpu get name
    ComputerStatus {
        cpu : String::from("Intel(R) Core(TM) i5-4258U CPU @ 2.40GHz"),
        ram : 8*1024*1024*1024,
        os : String::from("MAC_10_11"),
        node_version : String::from("0.1"),
        power : String::from("battery"),
        ethernet : false,
        wifi : true,
        subnet : String::from("255.255.255.0"),
        router_mac : [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    }
}

pub fn generate_guid2() -> [u8; 32]{
    return [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32];
}

pub fn generate_guid() -> [u8; 32]{
    return [0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32];
}

pub fn guid() -> [u8; 32]{
    let mut rng = rand::thread_rng(); // TODO: Randomize !!!
    let mut arr = [0u8; 32];
    for place in arr.iter_mut() {
        *place = rng.gen::<u8>();
    }
    return arr;
}

pub fn send_node_info_to_operator(node_info : &NodeInfo, socket : &mut UdpSocket, key : &KeyPair, sender : &Node, receiver : &OperatorNode, db: &DHT::DB) -> Result<(), String>{
    let command : Command = match Command::new_with_payload(CommandType::NodeInfo, node_info) {
        Ok(c) => c,
        Err(err) => return Err(format!("Error sending NodeInfo:\n\t{}", err))
    };

    let receiver_node : Node = match db.retrieve_node(&receiver.domain, &receiver.pub_hash){
        Ok(n) => n,
        Err(err) => return Err(format!("Error finding Node for operator: {}", err))
    };

    let packet = match construct_message_packet(&receiver_node.domain, &receiver_node.pub_hash, sender, command, key){
        Ok(p) => p,
        Err(err) => return Err(format!("Error constructing message for sending NodeInfo: {}", err))
    };

    send_udp_packet_to_node(socket, &receiver_node, packet, db)
}

pub fn construct_message_packet(receiver_domain : &Domain, receiver_pub_hash : &PubHash, sender : &Node, payload : Command, key : &KeyPair) -> Result<Vec<u8>, String>{
    let payload : Message = match Message::new(receiver_domain, receiver_pub_hash, sender, payload, key){
        Ok(contents) => contents,
        Err(error) => return Err(format!("Error while creating message:\n\t{}", error))
    };

    let serialized_payload = match encode(&payload, Infinite){
        Ok(contents) => contents,
        Err(error) => return Err(format!("Error while serializing message:\n\t{}", error))
    };

    // TODO: Where is it encrypted?
    Ok(serialized_payload)
}

pub fn send_udp_packet_to_src(socket : &mut UdpSocket, addr : SocketAddr, packet : Vec<u8>) -> Result<(), String>{
    send_udp_packet_to_addr(socket, vec![addr], packet)
}

pub fn send_udp_packet_to_addr(socket : &mut UdpSocket, addrs : Vec<SocketAddr>, packet : Vec<u8>) -> Result<(), String>{
    let mut last_error = "".to_string();
    for addr in addrs {
        // println!("Sending message of: {:?} bytes", packet.len());

        match socket.send_to(&packet[..], &addr){//"127.0.0.1:24822"){
            Ok(_) => return Ok(()), // Return which address worked
            Err(error) => {
                 last_error = format!("Got error while sending message:\n\t{}", error);
            }
        }
    }
    return Err(last_error);
}

pub fn send_udp_packet_to_node(socket : &mut UdpSocket, receiver : &Node, packet : Vec<u8>, db : &DHT::DB) -> Result<(), String>{
    let addrs : Vec<SocketAddr> = match receiver.get_addresses(db){
        Ok(ips) => ips,
        Err(error) => return Err(format!("Error getting IP or port for node:\n\t{}", error))
    };

    send_udp_packet_to_addr(socket, addrs, packet)
}

pub fn send_to_addrs_and_expect_response_of(socket : &mut UdpSocket, node : &Node, addrs : Vec<SocketAddr>, packet : Vec<u8>, expected_response : CommandType, timeout : Option<Duration>, key : &KeyPair, db : &DHT::DB) -> Result<(Command, Node), String>{
    send_udp_packet_to_addr(socket, addrs, packet);
    let cmd_sender = match expect_response_of(socket, node, expected_response, timeout, key, db){
        Ok((c,s)) => (c,s),
        Err(error) => return Err(format!("Error getting expected response:\n\t{}", error))
    };
    return Ok(cmd_sender);
}

pub fn send_to_node_and_expect_response_of(socket : &mut UdpSocket, node : &Node, receiver : &Node, packet : Vec<u8>, expected_response : CommandType, timeout : Option<Duration>, key : &KeyPair, db : &DHT::DB) -> Result<(Command, Node), String>{
    send_udp_packet_to_node(socket, receiver, packet, db);
    let cmd_sender = match expect_response_of(socket, node, expected_response, timeout, key, db){
        Ok((c,s)) => (c,s),
        Err(error) => return Err(format!("Error getting expected response:\n\t{}", error))
    };
    return Ok(cmd_sender);
}

pub fn expect_response_of(socket : &mut UdpSocket, node : &Node, expected_response : CommandType, timeout : Option<Duration>, key : &KeyPair, db : &DHT::DB) -> Result<(Command, Node), String>{
    match socket.set_read_timeout(timeout){
        Ok(_) => (),
        Err(error) => return Err(format!("Error setting timeout:\n\t{}", error))
    }

    let start : Instant = Instant::now();

    let mut last_error : String = String::from("");
    let mut cmd_sender : Option<(Command, Node)> = None;
    while timeout != None && Instant::now()-start < timeout.unwrap(){
        cmd_sender = match receive_command(socket, node, key, db){
            Ok((_,c,s)) => {
                if c.command_type == expected_response{
                    Some((c,s))
                }
                else {
                    last_error = format!("Received and discarded command of {:?}. Waiting for {:?}", c.command_type, expected_response);
                    continue;
                }
            },
            Err(error) => {
                last_error = format!("Error occured while receiving answer:\n\t{}", error);
                continue;
            }
        };
        break;
    }

    match socket.set_read_timeout(None){
        Ok(_) => (),
        Err(error) => return Err(format!("Error setting timeout:\n\t{}", error))
    }

    match cmd_sender{
        Some((c,s)) => return Ok((c,s)),
        None => return Err(format!("Couldn't get the expected response. Last error:\n\t{}", last_error))
    };
}

pub fn receive_command(socket : &mut UdpSocket, node : &Node, key : &KeyPair, db : &DHT::DB) -> Result<(SocketAddr, Command, Node), String>{
    // read from the socket
    let mut buf = [0; 16*1024]; // 16k is arbitrary -- slight more than a max-sized UDP packet?
    let (bytes, src) = match socket.recv_from(&mut buf){
        Ok(packet) => packet,
        Err(error) => {
            return Err(format!("Error receiving data packet:\n\t{}", error));
        }
    };

    println!("\nRead {} bytes from: {}", bytes, src);

    // Deserialize message
    let msg : Message = match Message::from_buffer(&buf[..bytes]){
        Ok(payload) => payload,
        Err(error) => {
            return Err(format!("Got error while parsing incoming message:\n\t{}", error));
        }
    };

    // Command, Node
    let domain : Domain = msg.sender_domain.clone();
    let pub_hash : PubHash = msg.sender_pub_hash.clone();

    let (cmd, sender) = match msg.unpack(node, &db){
        Ok(cmd_sender) => cmd_sender,
        Err((error, missing_node)) => {
            if missing_node{
                let cmd = Command::new(CommandType::GetNode); // TODO: Add domain and public hash!!! Or allow empty GetNode to alias to "WhoAreYou"

                // Constructing message
                let packet : Vec<u8> = match construct_message_packet(&domain, &pub_hash, node, cmd, key){
                    Ok(p) => p,
                    Err(error) => return Err(format!("Error constructing WhoAreYou message:\n\t{}", error))
                };

                // Sending message
                match send_udp_packet_to_src(socket, src, packet){
                    Ok(_) => (),
                    Err(error) => return Err(format!("Error sending WhoAreYou message:\n\t{}", error))
                }
            }
            return Err(format!("Error while unpacking message to command:\n\t{}", error));
        }
    };

    return Ok((src, cmd, sender));
}

pub fn execute_command(command : Command, socket : &mut UdpSocket, src : SocketAddr, src_node : &Node, node : &Node, key : &KeyPair, db : &DHT::DB, is_operator : bool) -> Result<(), String>{
    println!("Finding reply to: {:?}", command.command_type);

    // let temp_payload_str = match command.payload{
    //     Ok(s) => s,
    //     Err(err) => return Err(format!("Error converting payload from base64:\n\t{}", err))
    // };

    // let payload_str = match str::from_utf8(temp_payload_str.as_slice()) {
    //     Ok(s) => s,
    //     Err(error) => return Err(format!("Error while converting command payload to str:\n\t{}", error))
    // };


    let reply_cmd : Result<Command, String> = match command.command_type{

    ////////////////////////////////////////
    // Operator nodes
        CommandType::GetOperatorNodes => {
            // Fetch operator nodes
            let operator_nodes : Vec<OperatorNode> = match db.retrieve_operator_nodes(){
                Ok(nodes) => nodes,
                Err(err) => return Err(format!("Couldn't find operator nodes:\n\t{}", err))
            };

            Command::new_with_payload(CommandType::OperatorNodes, &operator_nodes)
        },
        CommandType::OperatorNodes => {
            // Save operator nodes
            // db.insert_oprator_node_vec();
            println!("Received list of operator nodes:\n\t{:?}", command.payload.as_slice());
            return Err("Not implemented".to_string());
        },

    ////////////////////////////////////////
    // Super nodes
        CommandType::GetSuperNodes => {
            // Fetch super nodes
            let super_nodes : Vec<SuperNode> = match db.retrieve_super_nodes(){
                Ok(nodes) => nodes,
                Err(err) => return Err(format!("Error getting super nodes:\n\t{}", err))
            };

            Command::new_with_payload(CommandType::SuperNodes, &super_nodes)
        },
        CommandType::SuperNodes => {
            // Save super nodes
            return Err("Not implemented".to_string());
        },
        CommandType::SubmitSuperNode => {
            if is_operator {
                // Sign begin super_node and save
                // Share with other possible Operators
                // Share with super nodes in redundancy

                // Determine Section
                // Accept as super-node. Send message of redundancies to all super-nodes in group
                // including the submitted node

                // Extract node data
                let node : SuperNode = match decode(command.payload.as_slice()){
                    Ok(n) => n,
                    Err(error) => return Err(format!("Error deserializing command payload to node:\n\t{}", error))
                };

                // Insert into DHT
                match db.insert_super_node(&node){
                    Ok(()) => (),
                    Err(error) => return Err(format!("Error, can't submit super-node:\n\t{}", error))
                };

                Ok(Command {
                    command_type : CommandType::SuperNodes,
                    payload : Vec::new() // TODO: populate list!
                })
            }
            else{
                return Err(format!("Error: Received SubmitSuperNode, but this node isn't an operator."))
            }
        },
        CommandType::TransferPartition => {
            // if is_super_node
            panic!("TransferPartition: Not Implemented!");
        },

    ////////////////////////////////////////
    // Nodes
        CommandType::GetNode => {
            // Fetch node
            let node : Node = match db.retrieve_node(&src_node.domain, &src_node.pub_hash){
                Ok(node) => node,
                Err(err) => {
                    return Err(format!("Error getting node:\n\t{}", err))
                }
            };

            Command::new_with_payload(CommandType::Node, &node)
        },
        CommandType::Node => {
            // Save node
            return Err("Not implemented".to_string());
        },

    ////////////////////////////////////////
    // Node Info
        CommandType::GetNodeInfo => {
            let node : Node = match decode(command.payload.as_slice()){
                Ok(n) => n,
                Err(err) => {
                    return Err(format!("Couldn't decode as NodeInfo:\n\t{}",err))
                }
            };

            Command::new_with_payload(CommandType::NodeInfo, &node)
        },
        CommandType::NodeInfo => {
            let node_info : NodeInfo = match decode(command.payload.as_slice()){
                Ok(n) => n,
                Err(err) => {
                    return Err(format!("Couldn't decode as NodeInfo:\n\t{}",err))
                }
            };

            return match db.insert_node_info(&node_info) {
                Ok(_) => Ok(()),
                Err(err) => Err(format!("Received NodeInfo, but couldn't insert it in the DB: {}", err))
            };
        },

    ////////////////////////////////////////
    // Tunnel
        CommandType::GetTunnelNodes => {
            panic!("GetTunnelNodes: Not Implemented!");
        },

        CommandType::TunnelRequest => {

            println!("TunnelRequest fisjisddfs");
            // Extract node data
            let tcp_proxy : network_tools::TcpProxy = match decode(command.payload.as_slice()){
                Ok(n) => n,
                Err(error) => return Err(format!("Error deserializing command payload to TcpProxy:\n\t{}", error))
            };

            // Return ip to requesting node to know which (possibly random or range) port will be used
            // let available_port : u16 =


            // TODO: Move this to another thread!
            let mut found_port : Option<u16> = None;
            let mut last_error = "".to_string();
            for p in DEFAULT_PROXY_PORT..DEFAULT_PROXY_PORT+PROXY_PORT_RANGE{
                match TcpListener::bind(SocketAddr::new(socket.local_addr().unwrap().ip(), p)){ // TODO: Does this only work for IPv4?
                    Ok(listener) => {
                        println!("Spawning tunnel thread from: {:?}:{} to {}", socket.local_addr().unwrap().ip(), p, tcp_proxy.target_addr);
                        // tcp_proxy.start(listener);
                        let t = thread::Builder::new()
                            .name(format!("Tunnel from: {:?}:{} to {}", socket.local_addr().unwrap().ip(), p, tcp_proxy.target_addr))
                            .stack_size(32_768)
                            .spawn(move|| {
                                tcp_proxy.start(listener);
                            });
                        found_port = Some(p);
                    },
                    Err(error) => {
                        last_error = format!("{}",error);
                        continue;
                    }
                };
                break;
            }

            match found_port{
                Some(p) => Command::new_with_payload(CommandType::TunnelOpened, p),
                None => {
                    Err(format!("Couldn't find port for tunnel!\n\t{}", last_error))
                }
            }
        }
        CommandType::TunnelOpened => {
            let opened_port : u16 = match decode(command.payload.as_slice()){
                Ok(p) => p,
                Err(error) => return Err(format!("Error deserializing command payload to TunnelOpened:\n\t{}", error))
            };

            println!("Port opened for tunneling on: {:?} {}", src, opened_port);
            Err("Not implemented".to_string())
        }
        CommandType::Ping => {
            Ok(Command::new(CommandType::Reping))
        }
        CommandType::Reping => {
            return Ok(());
        }
    };

    // Unwrap return command
    let cmd : Command = match reply_cmd{
        Ok(c) => c,
        Err(err) => {
            return Err(format!("Error contructing reply:\n\t{}", err))
        }
    };

    // Constructing message
    let packet : Vec<u8> = match construct_message_packet(&src_node.domain, &src_node.pub_hash, node, cmd, key){
        Ok(p) => {
            p
        },
        Err(error) => {
            return Err(format!("Error constructing message packet:\n\t{}", error))
        }
    };

    // Sending message
    match send_udp_packet_to_src(socket, src, packet){
        Ok(_) => (),//println!("Message sent"),
        Err(error) => return Err(format!("Error sending message:\n\t{}", error))
    }

    Ok(())
}

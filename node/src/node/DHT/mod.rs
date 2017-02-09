//
// Author: Mads Ynddal
// License: See LICENSE file
// GitHub: https://github.com/Baekalfen/BachelorProjekt.git
//

use std::net::{UdpSocket, SocketAddr};
// Most of these are only for fetch operations!
use super::{Node, NodeInfo, SuperNode, OperatorNode, generate_guid, KeyPair, Command, CommandType, construct_message_packet, send_udp_packet_to_node, expect_response_of};
use std::fs;
use std::time::{Duration};

// Only for fetch operations!
use bincode::SizeLimit;
use bincode::rustc_serialize::{encode, decode};
use rustc_serialize::Encodable;
// use rustc_serialize::base64::{self, FromBase64, ToBase64};
// use rustc_serialize::hex::{FromHex, ToHex};

extern crate rusqlite;
use rusqlite::{Connection, Row};
use rusqlite::types::{SqlArr4, SqlArr16, SqlArr32};

use super::{IPv4, IPv6};

const SQLPATH : &'static str = "db.sqlite";
const TIMEOUT : u64 = 5;


macro_rules! hex_string {
    ($expr:expr) => (
        $expr.iter().map(|b| format!("{:02X}", b)).collect::<String>()
    )
}

pub struct DB{
    connection : Connection,
    // insert_node : Statement<'a>,
    // retrieve_node : Statement<'a>
}

impl DB{
    pub fn new<'a> () -> DB{
        let create_db : bool = match fs::metadata(SQLPATH){
            Ok(metadata) => {
                if !metadata.is_file(){
                    panic!("SQLite database is not a file!")
                }
                else{
                    false
                }
            },
            Err(_) => true
        };


        // Side effect of creating the file, if it doesn't exist
        let connection = match Connection::open(SQLPATH){
            Ok(c) => c,
            Err(error) => {
                panic!("Could not open database: {}", error);
            }
        };


        if create_db {
            match connection.execute("CREATE TABLE node (
                      domain                    BLOB NOT NULL,
                      pub_hash                  BLOB NOT NULL,
                      public_key                BLOB NOT NULL,
                      time_stamp                INTEGER NOT NULL,
                      signee_domain             BLOB NOT NULL,
                      signee_pub_hash           BLOB NOT NULL,
                      operator_signature        BLOB NOT NULL,
                      PRIMARY KEY (domain, pub_hash)
                      )", &[]){
                Ok(_) => (),
                Err(error) => println!("Failed to create table for nodes. It probably already exists: {}", error)
            };

            match connection.execute("CREATE TABLE node_info (
                      domain                    BLOB NOT NULL,
                      pub_hash                  BLOB NOT NULL,
                      ipv4                      BLOB,
                      ipv6                      BLOB,
                      port                      INTEGER NOT NULL,
                      super_node                INTEGER,
                      tunnel_node               INTEGER,
                      time_stamp                INTEGER NOT NULL,
                      node_signature            BLOB,
                      PRIMARY KEY (domain, pub_hash), -- Enforced by foreign key?
                      FOREIGN KEY (domain, pub_hash) REFERENCES node(domain, pub_hash)
                      )", &[]){
                Ok(_) => (),
                Err(error) => println!("Failed to create table for nodes. It probably already exists: {}", error)
            };

            match connection.execute("CREATE TABLE super_nodes (
                      domain                    BLOB NOT NULL,
                      pub_hash                  BLOB NOT NULL,
                      section_from              INTEGER,
                      section_to                INTEGER,
                      time_stamp                INTEGER NOT NULL,
                      signee_domain             BLOB NOT NULL,
                      signee_pub_hash           BLOB NOT NULL,
                      operator_signature            BLOB NOT NULL,
                      PRIMARY KEY (domain, pub_hash), -- Enforced by foreign key?
                      FOREIGN KEY (domain, pub_hash) REFERENCES node(domain, pub_hash)
                      )", &[]){
                Ok(_) => (),
                Err(error) => println!("Failed to create table for nodes. It probably already exists: {}", error)
            };

            match connection.execute("CREATE TABLE operator_nodes (
                      domain                    BLOB NOT NULL,
                      pub_hash                  BLOB NOT NULL,
                      time_stamp                INTEGER NOT NULL,
                      signee_domain             BLOB NOT NULL,
                      signee_pub_hash           BLOB NOT NULL,
                      operator_signature        BLOB NOT NULL,
                      PRIMARY KEY (domain, pub_hash), -- Enforced by foreign key?
                      FOREIGN KEY (domain, pub_hash) REFERENCES node(domain, pub_hash)
                      )", &[]){
                Ok(_) => (),
                Err(error) => println!("Failed to create table for nodes. It probably already exists: {}", error)
            };

            // identifier is hash of SSL and MAC
            match connection.execute("CREATE TABLE end_devices (
                      domain                    BLOB NOT NULL,
                      identifier                BLOB NOT NULL,
                      location                  BLOB NOT NULL,
                      time_stamp                INTEGER NOT NULL,
                      signee_domain             BLOB NOT NULL,
                      signee_pub_hash           BLOB NOT NULL,
                      operator_signature        BLOB NOT NULL,
                      PRIMARY KEY (domain, identifier)
                      )", &[]){
                Ok(_) => (),
                Err(error) => println!("Failed to create table for nodes. It probably already exists: {}", error)
            };

            println!("SQLite database create");
        }

        // let insert_node = match connection.prepare(""){
        //     Ok(p) => p,
        //     Err(error) => panic!("Couldn't prepare insert statement: {}", error)
        // };

        // let retrieve_node = match connection.prepare(""){
        //     Ok(p) => p,
        //     Err(error) => panic!("Couldn't prepare insert statement: {}", error)
        // };

        return DB{
            connection : connection,
            // insert_node : insert_node,
            // retrieve_node : retrieve_node
        };
    }


    pub fn fetch_node_info(&self, _domain : &[u8; 4], _pub_hash : &[u8; 32]) -> Result<NodeInfo, String>{
        return Err("Not implemented".to_string());
    }

    pub fn retrieve_node_info(&self, domain : &[u8; 4], pub_hash : &[u8; 32]) -> Result<NodeInfo, String>{
        // Retreive data from super-nodes if no record is found and save it in SQLite
        // TODO: Ping addresses and possibly remove addresses that don't work or down-prioritize them
        match self.connection.query_row(
            "SELECT domain, pub_hash, ipv4, ipv6, port, super_node, tunnel_node, time_stamp, node_signature FROM node_info WHERE domain = ? AND pub_hash = ?",
            &[&domain.to_vec(), &pub_hash.to_vec()],
            |row| {
                let domain : SqlArr4 = row.get(0);
                let pub_hash : SqlArr32 = row.get(1);
                let raw_ipv4 : Vec<u8> = row.get(2);
                let raw_ipv6 : Vec<u8> = row.get(3);
                let port : i32 = row.get(4);
                let node_signature : SqlArr32 = row.get(8);

                if raw_ipv4.len() % 4 != 0 {
                    return Err(format!("IPv4 from data is malformed. It has the length of: {}", raw_ipv4.len()));
                }

                let mut ipv4 : Vec<IPv4> = Vec::new();
                let mut i = 0;
                for n in 0..raw_ipv4.len()/4{
                    let mut arr = [0u8; 4];
                    for (place, element) in arr.iter_mut().zip(raw_ipv4[i..i+4].iter()) {
                        *place = *element;
                    }

                    ipv4.push(arr);
                    i += 4;
                }

                if raw_ipv6.len() % 16 != 0 {
                    return Err(format!("IPv6 from data is malformed. It has the length of: {}", raw_ipv6.len()));
                }
                let mut ipv6 : Vec<IPv6> = Vec::new();
                //TODO: Implement IPv6

                //TODO: Check signature

                Ok(NodeInfo{
                    domain : domain.v, //.as_slice(),
                    pub_hash : pub_hash.v,
                    // macs : row.get(2),
                    ipv4 : ipv4,
                    ipv6 : Vec::new(),//ipv6.v,
                    // ipv4 : match ipv4{
                    //     Some(ip) => Some(ip.v),
                    //     None => None
                    // },
                    // ipv6 : match ipv6{
                    //     Some(ip) => Some(ip.v),
                    //     None => None
                    // },
                    port : port as u16,
                    super_node : row.get(5),
                    tunnel_node : row.get(6),
                    time_stamp : row.get(7),
                    node_signature : node_signature.v
                })
            }){
                Ok(info) => info,
                Err(error) => {
                    return Err(format!("Error retrieving node information on node: {:?}, {:?},\n\t{}", domain, pub_hash, error));
                    //TODO: Default to fetching the data!
            }
        }
    }

    pub fn upload_node_info(&self) -> Result<(), String>{
        return Err("Not implemented".to_string());
    }

    pub fn insert_node_info(&self, n : &NodeInfo) -> Result<(),String>{
        let mut ipv4 : Vec<u8> = Vec::with_capacity(n.ipv4.len());
        for ip in &n.ipv4{
            ipv4.extend(ip.to_vec());
        }

        let mut ipv6 : Vec<u8> = Vec::with_capacity(n.ipv6.len());
        for ip in &n.ipv6{
            ipv6.extend(ip.to_vec());
        }

        match self.connection.execute("INSERT OR REPLACE INTO node_info (domain, pub_hash, ipv4, ipv6, port, super_node, tunnel_node, time_stamp, node_signature) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
             &[&n.domain.to_vec(), &n.pub_hash.to_vec(), &ipv4, &ipv6, &(n.port as i32), &n.super_node, &n.tunnel_node,  &n.time_stamp, &n.node_signature.to_vec()]){
            Ok(r) => {
                // grintln!("Inserted {} into node_info", r);
                Ok(())
            },
            Err(error) =>{
                Err(format!("Error inserting node:\n\t{}", error))
            }
        }
    }



    pub fn fetch_node(&self, _domain : &[u8; 4], _pub_hash : &[u8; 32]) -> Result<Node, String>{
        return Err("Not implemented".to_string());
    }


    pub fn retrieve_node(&self, domain : &[u8; 4], pub_hash : &[u8; 32]) -> Result<Node, String>{
        // Retreive data from super-nodes if no record is found and save it in SQLite
        // let mut stmt = conn.prepare("SELECT domain, pub_hash, public_key, operator_signature, time_stamp FROM node").unwrap();
        println!("Retreiving node data for : {:?} {:?}", hex_string!(domain), hex_string!(pub_hash));

        match self.connection.query_row(
            // "SELECT domain, pub_hash, public_key, operator_signature, time_stamp FROM node WHERE domain = ?",
            // &[&vec!(16,0,0,0)],
            "SELECT domain, pub_hash, public_key, operator_signature, time_stamp FROM node WHERE domain = ? AND pub_hash = ?",
            &[&domain.to_vec(), &pub_hash.to_vec()], |row| row_to_node(&row)){
                Ok(n) => Ok(n),
                Err(error) => Err(format!("Error retrieving node:\n\t{}", error))
        }
    }

    pub fn upload_node(&self) -> Result<(), String>{
        return Err("Not implemented".to_string());
    }

    pub fn insert_node(&self, n : &Node) -> Result<(),String>{
        // domain : [0,0,0,0],
        // pub_hash : generate_guid2(),
        // public_key : generate_guid(),
        // time_stamp : UTC::now().timestamp(),
        // operator_signature : generate_guid(),

        match self.connection.execute("INSERT OR REPLACE INTO node (domain, pub_hash, public_key, time_stamp, operator_signature) VALUES ($1, $2, $3, $4, $5)",
             &[&n.domain.to_vec(), &n.pub_hash.to_vec(), &n.public_key.to_vec(), &n.time_stamp, &n.operator_signature.to_vec()]){
            Ok(r) => {
                // println!("Inserted {} into node", r);
                return Ok(())
            },
            Err(error) =>{
                return Err(format!("Error inserting node:\n\t{}", error));
            }
        }
    }

    pub fn fetch_operator_nodes_from_addrs(&self, socket : &mut UdpSocket, node : &Node, key : &KeyPair, addrs : &Vec<SocketAddr>) -> Result<Vec<OperatorNode>, String>{
        return Err("Not implemented".to_string());
    }

    //TODO: Move ALL fetch operations to s/n/mod.rs
    pub fn fetch_operator_nodes(&self, socket : &mut UdpSocket, node : &Node, key : &KeyPair) -> Result<Vec<OperatorNode>, String>{
// pub fn send_to_node_and_expect_response_of(socket : &mut UdpSocket, node : &Node, receiver : &Node, packet : Vec<u8>, expected_response : CommandType, timeout : Option<Duration>, db : &DHT::DB) -> Result<(Command, Node), String>{

        let op_nodes = match self.retrieve_node_of_operator_nodes(){
            Ok(n) => n,
            Err(error) => panic!("No operator nodes in the database. System can't continue! Error message was: {}", error)
        };

        for op in op_nodes{
            let cmd = Command::new(CommandType::GetOperatorNodes);

            // Constructing message
            let packet : Vec<u8> = match construct_message_packet(&op.domain, &op.pub_hash, node, cmd, key){
                Ok(p) => {
                    p
                },
                Err(error) => {
                    return Err(format!("Error constructing message packet:\n\t{}", error));
                }
            };


// pub fn send_udp_packet_to_node(socket : &mut UdpSocket, receiver : &Node, packet : Vec<u8>, db : &DHT::DB) -> Result<(), String>{
            match send_udp_packet_to_node(socket, &op, packet, &self){
                Ok(_) =>(),
                Err(error) => {
                    return Err(format!("Error sending request to operator node, {}", error));
                }
            }
        }

// pub fn expect_response_of(socket : &mut UdpSocket, node : &Node, expected_response : CommandType, timeout : Option<Duration>, db : &DHT::DB) -> Result<(Command, Node), String>{
        match expect_response_of(socket, node, CommandType::OperatorNodes, Some(Duration::new(TIMEOUT, 0)), key, &self){
            Ok((cmd, n)) => {
                // println!("Received list of operator nodes: {}", String::from_utf8(cmd.payload).unwrap());
                // let string = match String::from_utf8(cmd.payload){
                //     Ok(s) => s,
                //     Err(err) =>{
                //         return Err(format!("Error decoding payload into String:\n\t{}", err));
                //         // TODO: Try next packet
                //     }
                // };

                match decode::<Vec<OperatorNode>>(cmd.payload.as_slice()){
                // match decode::<Vec<OperatorNode>>(&*string){
                    Ok(new_ops) =>{
                        for op in new_ops.iter(){
                            self.insert_operator_node(&op);
                        }
                        Ok(new_ops)
                    },
                    Err(err) => {
                        Err(format!("Error fetching operator_nodes:\n\t{}", err))
                    }
                }
            },
            Err(err) => {
                Err(format!("Error fetching operator_nodes:\n\t{}", err))
            }
        }
    }

    pub fn retrieve_node_of_operator_nodes(&self) -> Result<Vec<Node>, String>{
        // println!("Retreiving nodes for operator nodes");
        let mut stmt = self.connection.prepare("select node.domain, node.pub_hash, public_key, node.operator_signature, node.time_stamp from operator_nodes inner join node on (operator_nodes.pub_hash = node.pub_hash and operator_nodes.domain = node.domain)").unwrap();

        let op_node_iter = match stmt.query_map(&[], |row| row_to_node(row)){
                Ok(n) => n,
                Err(error) => {
                    return Err(format!("Error retrieving operator node:\n\t{}", error));
            }
        };

        // TODO: Sketchy unwrap. How can this go wrong?
        let op_nodes : Vec<Node> = op_node_iter.map(|node_result| node_result.unwrap()).collect();

        if op_nodes.len() == 0 {
            return Err("No operator nodes found".to_string());
        }

        Ok(op_nodes)
    }

    pub fn retrieve_operator_nodes(&self) -> Result<Vec<OperatorNode>, String>{
        // println!("Retreiving operator nodes");

        let mut stmt = self.connection.prepare("SELECT domain, pub_hash, operator_signature, time_stamp FROM operator_nodes").unwrap();

        let op_node_iter = match stmt.query_map(&[], |row| {
                let domain : SqlArr4 = row.get(0);
                let pub_hash : SqlArr32 = row.get(1);
                let operator_signature : SqlArr32 = row.get(2);

                OperatorNode{
                    domain : domain.v,
                    pub_hash : pub_hash.v,
                    time_stamp : row.get(3),
                    operator_signature : operator_signature.v
                }
            }){
                Ok(n) => n,
                Err(error) => {
                    return Err(format!("Error retrieving operator node:\n\t{}", error));
            }
        };

        // TODO: Sketchy unwrap. How can this go wrong?
        let op_nodes : Vec<OperatorNode> = op_node_iter.map(|node_result| node_result.unwrap()).collect();

        if op_nodes.len() == 0 {
            return Err("No operator nodes were retrieved".to_string());
        }

        Ok(op_nodes)
    }

    pub fn insert_operator_node(&self, n : &OperatorNode) -> Result<(),String>{
        // domain : [0,0,0,0],
        // pub_hash : generate_guid2(),
        // public_key : generate_guid(),
        // time_stamp : UTC::now().timestamp(),
        // operator_signature : generate_guid(),
        let operator_signature : [u8; 32] = generate_guid();

        match self.connection.execute("INSERT OR REPLACE INTO operator_nodes (domain, pub_hash, time_stamp, signee_domain, signee_pub_hash, operator_signature) VALUES ($1, $2, $3, $4, $5, $6)",
             &[&n.domain.to_vec(), &n.pub_hash.to_vec(), &n.time_stamp, &generate_guid().to_vec(), &generate_guid().to_vec(), &operator_signature.to_vec()]){
            Ok(r) => {
                // println!("Inserted {} into operator_nodes", r);
                return Ok(())
            },
            Err(error) =>{
                return Err(format!("Error inserting operator node:\n\t{}", error));
            }
        }
    }

    pub fn retrieve_super_nodes_group(&self, _section : u8) -> Result<Vec<SuperNode>, String>{
        return Err("Not implemented".to_string());
    }

    pub fn retrieve_super_nodes(&self) -> Result<Vec<SuperNode>, String>{
        return Err("Not implemented".to_string());
    }

    pub fn insert_super_node(&self, _n : &SuperNode) -> Result<(),String>{
        // domain : [0,0,0,0],
        // pub_hash : generate_guid2(),
        // public_key : generate_guid(),
        // time_stamp : UTC::now().timestamp(),
        // operator_signature : generate_guid(),

        // match self.connection.execute("INSERT OR REPLACE INTO node (domain, pub_hash, public_key, time_stamp, operator_signature) VALUES ($1, $2, $3, $4, $5)",
        //      &[&n.domain.to_vec(), &n.pub_hash.to_vec(), &n.public_key.to_vec(), &n.time_stamp, &n.operator_signature.to_vec()]){
            // Ok(r) => {
            //     println!("Inserted {} into node", r);
            //     return Ok(())
            // },
            // Err(error) =>{
            //     return Err(format!("Error inserting node: {}", error));
            // }
        //     }
        // }
        Err("Not Implemented".to_string())
    }
}

fn row_to_node(row : &Row) -> Node{
    let domain : SqlArr4 = row.get(0);
    let pub_hash : SqlArr32 = row.get(1);
    let public_key : SqlArr32 = row.get(2);
    let operator_signature : SqlArr32 = row.get(3);

    //TODO: Check signature

    Node{
        domain : domain.v,
        pub_hash : pub_hash.v,
        public_key : public_key.v,
        time_stamp : row.get(4),
        operator_signature : operator_signature.v
    }
}

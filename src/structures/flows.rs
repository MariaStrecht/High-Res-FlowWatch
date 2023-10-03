// Declare the structures module
pub mod flows {
    use pcap::Packet;
    use std::{fmt,collections::HashMap,hash::{Hash, Hasher}};
    use etherparse::{TransportHeader, IpHeader, PacketHeaders};
    use crate::utils::calculate_hash;

    /**
    * TransProtocol 
    * - Defines the Transport Protocol
    */
    #[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
    pub enum TransProtocol {
        UDP,
        TCP,
        Icmpv4,
        Icmpv6,
    }

    impl TransProtocol{
        /**
         * get_id
         * - Get the ID corresponding to the transport protocol
        */
        pub fn get_id(&self) -> u8{
            match *self{
                self::TransProtocol::TCP => return 1,
                self::TransProtocol::Icmpv4 => return 2,
                self::TransProtocol::Icmpv6 => return 3,
                _ => return 0,
            }
        }
    }
    impl fmt::Display for TransProtocol {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{:?}", self)
        }
    }
    /**
     * FlowTable 
     * - Structure to store the flows based on their filter
     */
    pub struct FlowTable {
        // structure to store all flows related to a filter
        // id do filter (hash da rule) com a lista de flows
        flows :  HashMap<u64,HashMap<u64,Flow>>,
        // structure where are stored the IPs that are always considered the clients
        clients: HashMap<u64,Vec<u8>>,
    }

    impl FlowTable{
        /**
         * new
         * - Create a new FlowTable with the provided clients
         * @param clients - map with clients defined by the user, where key is key and value is the ip
        */
        pub fn new(clients: HashMap<u64,Vec<u8>>) -> FlowTable {
            FlowTable {
                flows: HashMap::new(),
                clients,
            }
        }

        /**
         * flow_definition
         * - Get the flow definition for the given flow ID
         * @param flow_id - id of the flow
        */
        pub fn flow_definition(&self, flow_id: &u64) ->  Result<(u8, u8, Vec<u8>, u16, Vec<u8>, u16),()>{
            for (_key, map) in &self.flows{
                match map.get(flow_id){
                    Some(flow) => {
                        return Ok((flow.protocol.get_id(),(flow.client_ip.len() as u8),flow.client_ip.clone(),flow.client_port,flow.server_ip.clone(),flow.server_port));
                    }
                    None => {
                        continue;
                    }
                }
            }
            return Err(());
        }

        /**
         * get_flow
         * - Get the flow for the given packet and filter ID
         * @param id_filter - id of the filter matched
         * @param packet - data of the packet capture
         * @param n_bytes - number of bytes transmitted
         * @param offset - value of offset
         * @param verbose - verbose flag
         * 
        */
        pub fn get_flow(&mut self, id_filter:&u64, packet:&Packet, is_upload: &mut bool, n_bytes: &mut u128, offset: usize, verbose:bool) -> Option<u64>{
            if verbose {println!("|--------------------------select_flow--------------------------");}

            let mut source_ip= Vec::new();
            let mut source_port= 0;
            let mut destination_ip= Vec::new();
            let mut destination_port= 0;
            let mut transport_protocol = TransProtocol::TCP;

            let result = Self::decode_packet(packet,offset,&mut source_ip,&mut source_port,&mut destination_ip,&mut destination_port,&mut transport_protocol, n_bytes,verbose);

            match result{
                Ok(_) => {
                    let destination_hash = calculate_hash(&destination_ip);
                    let op_flows = self.flows.get_mut(id_filter);
                    let tmp = Flow::new(transport_protocol,source_ip,source_port,destination_ip,destination_port);
                    let hash = calculate_hash(&tmp);
                    let tmp2 = tmp.reverse();
                    let hash2 = calculate_hash(&tmp2);

                    match op_flows{
                        Some(filter_flows) => {
                            // ! exist flows for this filter
                            // ! there is not a flow that matches that direction
                            if !filter_flows.contains_key(&hash){
                                // ! neither the oposite direction
                                if !filter_flows.contains_key(&hash2){
                                    // ! if the destination of the packet matches one of the clients, then change source and destination
                                    if self.clients.contains_key(&destination_hash){
                                        if verbose{
                                            println!("\t>[!!] Found Client on destination");
                                            println!("\t>[Created] flow: {}",tmp2);
                                        }
                                        *is_upload=false;
                                        filter_flows.insert(hash2, tmp2);
                                        return Some(hash2);
                                    }
                                    if verbose {println!("\t>[Created] flow: {}",tmp);}
                                    filter_flows.insert(hash, tmp);
                                }else{
                                    if verbose {println!("\t>Found flow: id:{}",hash2);}
                                    *is_upload=false;
                                    return Some(hash2);
                                }
                            }
                            if verbose {println!("\t>Found flow: id:{}",hash);}
                            *is_upload=true;
                            return Some(hash);

                        }
                        None => {
                            // ! does not exist flows for this filter
                            // create flow and add to map
                            let mut map:HashMap<u64,Flow> = HashMap::new();
                            // ! if the destination of the packet matches one of the clients, then change source and destination
                            if self.clients.contains_key(&destination_hash){
                                if verbose{
                                    println!("\t>[!!] Found Client on destination");
                                    println!("\t>[Created] flow: {}",tmp2);
                                }
                                *is_upload=false;
                                map.insert(hash2, tmp2);
                                self.flows.insert(*id_filter, map);
                                return Some(hash2);
                            }
                            *is_upload=true;
                            if verbose {println!("\t>[Created] flow: {}",tmp);}
                            let hash = calculate_hash(&tmp);
                            map.insert(hash, tmp);
                            self.flows.insert(*id_filter, map);
                            return Some(hash);
                        }
                    };
                }
                Err(_) => {
                    if verbose{
                        // println!(".");
                    }
                    None
                }
            }
        }

        /**
         * decode_packet
         * - Decode the packet and extract flow information
         * @param packet               - pointer to packet data
         * @param source_ip             - ip of source
         * @param source_port           - port of source
         * @param destination_ip        - ip of destination
         * @param destination_port      - port of destination
         * @param transport_protocol    - transport protocol
         * @param n_bytes               - number of bytes
         * @param verbose               - verbose flag
        */
        pub fn decode_packet(packet:&Packet, offset: usize, source_ip:&mut Vec<u8>, source_port:&mut u16, destination_ip:&mut Vec<u8>, destination_port:&mut u16, transport_protocol: &mut TransProtocol, n_bytes:&mut u128, verbose:bool) -> Result<(),()>{
            match PacketHeaders::from_ethernet_slice(&packet[offset..]) {
                Err(value) => {
                    println!("Err {:?}", value);
                    return Err(());
                }
                Ok(value) => {
                    // ! if it is possible to withdraw the PacketHeader from the packet data, then get the network and trasnport header
                    let network_header= value.ip;
                    let transport_header= value.transport;

                    match network_header {
                        Some(IpHeader::Version4(ipv4header, _)) => {
                            // ! if the network header matches an IPv4 header, get the ips and number of bytes from the header
                            *source_ip = ipv4header.source.to_vec();
                            *destination_ip = ipv4header.destination.to_vec();
                            *n_bytes = u128::from(ipv4header.payload_len);
                        }
                        Some(IpHeader::Version6(ipv6header, _)) => {
                            // ! if the network header matches an IPv6 header, get the ips and number of bytes from the header
                            *source_ip = ipv6header.source.to_vec();
                            *destination_ip = ipv6header.destination.to_vec();
                            *n_bytes = u128::from(ipv6header.payload_length);
                        }
                        _ => {
                            return Err(());
                        }
                    }

                    match transport_header {
                        Some(TransportHeader::Udp(udp_header)) => {
                            // ! if the transport header matches an UDP header, get the ports from the header
                            *source_port = udp_header.source_port;
                            *destination_port = udp_header.destination_port;
                            *transport_protocol = TransProtocol::UDP;
                        }
                        Some(TransportHeader::Tcp(tcp_header)) => {
                            // ! if the transport header matches an TCP header, get the ports from the header
                            *source_port = tcp_header.source_port;
                            *destination_port = tcp_header.destination_port;
                            *transport_protocol = TransProtocol::TCP;
                        }
                        Some(TransportHeader::Icmpv4(_icmpv4_header)) => {
                            // ! if the transport header matches an TCP header, get the ports from the header
                            *source_port = 0;
                            *destination_port = 0;
                            *transport_protocol = TransProtocol::Icmpv4;
                        }
                        Some(TransportHeader::Icmpv6(_icmpv6_header)) => {
                            // ! if the transport header matches an TCP header, get the ports from the header
                            *source_port = 0;
                            *destination_port = 0;
                            *transport_protocol = TransProtocol::Icmpv6;
                        }
                        _ => {
                            return Err(());
                        }
                    }
                    if verbose{
                        println!("\t-------------packet-------------");
                        println!("\tsource ip: {:?}", source_ip);
                        println!("\tsource port: {}", source_port);
                        println!("\tdestination ip: {:?}", destination_ip);
                        println!("\tdestination port: {}", destination_port);
                        println!("\ttransport Protocol: {:?}", transport_protocol);
                        println!("\tnº bytes: {}", n_bytes);
                        println!("\t--------------------------------\n");
                    }
                    return Ok(());
                }
            }
        }

        /**
         * get_info
         * - Get flow information based on filter and flow IDs
         * @param filter_id         - filter ID
         * @param flow_id           - flow ID
        */
        pub fn get_info(&self,filter_id: &u64,flow_id: &u64) -> Result<(TransProtocol, Vec<u8>, u16, Vec<u8>, u16),String>{
            let x = self.flows.get(filter_id).unwrap().get(
                flow_id
            );
            match x {
                Some(flow) => {
                    return Ok((flow.protocol,flow.client_ip.clone(),flow.client_port,flow.server_ip.clone(),flow.server_port))
                }
                None =>{
                    println!("[Error] flow not found");
                    return Err("No flow found".to_string());
                }
            }
        }

        /**
         * get_info
         * - Remove a flow from the flow table
         * @param flow_id           - flow ID
        */pub fn remove_flow(&mut self, flow_id: &u64) {
            for inner_map in self.flows.values_mut() {
                if let Some(value) = inner_map.remove_entry(flow_id){
                    drop(value);
                    break;
                }
            }
        }

    }

    /**
     * Flow 
     * - Struct representing a flow
     */
     pub struct Flow {
        protocol: TransProtocol,
        client_ip: Vec<u8>,
        client_port: u16,
        server_ip: Vec<u8>,
        server_port: u16,
    }

    impl Flow{
        /**
         * new
         * - Create a new flow instance
         * @param protocol - Protocol used
         * @param client_ip - IP of the client
         * @param client_port - Port of client
         * @param server_ip - IP of the server
         * @param server_port - Port of server
         */
        pub fn new(protocol: TransProtocol,client_ip: Vec<u8>, client_port:u16, server_ip: Vec<u8>,server_port: u16) -> Flow{
            Flow {protocol,client_ip,client_port,server_ip,server_port}
        }

        /**
         * reverse
         * - Reverse the source and destination fields of the flow
         * @param self - Flow object
         */
        pub fn reverse(&self) -> Flow{
            Flow::new(self.protocol,self.server_ip.clone(),self.server_port,self.client_ip.clone(),self.client_port)
        }

    }

    // Implement the Hash trait for Flow
    impl Hash for Flow {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.protocol.hash(state);
            self.client_ip.hash(state);
            self.client_port.hash(state);
            self.server_ip.hash(state);
            self.server_port.hash(state);
        }
    }

    impl fmt::Display for Flow {
        // Implement the Display trait for Flow
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "protocol:{:?} | client_ip: {:?} | client_port: {} | server_ip: {:?} | server_port: {}\n", self.protocol,self.client_ip,self.client_port,self.server_ip,self.server_port)?;
            Ok(())
        }
    }
}
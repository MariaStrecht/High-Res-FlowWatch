use std::{hash::{Hash, Hasher},fs::{OpenOptions,File},collections::HashMap, io::{BufRead, BufReader,Write, BufWriter, Read},collections::{hash_map::DefaultHasher, HashSet}, net::Ipv6Addr};
use chrono::Datelike;
use pcap::Device;
use crate::structures::stats::stats::Stat;

/**
 * print_available_devices
 * - Procedure to print available devices
 * @param vec_devices - Vector of Device objects
*/
pub fn print_available_devices<'a> (vec_devices : &'a Vec<Device>) {
    println!("-Available devices:", );
    for device in vec_devices {
        match device {
            _ => println!("\t* Device {:?} : {:?}", device.name, device.desc),
        }
    }
}

/**
 * get_requested_device
 * - Simple procedure to get the requested device
 * @param requested_device - A single Device structure to save the requested_device device
 * @param vec_devices - A vector of Device objects
*/
pub fn get_requested_device<'a> (requested_device_s : &Vec<String>, requested_devices : &'a mut Vec<Device>, vec_devices : &'a Vec<Device>) -> Result<String,String>{
    for i in 0..requested_device_s.len(){
        let mut found = false;
        requested_devices.insert(i,Device::lookup()
            .expect("device lookup failed")
            .expect("no device available"));
        for device in vec_devices {
            if &*device.name == requested_device_s[i] {
                requested_devices[i].name = device.name.clone();
                requested_devices[i].desc = device.desc.clone();
                found = true;
                break;
            };
        };
        if !found{
            let msg = format!("Device not found (\"{}\")", requested_device_s[i]);
            return Err(msg);
        }
    }
    Ok(format!("Captured devices ({:?})", requested_device_s))
}

/**
 * get_filters
 * - read filters fromn file and load them
 * @param filename - name of file with filters
*/
pub fn get_filters(filename: &str) -> std::io::Result<HashMap<String, String>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let mut map: HashMap<String, String> = HashMap::new();
    
    for line in reader.lines() {
        let lline = line?.replace(";","");
        let vec: Vec<&str> = lline.split(" : ").collect();
        map.insert(vec[0].to_owned(), vec[1].to_owned());
    }

    Ok(map)
}

/**
 * get_map
 * - Transform list of clients given as argument into hashmap
 * @param map - returned hashmap
 * @param vec_clients - list of clients given by the user
*/
pub fn get_map(map: &mut HashMap<u64,Vec<u8>>,vec_clients : &Vec<String>){
    for a in vec_clients{
        let mut ip_vec: Vec<u8> = Vec::new();
        for octet_str in a.split(".") {
            let octet: u8 = octet_str.parse().unwrap();
            ip_vec.push(octet);
        }
        map.insert(calculate_hash(&ip_vec), ip_vec);
    }
}

/**
 * export_data
 * - Function that exports data into binary file
 * @param flow_id - Id of the flow
 * @param fl_definition -flows definition
 * @param stat - Stat object of the flow
 * @param ind - indice of file
 * @param cday - current day
*/
pub fn export_data(flow_id: &u64, fl_definition: &(u8, u8, Vec<u8>, u16, Vec<u8>, u16), stat: &Stat, ind: &mut u16, cday: &mut u32) {
    let (initial, last,map) = stat.get_info();
    let current_date = chrono::Utc::now();
    let c = current_date.day();
    if c!=*cday{
        println!("\nStarting Day: {}",c);
        *cday = c;
        *ind = 0;
    
    }
    let file_name = format!("archive/{:04}{:02}{:02}_{:04}.bin", current_date.year(),current_date.month(),cday,ind);
    let rfile = OpenOptions::new().create(true).append(true).open(file_name);

    match rfile{
        Ok(file) => {
            let mut file = BufWriter::new(file);

            //  initial     last   flow_id    
            // 16 bytes cada
            for a in [&flow_id.to_le_bytes(),&initial.to_le_bytes(),&last.to_le_bytes()]{
                match file.write_all(a){
                    Ok(_)=>{}
                    Err(e) => {println!("Error:{}",e)}
                }
            }

            // protocol: TransProtocol,
            // client_ip: Vec<u8≳,
            // client_port: u16,
            // server_ip: Vec<u8≳,
            // server_port: u16,
            let (protocol, ip_size,c_ip,c_p,s_ip,s_p) = fl_definition;

            // write protocol
            match file.write_all( &protocol.to_le_bytes() ){
                Ok(_)=>{}
                Err(e) => {println!("Error:{}",e)}
            }
            
            // write ips and ports
            // write number of bytes of ips
            match file.write_all( &ip_size.to_le_bytes()){
                Ok(_)=>{}
                Err(e) => {println!("Error:{}",e)}
            }

            // 4 bytes or 16 bytes
            for byte in s_ip{
                match file.write_all( &byte.to_le_bytes()){
                    Ok(_)=>{}
                    Err(e) => {println!("Error:{}",e)}
                }
            }

            // 2 bytes
            match file.write_all(&c_p.to_le_bytes()){
                Ok(_)=>{}
                Err(e) => {println!("Error:{}",e)}
            }

            // 4 bytes or 16 bytes
            for byte in c_ip{
                match file.write_all( &byte.to_le_bytes()){
                    Ok(_)=>{}
                    Err(e) => {println!("Error:{}",e)}
                }
            }

            // 2 bytes
            match file.write_all(&s_p.to_le_bytes()){
                Ok(_)=>{}
                Err(e) => {println!("Error:{}",e)}
            }

            
            // number_of_stats
            // 2 bytes
            match file.write_all( &(map.len() as u16).to_le_bytes() ){
                Ok(_)=>{}
                Err(e) => {println!("Error:{}",e)}
            }
            
            let mut sorted_stats: Vec<_> = map.iter().collect();
            sorted_stats.sort_by_key(|(k, _)| *k);
            for (timestamp,(nb_upload,nb_download,np_upload,np_download)) in sorted_stats {
                match file.write_all(&timestamp.to_le_bytes()){
                    Ok(_)=>{}
                    Err(e) => {println!("Error:{}",e)}
                }
                for a in [&nb_upload.to_le_bytes(),&nb_download.to_le_bytes()]{
                    match file.write_all(a){
                        Ok(_)=>{}
                        Err(e) => {println!("Error:{}",e)}
                    }
                }
                for a in [&np_upload.to_le_bytes(),&np_download.to_le_bytes()]{
                    match file.write_all(a){
                        Ok(_)=>{}
                        Err(e) => {println!("Error:{}",e)}
                    }
                }
            }
            let t = file.flush();
            match t{
                Ok(_)=>{}
                Err(e) => {println!("Error:{}",e)}
            }
        }
        Err(e) => {println!("Error:{}",e)}
    }
    
}


/**
 * read_file
 * - Read Binary file and print information
 * @param path - path to binary file
*/
pub fn read_file(path: &str){
    
    let rfile = File::open(path);

    match rfile{
        Ok(file) => {
            let mut file = BufReader::new(file);
            //  timestamp   filter_id   flow_id    initial
            // 16 bytes cada
            let mut flow_id = [0u8;8];
            let mut initial = [0u8;8];
            let mut last = [0u8;8];
            let mut size = [0u8;2];
            let mut size_int;

            let mut ip_type = [0u8];
            let mut proto = [0u8];
            let mut ip_size;

            let mut s_ip = [0u8;16];
            let mut c_ip = [0u8;16];

            let mut s_p = [0u8;2];
            let mut c_p = [0u8;2];

            // stats
            let mut count_flow: usize = 0;
            let mut count_packet: u64 = 0;
            let mut count_bytes: u128 = 0;
            let mut ipset: HashSet<String> = HashSet::new();
            loop{
                let mut _ip_tmp: String = String::new();
                match read_u64(&mut file,&mut flow_id) {
                    Some(tmp) => {
                        println!("\n[Flow id: {}]", tmp);
                        count_flow+=1;
                    }None=>{break;}
                }

                match read_u64(&mut file,&mut initial) {
                    Some(tmp) => {
                        println!("  Intial Timestamp: {}", tmp);
                    }None=>{break;}
                }

                match read_u64(&mut file,&mut last) {
                    Some(tmp) => {
                        println!("  Last Timestamp:   {}", tmp);
                    }None=>{break;}
                }
                
                match read_u8(&mut file,&mut proto) {
                    Some(tmp) => {
                        match tmp as u8{
                            1=>println!("  Protocol:\tTCP"),
                            2=>println!("  Protocol:\tICMPv4"),
                            3=>println!("  Protocol:\tICMPv6"),
                            _=>println!("  Protocol:\tUDP"),
                        }
                    }None=>{break;}
                }

                match read_u8(&mut file,&mut ip_type) {
                    Some(tmp) => {
                        ip_size = tmp as usize;
                        println!("  IP size:\t{}", ip_size);
                    }None=>{break;}
                }

                // ...
                // read client ip
                if ip_size > 4{
                    let mut tmp_buf = [0u8];
                    for i in 0..16{
                        match read_u8(&mut file,&mut tmp_buf) {
                            Some(tmp) => {
                                c_ip[i]=tmp;
                            }None=>{break;}
                        }
                    }
                    _ip_tmp=ipv6_addr_from_bytes(&c_ip);
                    print!("  Client:\n\tIP:\t{}",_ip_tmp);
                }else{
                    print!("  Client:\n\tIP:\t");
                    _ip_tmp="".to_string();
                    for i in 0..ip_size{
                        let mut tmp_buf = [0u8];
                        match read_u8(&mut file,&mut tmp_buf) {
                            Some(tmp) => {
                                _ip_tmp+=&tmp.to_string();
                                if i!=ip_size-1{
                                    _ip_tmp+=".";
                                }
                            }None=>{break;}
                        } 
                    }
                    print!("{}",_ip_tmp);
                }
                ipset.insert(_ip_tmp);

                // read client port
                match read_u16(&mut file,&mut c_p) {
                    Some(tmp) => {
                        println!("\n\tPort:\t{:?}", tmp);
                    }None=>{break;}
                }

                // read server ip
                if ip_size > 4{
                    let mut tmp_buf = [0u8];
                    for i in 0..16{
                        match read_u8(&mut file,&mut tmp_buf) {
                            Some(tmp) => {
                                s_ip[i]=tmp;
                            }None=>{break;}
                        }
                    }
                    _ip_tmp = ipv6_addr_from_bytes(&s_ip);
                    print!("  Server:\n\tIP:\t{}",_ip_tmp);
                }else{
                    print!("  Server:\n\tIP:\t");
                    _ip_tmp="".to_string();
                    for i in 0..ip_size{
                        let mut tmp_buf = [0u8];
                        match read_u8(&mut file,&mut tmp_buf) {
                            Some(tmp) => {
                                _ip_tmp+=&tmp.to_string();
                                if i!=ip_size-1{
                                    _ip_tmp+=".";
                                }
                            }None=>{break;}
                        } 
                    }
                    print!("{}",_ip_tmp);
                }
                ipset.insert(_ip_tmp);

                // read server port
                match read_u16(&mut file,&mut s_p) {
                    Some(tmp) => {
                        println!("\n\tPort:\t{:?}", tmp);
                    }None=>{break;}
                }

                match read_u16(&mut file,&mut size) {
                    Some(tmp) => {
                        size_int = tmp as i32;
                        println!("  Number of timestamp blocks: {}", size_int);
                    }None=>{break;}
                }

                for i in 0..size_int{
                    let mut timestamp:[u8;8] = [0u8;8];

                    let mut nb_upload:[u8;16] = [0u8;16];
                    let mut nb_download:[u8;16]  = [0u8;16];

                    let mut np_upload:[u8;4]  = [0u8;4];
                    let mut np_download:[u8;4]  = [0u8;4];

                    println!("\t[Stat {}]", i);

                    match read_u64(&mut file,&mut timestamp) {
                        Some(tmp) => {
                            println!("\t - Timestamp: {}", tmp);
                        }None=>{break;}
                    }
                    match read_u128(&mut file,&mut nb_upload) {
                        Some(tmp) => {
                            println!("\t - Bytes upload:\t{}", tmp);
                            count_bytes+=tmp;
                        }None=>{break;}
                    }
                    match read_u128(&mut file,&mut nb_download) {
                        Some(tmp) => {
                            println!("\t - Bytes download:\t{}", tmp);
                            count_bytes+=tmp;
                        }None=>{break;}
                    }
                    match read_u32(&mut file,&mut np_upload) {
                        Some(tmp) => {
                            println!("\t - Packets upload:\t{}", tmp);
                            count_packet+=tmp as u64;
                        }None=>{break;}
                    }
                    match read_u32(&mut file,&mut np_download) {
                        Some(tmp) => {
                            println!("\t - Packets download:\t{}", tmp);
                            count_packet+=tmp as u64;
                        }None=>{break;}
                    }
                }
            }
            println!("\nOverview:");
            println!("- {} Flows stored",count_flow);
            println!("- {} IPs found",ipset.len());
            println!("- {} Packets exchanged",count_packet);
            println!("- {} Bytes exchanged",count_bytes);
        }
        Err(e) => {println!("Error:{}",e)}
    }
}

/// Functions to read binary file
/**
 * read_u8
 * - Helper function to read a u8 value from a file
*/
pub fn read_u8(file: &mut BufReader<File>, buf: &mut [u8;1]) -> Option<u8>{
    match file.read_exact(buf) {
        Ok(_) => {
            let val = u8::from_le_bytes(*buf);
            return Some(val)
        }
        Err(ref err) if err.kind() == std::io::ErrorKind::UnexpectedEof => None,
        Err(e) => {println!("Error:{}",e);None}
    }
}
/**
 * read_u16
 * - Helper function to read a u16 value from a file
*/
pub fn read_u16(file: &mut BufReader<File>, buf: &mut [u8;2]) -> Option<u16>{
    match file.read_exact(buf) {
        Ok(_) => {
            let val = u16::from_le_bytes(*buf);
            return Some(val)
        }
        Err(ref err) if err.kind() == std::io::ErrorKind::UnexpectedEof => None,
        Err(e) => {println!("Error:{}",e);None}
    }
}
/**
 * read_u32
 * - Helper function to read a u32 value from a file
*/
pub fn read_u32(file: &mut BufReader<File>, buf: &mut [u8;4]) -> Option<u32>{
    match file.read_exact(buf) {
        Ok(_) => {
            let val = u32::from_le_bytes(*buf);
            return Some(val)
        }
        Err(ref err) if err.kind() == std::io::ErrorKind::UnexpectedEof => None,
        Err(e) => {println!("Error:{}",e);None}
    }
}
/**
 * read_u64
 * - Helper function to read a u64 value from a file
*/
pub fn read_u64(file: &mut BufReader<File>, buf: &mut [u8;8]) -> Option<u64>{
    match file.read_exact(buf) {
        Ok(_) => {
            let val = u64::from_le_bytes(*buf);
            return Some(val)
        }
        Err(ref err) if err.kind() == std::io::ErrorKind::UnexpectedEof => None,
        Err(e) => {println!("Error:{}",e);None}
    }
}
/**
 * read_u128
 * - Helper function to read a u128 value from a file
*/
pub fn read_u128(file: &mut BufReader<File>, buf: &mut [u8;16]) -> Option<u128>{
    match file.read_exact(buf) {
        Ok(_) => {
            let val = u128::from_le_bytes(*buf);
            return Some(val)
        }
        Err(ref err) if err.kind() == std::io::ErrorKind::UnexpectedEof => None,
        Err(e) => {println!("Error:{}",e);None}
    }
}

/**
 * calculate_hash
 * - Function to calculate a hash value for IP addresses
*/
pub fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

/**
 * ipv6_addr_from_bytes
 * - function to translate array into ipv6 string
*/
pub fn ipv6_addr_from_bytes(bytes: &[u8]) -> String {
    let addr = Ipv6Addr::new(
        (bytes[0] as u16) << 8 | (bytes[1] as u16),
        (bytes[2] as u16) << 8 | (bytes[3] as u16),
        (bytes[4] as u16) << 8 | (bytes[5] as u16),
        (bytes[6] as u16) << 8 | (bytes[7] as u16),
        (bytes[8] as u16) << 8 | (bytes[9] as u16),
        (bytes[10] as u16) << 8 | (bytes[11] as u16),
        (bytes[12] as u16) << 8 | (bytes[13] as u16),
        (bytes[14] as u16) << 8 | (bytes[15] as u16),
    );
    addr.to_string()
}


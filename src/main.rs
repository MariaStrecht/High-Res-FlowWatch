#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

extern crate argparse;
extern crate pcap;
extern crate ctrlc;
pub mod utils;
pub mod structures;

use pcap::{Capture, Device};
use std::{process, sync::{Arc},collections::HashMap, sync::atomic::{Ordering, AtomicUsize}, thread::{self, JoinHandle}, time::{Duration}};
use argparse::{ArgumentParser, Store, StoreTrue, Collect};
use crate::{structures::shared_data::shared_data::SharedData, utils::{get_filters, get_map, print_available_devices, get_requested_device, read_file}};

fn main() -> std::io::Result<()> {

    let mut requested_devices : Vec<Device> = Vec::new();
    // Arguments
    let mut print_devices : bool = false;
    let mut read_binary : String = String::new();
    let mut stat_delta : i32 = 10;
    let mut requested_device_s : Vec<String> = vec!["wlp2s0".to_string()];
    let mut vec_clients = Vec::<String>::new();
    let mut verbose : bool = false;
    let mut erspan : bool = false;
    let mut offset : usize = 0;
    {
        let mut argparse = ArgumentParser::new();
        argparse.set_description("Hot Rust tool");
        argparse.refer(&mut print_devices)
            .add_option(&["-s", "--show_devices"], StoreTrue,
            "Show devices found");
        argparse.refer(&mut read_binary)
            .add_option(&["-b", "--binary"], Store,
            "Read binary file");
        argparse.refer(&mut stat_delta)
                .add_option(&["-i", "--interval"], Store,
                "Provide interval between stats");
        argparse.refer(&mut requested_device_s)
            .add_option(&["-d", "--devices"], Collect,
            "Request a device or multiple devices");
        argparse.refer(&mut vec_clients)
            .add_option(&["-c", "--clients"], Collect,
            "Provide network clients");
        argparse.refer(&mut erspan)
            .add_option(&["-e", "--erspan"], StoreTrue,
            "Enables compatibility to GREP tunnel and ERSPAN protocol");
        argparse.refer(&mut verbose)
            .add_option(&["-v", "--verbose"], StoreTrue,
            "Be verbose");
        // Other options
        argparse.parse_args_or_exit();
    }

    if !read_binary.is_empty() {
        println!("Reading file: {}",read_binary);
        read_file(&read_binary);
        std::process::exit(1);
    }
 
    if !vec_clients.is_empty(){
        println!("Clients:{:?}",vec_clients);
    }

    println!("Interval between stats: {} seconds",stat_delta);

    // if the packets are encapsulated with erspan and gre the offset of the data to be retrieved changes
    if erspan{
        offset = 50;
    }

    // get the requested device
    let devices = Device::list();
    match devices {
        Ok(vec_devices) => {
            if print_devices {
                print_available_devices(&vec_devices);
            }
            println!("Requested_device : {:?}", requested_device_s);
            match get_requested_device(&requested_device_s, &mut requested_devices, &vec_devices) {
                Ok(s) => {
                    if verbose {println!("{}",s);}
                }
                Err(e) => {
                    println!("[Error]: {}",e);
                }
            }
        }
        Err(_) => {
            println!("No devices found...");
            std::process::exit(1);
        },
    }

    for a in &requested_devices{
        if !requested_device_s.contains(&a.name) {
            std::process::exit(1);
        }
    }

    let running = Arc::new(AtomicUsize::new(0));
    let r = running.clone();
    ctrlc::set_handler(move || {
        let prev = r.fetch_add(1, Ordering::SeqCst);
        if prev == 0 {
            println!("Exiting...");
        } else {
            process::exit(0);
        }
    })
    .expect("Error setting Ctrl-C handler");

    //* get the Device and start capture
    let mut clients = HashMap::new();
    let hashmap = get_filters("./assets/filters.txt")?;
    if vec_clients.len()>0{
        get_map(&mut clients, &vec_clients);
    }
    
    //*structures*/
    let sd = SharedData::new(clients,hashmap,offset,stat_delta);
    let mut sd_delete = sd.clone();

    // spawn capture threads, one for each interface
    let mut threads:Vec<JoinHandle<()>> = Vec::new();
    for a in requested_devices{
        let sd_capture = sd.clone();
        let capture_thread = thread::spawn(move || capture_packet(&sd_capture,offset,verbose,a));
        threads.append(&mut vec![capture_thread]);
    }

    // create a thread to delete flows from the program's memory
    let delete_thread = thread::spawn(move || {
        // loop to continuously delete the timed out flows
        loop {
            // if ctrl+c has been typed - stop program
            if running.load(Ordering::SeqCst) > 0 {
                // signal to other threads to stop the program
                sd_delete.stop();
                break;
            }
            thread::sleep(Duration::from_secs(5));

            // time out flows that have been inactive for over 2 minutes
            sd_delete.timeout_flows();
            // delte flows that have been timed out
            sd_delete.remove_flows();

            if verbose{
                println!("packets received:{}",sd_delete.get_packet_count());
            }
        }

    });
    threads.append(&mut vec![delete_thread]);

    // wait for the threads to finish
    for handle in threads{
        let result = handle.join();
        match result {
            Ok(_) =>{}
            Err(r) => {
                println!("{:?}", r);
            }
        }
    }

    // Clean up and exit the program safely
    println!("Exiting gracefully");

    Ok(())
}

pub fn capture_packet(sd_capture : &SharedData, offset: usize, verbose:bool, device: Device){
    let name = device.clone().name;
    let cap_result = Capture::from_device(device) // open the "default" interface
        .unwrap() // assume the device exists and we are authorized to open it
        .open(); // activate the handle
    
    match cap_result{
        Ok(mut cap) =>{
            loop{
                if !sd_capture.get_status(){
                    break;
                }
                // loop to continuously capture packets
                while let Ok(packet) = cap.next_packet() {
                    if !sd_capture.get_status(){
                        break;
                    }
                    // increment packet counter
                    sd_capture.add_packet();
                    
                    // ! received packet
                    // ? does it matches any filter
                    let op_filter = sd_capture.find_filter(&packet);
                    match op_filter{
                        Some(filter_id) => {
                            if verbose {println!("\n[!] Found filter (id:{})",filter_id);}
                            let mut is_upload: bool = true;
                            let mut n_bytes: u128 = 0;

                            // ? does it match any existing flow - if so get its id; if not create a flow an return id
                            let option = sd_capture.get_flowid(&filter_id, &packet,&mut is_upload,&mut n_bytes,offset,verbose);
                            match option{
                                Some(flow_id) => {
                                    if verbose {
                                        println!("\t|-[Flow( id: {})]-------------",flow_id);
                                    }
                                    // if flow found then update its stats
                                    sd_capture.update_stats(flow_id,is_upload,n_bytes,verbose);
                                }
                                None => {
                                    // never happens since a flow id is always returned
                                }
                            }
                        }
                        None => {
                            // if does not match any filter ignore packet
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("\n[Error] : Cannot capture device \"{}\" - {}",name,e);
            println!("\tUse: \"sudo setcap cap_net_admin,cap_net_raw=eip target/debug/flowspy\"");
            std::process::exit(1);
        }
    }
}
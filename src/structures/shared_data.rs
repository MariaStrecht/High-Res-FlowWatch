// Declare the structures module
pub mod shared_data {
    use pcap::Packet;
    use std::{sync::{Arc, Mutex}, collections::HashMap, time::{SystemTime,Duration}};
    use crate::{structures::{flows::flows::FlowTable, stats::stats::StatTable, filters::filters::FilterTable}, utils::export_data};

    /**
     * SharedData
     * - stores the data that need to be accessed by both threads
    */
    pub struct SharedData {
        // Shared reference to FlowTable
        pub flowtable: Arc<Mutex<FlowTable>>,
        // Shared reference to StatTable
        pub stattable: Arc<Mutex<StatTable>>,
        // Shared reference to FilterTable
        pub filtertable: Arc<Mutex<FilterTable>>,
        // Shared reference to a vector of flow IDs and flow definitions that need to be deleted
        pub delete_flows: Arc<Mutex<Vec<(u64, (u8, u8, Vec<u8>, u16, Vec<u8>, u16))>>>,
        // Shared reference to the count of flows
        pub flow_count: Arc<Mutex<u16>>,
        // Shared reference to the file index
        pub file_indice: Arc<Mutex<u16>>,
        // Shared reference to the current day
        pub currentday: Arc<Mutex<u32>>,
        // Shared reference to the isrunning status of the program
        pub isrunning: Arc<Mutex<bool>>,
        // Shared reference to the count of packets
        pub packet_count: Arc<Mutex<u128>>,
    }

    // Implement Clone for SharedData
    // Cloning creates a new instance with shared references to the same internal data
    impl Clone for SharedData {
        fn clone(&self) -> Self {
            SharedData {
                flowtable: Arc::clone(&self.flowtable),
                stattable: Arc::clone(&self.stattable),
                filtertable: Arc::clone(&self.filtertable),
                delete_flows: Arc::clone(&self.delete_flows),
                flow_count: Arc::clone(&self.flow_count),
                file_indice: Arc::clone(&self.file_indice),
                currentday: Arc::clone(&self.currentday),
                isrunning: Arc::clone(&self.isrunning),
                packet_count:  Arc::clone(&self.packet_count),
            }
        }
    }

    impl SharedData {

        /**
         * new
         * - Constructor for SharedData
         * @param clients - map with clients defined by the user, where key is key and value is the ip
         * @param hashmap - map with filters, where key is the name of the filter and value is the bpf syntax of the rule's filter
         * @param offset - value of offset
         * @param delta - value of delta
        */
        pub fn new(clients:HashMap<u64,Vec<u8>>, hashmap: HashMap<String,String>, offset: usize, delta: i32) -> SharedData{
            SharedData { flowtable: Arc::new(Mutex::new(FlowTable::new(clients))), stattable: Arc::new(Mutex::new(StatTable::new(delta))), filtertable: Arc::new(Mutex::new(FilterTable::new(hashmap, offset))), delete_flows: Arc::new(Mutex::new(Vec::new())), isrunning: Arc::new(Mutex::new(true)), flow_count:  Arc::new(Mutex::new(0)), file_indice:  Arc::new(Mutex::new(0)),currentday: Arc::new(Mutex::new(0)),packet_count:Arc::new(Mutex::new(0))  }
        }

        /**
         * get_flowid
         * - Function to get flow id based on packet with access control
         * @param filter_if - id of filter
         * @param packet    - packet object
         * @param is_upload - bool to know if is upload or download
         * @param n_bytes   - number of bytes received/sent
         * @param verbose   - bool if verbose is active
        */
        pub fn get_flowid(&self,filter_id: &u64, packet: &Packet,mut is_upload: &mut bool,mut n_bytes: &mut u128, offset: usize, verbose:bool) -> Option<u64> {
            // Acquire a lock on the flowtable field
            let mut l_sd_flows = self.flowtable.lock().unwrap();
            // Call the get_flow method of FlowTable to get the flow ID
            l_sd_flows.get_flow(filter_id, &packet,&mut is_upload,&mut n_bytes,offset, verbose)
        }

        
        /**
         * find_filter
         * - Function to get flow ID based on packet with access control
         * @param packet - packet object
        */
        pub fn find_filter(&self, packet: &Packet) -> Option<u64>{
            // Acquire a lock on the filtertable field
            let l_sd_filters = self.filtertable.lock().unwrap();
            // Call the find_filter method of FilterTable to find the filter ID
            l_sd_filters.find_filter(&packet)
        }

        /**
         * update_stats
         * - Function to update the statistics of a flow
         * @param flow_id   - id of flow
         * @param is_upload - bool to know if is upload or download
         * @param n_bytes   - number of bytes received/sent
        */
        pub fn update_stats(&self, flow_id: u64, is_upload: bool, n_bytes: u128, verbose:bool){
            // Acquire a lock on the stattable field
            let mut lock2 = self.stattable.lock().unwrap();
            // Call the st_update method of StatTable to update the statistics
            lock2.update(flow_id, is_upload, n_bytes,verbose)
        }

        /**
         * timeout_flows
         * - Function to process flows that have timed out
        */
        pub fn timeout_flows(&self){
            // Acquire locks on stattable, delete_flows, flow_count, and file_indice fields
            let l_sd_stats = self.stattable.lock().unwrap();
            let mut l_delete_flows = self.delete_flows.lock().unwrap();
            let x = l_sd_stats.get_stats();
            let mut l_flow_count = self.flow_count.lock().unwrap();
            let mut l_file_indice = self.file_indice.lock().unwrap();
            
            // Iterate over the statistics in stattable
            for (flow_id, stat) in x{
                // check if any flow has timed out
                // Calculate the time elapsed since the last packet of the flow
                let c_timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap()-Duration::from_secs(120);
                if c_timestamp.as_secs()>*stat.get_last(){
                    // if so add to the list
                    let s = l_delete_flows.len();
                    let lock10 = self.flowtable.lock().unwrap();
                    let r_fil = lock10.flow_definition(flow_id);
                    match r_fil{
                        Ok(a) => {
                            l_delete_flows.insert(s,(*flow_id,a));

                            if *l_flow_count==60000{
                                *l_flow_count=0;
                                *l_file_indice+=1;
                            }
                            *l_flow_count+=1;
                        }
                        Err(())=>{
                            continue;
                        }
                    }
                }
            }
        }

        
        /**
         * remove_flows
         * - Function to remove flows from structures that timed out with access control
        */
        pub fn remove_flows(&mut self){
            let mut l_sd_flows = self.flowtable.lock().unwrap();
            let mut l_sd_stats = self.stattable.lock().unwrap();
            let mut l_delete_flows = self.delete_flows.lock().unwrap();
            let mut l_file_indice = self.file_indice.lock().unwrap();
            let mut l_currentday = self.currentday.lock().unwrap();

            // * delete flow
            for (f,fil) in &*l_delete_flows{
                let x = l_sd_stats.get_stat(f);
                match x{
                    Some(stat) => {
                        export_data(&f, fil, stat, &mut *l_file_indice,&mut *l_currentday);
                        // ! delete from Stats Table
                        l_sd_stats.remove_flow(&f);
                        // ! delete from Flows Table
                        l_sd_flows.remove_flow(&f);
                        println!("|-Flow (id:{}) is dropped",f);
                    }
                    None=>{}
                }
            }
            
            *l_delete_flows = Vec::new();
        }

        /**
         * stop
         * - Function to signal to threads to stop the program with access control
        */
        pub fn stop(&self) {
            let mut l_running= self.isrunning.lock().unwrap();
            *l_running = false;
        }
        
        /**
         * status
         * - Get current status of process
        */
        pub fn get_status(&self) -> bool{
            let l_running= self.isrunning.lock().unwrap();
            return *l_running;
        }


        /**
         * get_packet_count
         * - Function to get the packet count
        */
        pub fn get_packet_count(&self) -> u128 {
            // Acquire a lock on the packet_count field
            let packet_count = self.packet_count.lock().unwrap();
            // Return the packet count
            *packet_count
        }

        /**
         * add_packet
         * - Function to update the packet count
        */
        pub fn add_packet(&self){
            let mut l_packet_count = self.packet_count.lock().unwrap();
            *l_packet_count+=1;
        }

   
    }
}
// Declare the structures module
pub mod stats {
    use std::{collections::HashMap,time::SystemTime,fmt};

    /**
     * StatTable 
     * - stores the stats based on their flow
     */
    pub struct StatTable {
        stats: HashMap<u64, Stat>, // HashMap to store flow statistics
        delta: i32, // Delta value for timestamp calculation
    }

    impl StatTable{
        /**
         * new
         * - Constructor for StatTable
         * @param delta - value of delta
        */
        pub fn new(delta: i32) -> StatTable {
            StatTable {
                stats: HashMap::new(),
                delta
            }
        }

        /**
         * get_stats
         * - get stats hashmap
        */
        pub fn get_stats(&self) -> &HashMap<u64,Stat>{
            return &self.stats;
        }
        
        /**
         * get_stat
         * - get Stat object from a flow
         * @param flow_id   - id of flow
        */
        pub fn get_stat(&self, flow_id: &u64) -> Option<&Stat>{
            return self.stats.get(flow_id);
        }

        /**
         * update
         * - updates stats of flow
         * @param flow_id   - id of flow
         * @param is_upload - bool that tells if it is upload or download
         * @param n_bytes   - number of bytes exchanged
         * @param verbose   - bool if verbose is active
        */
        pub fn update(&mut self, flow_id: u64, is_upload: bool,n_bytes: u128, verbose:bool){
            let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
            match self.stats.get_mut(&flow_id){
                Some(stat) => {
                    // ! if exists an Stat on the table for that flow, update it
                    stat.update(timestamp, is_upload,n_bytes,&self.delta);
                    if verbose { println!("{}",stat);}
                }
                None => {
                    // ! if not initiate it
                    let tmp = Stat::new(timestamp, is_upload, n_bytes);
                    if verbose { println!("{}",tmp);}
                    self.stats.insert(flow_id, tmp);
                }   
            }
        }

        /**
         * remove_flow
         * - remove flow from stats
         * @param flow_id   - id of flow
        */pub fn remove_flow(&mut self,flow_id: &u64){
            if let Some(value) = self.stats.remove_entry(flow_id){
                // Explicitly drop the value to deallocate it
                drop(value);
            }
        }
    }


    impl IntoIterator for StatTable {
        type Item = (u64 , Stat);
        type IntoIter = std::collections::hash_map::IntoIter<u64, Stat>;

        fn into_iter(self) -> Self::IntoIter {
            self.stats.into_iter()
        }
    }

    /**
     * Stat 
     * - stores the information of a Stat
     * - nº bytes and nº of packets of upload and download
     */
    pub struct Stat{
        // structure to store the statistics of a flow
        // timestamp ,(nº bytes upload, nº bytes download, nº packets upload, nº packets download)
        stats: HashMap<u64,(u128,u128,u32,u32)>,
        initial_timestamp: u64, // first timestamp
        last_timestamp: u64, // last timestamp
    }
    impl Stat{
        /**
         * new
         * - Constructor for Stat
         * @param timestamp - timestamp value
         * @param is_upload - bool that tells if it is upload or download
         * @param n_bytes   - number of bytes exchanged
        */
        pub fn new(timestamp:u64, is_upload: bool, n_bytes:u128) -> Stat{
            let mut x: HashMap<u64,(u128,u128,u32,u32)> = HashMap::new();
            let y = if is_upload { (n_bytes,0,1,0) } else { (0,n_bytes,0,1) };
            x.insert(timestamp, y);
            Stat {stats : x, initial_timestamp: timestamp, last_timestamp:timestamp}
        }

        /**
         * get_last
         * - gets last timestamp of packet
        */
        pub fn get_last(&self) -> &u64{
            return &self.last_timestamp;
        }

        /**
         * get_indice
         * - gets indice in hashmap based on timestamp of packet
         * @param timestamp - packet timestamp
         */
        pub fn get_indice(&self, timestamp:&u64, delta: &i32) -> u64{
            let tdelta = (((*timestamp as f64)-(self.initial_timestamp as f64)) / (*delta as f64)).floor() as u64;
            return self.initial_timestamp+(tdelta*(*delta as u64));
        }

        /**
         * update
         * - updates stats of flow
         * @param timestamp - current timestamp
         * @param is_upload - bool that tells if it is upload or download
         * @param n_bytes   - number of bytes exchanged
        */
        pub fn update(&mut self, timestamp:u64, is_upload: bool, n_bytes:u128, delta: &i32){
            let y = if is_upload { (n_bytes,0,1,0) } else { (0,n_bytes,0,1) };
            
            if self.stats.len()>0 {
                // get the indice of the current timestamp
                let blk_timestamp = self.get_indice(&timestamp,delta);
                let op = self.stats.get_mut(&blk_timestamp);
                match op{
                    Some(current) =>{
                        // ! if the stats have been already initiated, then add the current stats
                        // println!("\t\tStats: {:?}",current);
                        current.0+=y.0;
                        current.1+=y.1;
                        current.2+=y.2;
                        current.3+=y.3;
                    }
                    None => {
                        // ! if not initiate it
                        self.stats.insert(blk_timestamp, y);
                        self.last_timestamp = blk_timestamp;
                    }
                }
            }
        }

        /**
         * get_info
         * - get information of stat
        */
        pub fn get_info(&self) ->(&u64, &u64, &HashMap<u64,(u128,u128,u32,u32)>){
            return (&self.initial_timestamp,&self.last_timestamp,&self.stats);
        }

    }

    // function to display stat
    impl fmt::Display for Stat {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let mut sorted_stats: Vec<_> = self.stats.iter().collect();
            sorted_stats.sort_by_key(|(k, _)| *k);
            for (k, v) in sorted_stats {
                writeln!(f, "\t\tTimestamp: {}", (*k as f64))?;
                writeln!(f, "\t\t|-Bytes upload: {}", v.0)?;
                writeln!(f, "\t\t|-Bytes download: {}", v.1)?;
                writeln!(f, "\t\t|-Packets upload: {}", v.2)?;
                writeln!(f, "\t\t|-Packets download: {}", v.3)?;
            }
            Ok(())
        }
    }
}
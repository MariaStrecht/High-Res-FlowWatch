// Declare the structures module
pub mod filters {
    use pcap::{BpfProgram, Linktype, Capture, Packet};
    use std::collections::HashMap;
    use std::{fmt, process};
    use crate::utils::calculate_hash;

    /**
     * FilterTable 
     * - Structure to store all filters and related information
     */
    pub struct FilterTable {
        filters: HashMap<u64, Filter>, // HashMap to store filters with their IDs
        basefilters: (Filter, Filter), // Base filters for IP and IPv6 packets
        offset: usize, // Offset value
    }

    impl FilterTable{
        /**
         * new
         * - Creates a new FilterTable with provided filter map and offset
         * @param map    - map with filters to be loaded, with key as filter name and value as bpf syntax rule
         * @param offset - offset value 
        */
        pub fn new(map: HashMap<String, String>, offset:usize) -> FilterTable {
            // Initialize a new FilterTable with empty filter map and base filters.
            // Set the offset value.
            let mut tmp = FilterTable {
                filters: HashMap::new(),
                basefilters: (Filter::new("ip".to_string(),"basefilter1".to_string()),Filter::new("ip6".to_string(),"basefilter2".to_string())),
                offset: offset+14,
            };
            tmp.load(map); // Load filters from the provided map into the filter table.
            tmp // Return the initialized FilterTable.
        }

        /**
         * load
         * - Loads filters into the filter table
         * @param map - map with filters to be loaded, with key as filter name and value as bpf syntax rule
        */
        pub fn load(&mut self, map: HashMap<String, String>){
            for (name, rule) in map {
                let filter = Filter::new(rule, name);
                self.filters.insert(calculate_hash(&filter.rule), filter);
            }
            println!("\n----------| Filters |----------");
            println!("{}",self);// Print the filters in the filter table.
        }

        /**
         * find_filter
         * - Find a filter that matches the given packet and return its ID
         * @param packet - pointer to packet data
        */
        pub fn find_filter(&self, packet: &Packet) -> Option<u64>{
            if packet.len() > self.offset && self.is_ippacket(&packet[self.offset..]){
                for (id, fil) in &self.filters{
                    if fil.program.filter(&packet[self.offset..]){
                        return Some(*id);
                    }
                }
            }
            return None;// No matching filter found.
        }

        /**
         * is_ippacket
         * - Check if the given packet has an IP header
         * @param buf - packet data in a buffer in bytes
        */
        pub fn is_ippacket(&self, buf: &[u8]) -> bool{
                return self.basefilters.0.program.filter(buf) || self.basefilters.1.program.filter(buf);
        }

    }

    
    
    impl fmt::Display for FilterTable {
        // Display implementation for FilterTable
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            for (_rule,filter) in &self.filters {
                let _lt = match filter.fmt(f) {
                    Ok(lt) => lt,
                    Err(_) => {
                        println!("Invalid filter");
                        process::exit(1);
                    }
                };
            }
            Ok(())
        }
    }

    /**
     * Filter 
     * - Represents a filter with its name, rule, and compiled BPF program
     */
    pub struct Filter{
        name: String, // name of Filter
        rule: String, // rule in bpf syntax of Filter
        program: BpfProgram, // compiled bpfprogram of Filter
    }

    impl Filter{
        /**
         * new
         * - Create a new Filter with the given rule and name
         * @param rule - rule in BPF syntax
         * @param name - name of Filter
        */
        pub fn new(rule: String, name: String) -> Filter{
            let layertype = "RAW".to_string();

            let lt = match Linktype::from_name(&layertype) {
                Ok(t) => t,
                Err(_) => {
                    println!("Invalid linklayer type {}", layertype);
                    process::exit(1);
                }
            };

            // creates dead capture to generate BpfProgram, used to filter packets
            let capture = Capture::dead(lt).unwrap();
            let program: BpfProgram = match capture.compile(&rule, true) {
                Ok(p) => p,
                Err(e) => {
                    println!("{:?}", e);
                    process::exit(1);
                }
            };
            
            Filter {name, rule, program} // Return the initialized Filter.
        }

    }

    impl fmt::Display for Filter {
        // Display implementation for Filter
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "name:{} | rule: {}\n", self.name,self.rule)?;
            Ok(())
        }
    }
}
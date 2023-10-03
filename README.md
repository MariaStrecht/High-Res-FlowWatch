# FlowSpy
- Código da tese

## Project Structure
```bash
.
├── assets
│   └── filters.txt
│   └── filters2.txt
├── Cargo.lock
├── Cargo.toml
├── README.md
└── src
    ├── main.rs
    ├── structures
    │   ├── filters.rs
    │   ├── flows.rs
    │   └── shared_data.rs
    │   └── stats.rs
    ├── structures.rs
    └── utils.rs
└── scripts
    ├── memory_usage.sh
    ├── packets_dropped.sh
```
## How to build the software
- build:
  `cargo build`
- permit software to access interface:
  `sudo setcap cap_net_admin,cap_net_raw=eip target/debug/flowspy`
## Usage
To know how to use `flowspy`, use this command: `cargo run -- -h`. The output is shown bellow:

```bash
Usage:
  target/debug/flowspy [OPTIONS]

Hot Rust tool

Optional arguments:
  -h,--help              Show this help message and exit
  -s,--show_devices      Show devices found
  -b,--binary BINARY     Read binary file
  -i,--interval INTERVAL Provide interval between stats
  -d,--devices DEVICES   Request a device or multiple devices
  -c,--clients CLIENTS   Provide network clients
  -e,--erspan            Enables compatibility to GREP tunnel and ERSPAN protocol
  -v,--verbose           Be verbose
```
- Consider that to add arguments to the rust program it is necessary to add "--" before the other arguments!

In the testing environment used, it was run the command:
`cargo run -- -d ens192 -e`
- This command initiates the monitoring software in the network interface "ens192" with the ERSPAN and GREP encapsulation flag on.



## Crates
- [pcap](https://docs.rs/pcap/1.0.0/pcap/) = "1.0.0"
- [etherparse](https://docs.rs/etherparse/latest/etherparse/#) = "0.13.0"
- [ctrlc](https://docs.rs/crate/ctrlc/3.2.5) = "3.2.5"
- [chrono](https://docs.rs/chrono/latest/chrono/) = "0.4.24"

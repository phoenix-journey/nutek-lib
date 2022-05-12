/// # networking capabilities
/// 
/// currently uses nmap & rustscan
/// planned features are gobuster,
/// raccoon, nmap-analyze and others
/// like recon-ng, metasploit...
pub mod scanners {
    use std::path::Path;
    use std::time::{SystemTime};
    use std::{fs, time};
    use docker_api::{Exec};
    use docker_api::api::{ExecContainerOpts};
    use futures::{StreamExt};
    use std::io::Error;

    /// rustscan 2.1.0
    /// Fast Port Scanner built in Rust. WARNING Do not use this program against sensitive infrastructure since the specified
    /// server may not be able to handle this many socket connections at once. - Discord https://discord.gg/GFrQsGy - GitHub
    /// https://github.com/RustScan/RustScan
    /// 
    /// USAGE:
    ///     rustscan [FLAGS] [OPTIONS] [-- <command>...]
    /// 
    /// FLAGS:
    ///         --accessible    Accessible mode. Turns off features which negatively affect screen readers
    ///     -g, --greppable     Greppable mode. Only output the ports. No Nmap. Useful for grep or outputting to a file
    ///     -h, --help          Prints help information
    ///     -n, --no-config     Whether to ignore the configuration file or not
    ///        --top           Use the top 1000 ports
    ///     -V, --version       Prints version information
    /// 
    /// OPTIONS:
    ///     -a, --addresses <addresses>...    A list of comma separated CIDRs, IPs, or hosts to be scanned
    ///     -b, --batch-size <batch-size>     The batch size for port scanning, it increases or slows the speed of scanning.
    ///                                     Depends on the open file limit of your OS.  If you do 65535 it will do every port
    ///                                     at the same time. Although, your OS may not support this [default: 4500]
    ///     -p, --ports <ports>...            A list of comma separed ports to be scanned. Example: 80,443,8080
    ///     -r, --range <range>               A range of ports with format start-end. Example: 1-1000
    ///         --scan-order <scan-order>     The order of scanning to be performed. The "serial" option will scan ports in
    ///                                     ascending order while the "random" option will scan ports randomly [default:
    ///                                     serial]  [possible values: Serial, Random]
    ///         --scripts <scripts>           Level of scripting required for the run [default: default]  [possible values:
    ///                                     None, Default, Custom]
    ///     -t, --timeout <timeout>           The timeout in milliseconds before a port is assumed to be closed [default: 1500]
    ///         --tries <tries>               The number of tries before a port is assumed to be closed. If set to 0, rustscan
    ///                                     will correct it to 1 [default: 1]
    ///     -u, --ulimit <ulimit>             Automatically ups the ULIMIT with the value you provided
    ///
    /// ARGS:
    ///     <command>...    The Script arguments to run. To use the argument -A, end RustScan's args with '-- -A'. Example:
    ///                     'rustscan -T 1500 -a 127.0.0.1 -- -A -sC'. This command adds -Pn -vvv -p $PORTS automatically to
    ///                     nmap. For things like --script '(safe and vuln)' enclose it in quotations marks \"'(safe and
    ///                     vuln)'\"")
    pub async fn rustscan_help() -> Result<(), Error> {
        let docker = &connect_to_docker_api();

        let nutek_core_id = 
            create_nutek_core(docker.clone())
            .await;
        let nutek_id = nutek_core_id.as_str();
        start_nutek_core(docker.clone(), nutek_id).await;
        
        let options = ExecContainerOpts::builder()
            .cmd(vec!["rustscan", "--help"])
            .attach_stdout(true)
            .attach_stderr(true)
            .working_dir("/root")
            .build();
        let exec = Exec::create(
            docker, 
            nutek_id, 
            &options
        ).await;
        let mut stream = exec
            .expect("not execed").start();
        
        while let Some(tty) = stream.next().await {
            let i = tty.unwrap();
            let chunk = i.to_vec();
            println!("{}", String::from_utf8_lossy(&chunk));
        }
        Ok(())
    }

    /// # Rustscan
    ///
    /// dummy wrapper around RustScan
    /// 
    /// mostly used in aggressive scanning, fast port discovery
    /// 
    /// ## Arguments:
    /// 
    /// * `cmd: String` arguments for fastscan
    /// 
    /// ## Output:
    /// 
    /// * filename suffix which is the key in
    /// 
    ///     `.nutek/network_scan` folder
    /// * writes raw command output
    /// 
    ///     to `rustscan_cmd_`_suffix_`.txt`
    /// 
    /// ## Examples
    /// 
    /// Rage port scan:
    /// ```
    /// use crate::nutek_lib::network::rustscan;
    /// #[tokio::main]
    /// async fn rage_scan() {
    ///     let suffix = rustscan(
    ///         "--addresses scanme.nmap.org".to_string()
    ///     ).await;
    /// }
    /// ```
    pub async fn rustscan(cmd: String) -> Result<String, Error> {

        let command = cmd.split_ascii_whitespace();
        let mut cmd: Vec<String> = command.map(|x| x.to_string()).collect();
        
        let docker = &connect_to_docker_api();
        
        let suffix: u128 = match SystemTime::now().duration_since(time::UNIX_EPOCH) {
            Ok(n) => {
                n.as_micros()
            },
            Err(_) => panic!("SystemTime before UNIX EPOCH!"),
        };
        let help_dash_dash = cmd.iter().position(|r| r == "--help");//.unwrap();
        let help_dash = cmd.iter().position(|r| r == "-h");//.unwrap();
        if help_dash == None && help_dash_dash == None {
            cmd.append(&mut vec!["-oX".to_string(), 
                format!("/root/.nutek/network_scan/scan_result_{}.xml", suffix)]);
        }
        let nutek_core_id = 
            create_nutek_core(docker.clone())
            .await;
        let nutek_id = nutek_core_id.as_str();
        start_nutek_core(docker.clone(), nutek_id).await;
        
        let options = ExecContainerOpts::builder()
            .cmd(cmd)
            .attach_stdout(true)
            .attach_stderr(true)
            .working_dir("/root")
            .build();
        let exec = Exec::create(
            docker, 
            nutek_id, 
            &options
        ).await;
        let mut stream = exec
            .expect("not execed").start();
        
        let mut cmd_result = String::from("");
        while let Some(tty) = stream.next().await {
            let i = tty.unwrap();
            let chunk = i.to_vec();
            println!("{}", String::from_utf8_lossy(&chunk));
            cmd_result = format!("{}{}", cmd_result, String::from_utf8_lossy(&chunk));
        }
        stop_nutek_core(docker.clone(), nutek_id).await;
        remove_nutek_core(docker.clone(), nutek_id).await;
        fs::write(format!("{}/.nutek/network_scan/rustscan_cmd_{}.txt", 
            home::home_dir().unwrap().display(),
            suffix),
        cmd_result.clone())
            .expect("unable to write report file");
        Ok(format!("{}", suffix))
    }

    /// # Run any command...
    /// 
    /// ...inside nutek-core container
    /// 
    /// ## Arguments:
    /// 
    /// * `cmd: String` - the _command_
    /// 
    /// ## Output:
    /// 
    /// * filename **suffix** which is the key in
    /// 
    ///     `.nutek/run_cmd/terminal_cmd_`*suffix*`.txt`
    /// 
    /// ## Examples
    /// 
    /// ```
    /// #[tokio::main]
    /// async fn run() {
    ///     let suffix = nutek_lib::network::run_cmd(
    ///         "echo 'Hi Nutek!'".to_string()
    ///     ).await.expect("Nutek no run :(");
    /// }
    /// ```
    pub async fn run_cmd(cmd: String) -> Result<String, Error> {
        let command = cmd.split_ascii_whitespace();
        let cmd: Vec<String> = command.map(|x| x.to_string()).collect();
        let cmdlet = cmd.get(0).unwrap().to_owned();
        let docker = &connect_to_docker_api();
        let suffix: u128 = match SystemTime::now().duration_since(time::UNIX_EPOCH) {
            Ok(n) => {
                n.as_micros()
            },
            Err(_) => panic!("SystemTime before UNIX EPOCH!"),
        };
        let nutek_core_id = 
            create_nutek_core(docker.clone())
            .await;
        let nutek_id = nutek_core_id.as_str();
        start_nutek_core(docker.clone(), nutek_id).await;
        let options = ExecContainerOpts::builder()
            .cmd(cmd)
            .attach_stdout(true)
            .attach_stderr(true)
            .working_dir("/root")
            .build();
        let exec = Exec::create(
            docker, 
            nutek_id, 
            &options
        ).await;
        let mut stream = exec
            .expect("not execed").start();
        
        let mut cmd_result = String::from("");
        while let Some(tty) = stream.next().await {
            let i = tty.unwrap();
            let chunk = i.to_vec();
            println!("{}", String::from_utf8_lossy(&chunk));
            cmd_result = format!("{}{}", cmd_result, String::from_utf8_lossy(&chunk));
        }
        fs::write(format!("{}/.nutek/run_cmd/{}_cmd_{}.txt", 
            home::home_dir().unwrap().display(),
            cmdlet,
            suffix),
        cmd_result.clone())
            .expect("unable to write report file");
        stop_nutek_core(docker.clone(), nutek_id).await;
        remove_nutek_core(docker.clone(), nutek_id).await;
        Ok(format!("{}", suffix))
    }

    use std::{
        fs::File,
        io::{prelude::*, BufReader},
    };

    use crate::docker::runners::{create_nutek_core, start_nutek_core, stop_nutek_core, remove_nutek_core, connect_to_docker_api};
    
    fn lines_from_file(filename: impl AsRef<Path>) -> Vec<String> {
        let file = File::open(filename).expect("no such file");
        let buf = BufReader::new(file);
        buf.lines()
            .map(|l| l.expect("Could not parse line"))
            .collect()
    }

    /// # Make a website from Nmap XML
    /// 
    /// now you see me... and browse me
    /// 
    /// ## Arguments:
    /// 
    /// - Interchangeably, provide one, second
    /// 
    ///     empty like `*""`
    /// 
    ///     * `file` - custom xml file, somewhere in `.nutek`
    /// 
    ///         folder
    ///     * `suffix` - mostly for programming, 
    /// 
    ///         but you can extract the number from file
    /// 
    ///         name in `.nutek/network_scan` folder
    /// 
    ///         and work with that.
    /// 
    /// ## Output:
    /// 
    /// * writes webisite with report
    ///     in `.nutek/network_scan/scan_`_suffix_`.html`
    /// 
    /// * returns `path` to created website with report
    /// 
    /// ## Examples
    /// 
    /// ```
    /// #[tokio::main]
    /// async fn website() {
    ///     let path = 
    ///         nutek_lib::network::nmap_xml_to_html(String::from(""), String::from(""))
    ///         .await.expect("no browse");
    ///     println!("{}", path);
    /// }
    /// ```
    pub async fn nmap_xml_to_html(file: String, suffix: String) -> Result<String, Error> {
        let mut report_path = String::from("");
        if file == *"" && suffix != *"" {
            run_cmd(format!("xsltproc /root/.nutek/network_scan/scan_result_{}.xml 
                -o /root/.nutek/network_scan/scan_{}.html", suffix, suffix))
                .await.expect("can't creat nmap html report");
            report_path = format!("{}/.nutek/network_scan/scan_{}.html",
                home::home_dir().unwrap().display(),
                suffix);
        } else if file != *"" && suffix == *"" {
            let suffix: u128 = match SystemTime::now().duration_since(time::UNIX_EPOCH) {
                Ok(n) => {
                    n.as_micros()
                },
                Err(_) => panic!("SystemTime before UNIX EPOCH!"),
            };
            fs::copy(file, 
                format!("{}/.nutek/network_scan/scan_{}.xml", 
                home::home_dir().unwrap().display(),
                suffix))
                .expect("can't copy file to nmap folder");
            let mut lines = lines_from_file(
                format!("{}/.nutek/network_scan/scan_{}.xml",
                    home::home_dir().unwrap().display(), suffix));
            lines[2] = r#"<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>"#.to_string();
            // }
            let mut f = File::create(
                format!("{}/.nutek/network_scan/scan_{}.xml",
                home::home_dir().unwrap().display(), suffix))
                .expect("unable to create xml file");                                                                                                          
            for i in &lines{                                                                                                                                                                  
                f.write_all(i.as_bytes()).expect("unable to write data to xml stage file");                                                                                                                            
            }
            run_cmd(format!("xsltproc /root/.nutek/network_scan/scan_{}.xml
            -o /root/.nutek/network_scan/scan_{}.html", suffix, suffix))
                .await.expect("can't creat nmap html report from file");
            report_path = format!("{}/.nutek/network_scan/scan_{}.html",
                home::home_dir().unwrap().display(),
                suffix);
        }
        Ok(report_path)
    }

    /// # Open file in graphical user interface
    /// 
    /// ## Arguments
    /// 
    /// * path - system path to your file
    /// 
    /// ## Outputs
    /// 
    /// Open system default program for 
    /// 
    /// the file in question
    pub async fn open_nmap_html_report(path: String) -> Result<(), Error> {
        open::that(format!("{}",
            path).to_string())
            .expect("can't open nmap scan website with report");
        Ok(())
    }
}
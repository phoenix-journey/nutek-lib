pub mod hello {
    /// This is my cat's drawing of the key
    /// ___
    ///
    /// # Examples
    ///
    /// ```
    /// // Draw a key
    /// // If you pass --test to `rustdoc`, it will even test it for you!
    /// let person = nutek_lib::hello::hi_nutek();
    /// println!("{}", person);
    /// ```
    pub fn hi_nutek() -> &'static str {
        r#"::::    ::: :::    ::: ::::::::::: :::::::::: :::    ::: 
:+:+:   :+: :+:    :+:     :+:     :+:        :+:   :+:  
:+:+:+  +:+ +:+    +:+     +:+     +:+        +:+  +:+   
+#+ +:+ +#+ +#+    +:+     +#+     +#++:++#   +#++:++    
+#+  +#+#+# +#+    +#+     +#+     +#+        +#+  +#+   
#+#   #+#+# #+#    #+#     #+#     #+#        #+#   #+#  
###    ####  ########      ###     ########## ###    ### 😼
Neosb @museyoucoulduse
"#
    }
}

/// # Docker
/// 
/// docker specific set of functions
/// 
/// create, start, stop, remove
pub mod docker {
    use docker_api::{Docker, api::ContainerCreateOpts};

    #[cfg(unix)]
    fn new_docker() -> docker_api::Result<Docker> {
        Ok(Docker::unix("/var/run/docker.sock"))
    }
        
    #[cfg(not(unix))]
    fn new_docker() -> docker_api::Result<Docker> {
        Docker::new("http:\\localhost:2375")
    }

    /// connect to docker api 
    pub fn connect_to_docker_api() -> Docker {
        new_docker()
            .expect("no Docker!")
    }

    /// create nutek-core container
    /// 
    /// basically everything starts here
    pub async fn create_nutek_core(docker: Docker) -> String {
        let container_name_base = "nutek-core";
        let name = format!("{}-{}", container_name_base, uuid::Uuid::new_v4());
        let core_img = "neosb/nutek-core:latest";
        let opts = 
            ContainerCreateOpts::builder(core_img)
            .name(name)
            .attach_stdout(true)
            .attach_stderr(true)
            .attach_stdin(true)
            .volumes([format!("{}/.nutek:/root/.nutek", home::home_dir().unwrap().display())])
            .build();
        let d = docker.containers()
            .create(&opts)
            .await
            .expect("nutek-core not created").id().to_string();
        d
    }

    /// start nutek-core container
    /// 
    /// for nutek-lib api usage
    pub async fn start_nutek_core(docker: Docker, nutek_id: &str) {
        let _ = docker.containers().get(nutek_id)
            .start().await.expect("nutek-core didn't started");
    }

    /// stop nutek-core container
    /// 
    /// cleanu-up #1
    pub async fn stop_nutek_core(docker: Docker, nutek_id: &str) {
        let _ = docker.containers().get(nutek_id)
        .stop(Default::default()).await.expect("nutek-core didn't stoped");
    }

    /// remove nutek-core container
    /// 
    /// clean-up #2
    pub async fn remove_nutek_core(docker: Docker, nutek_id: &str) {
        let _ = docker.containers().get(nutek_id)
        .remove(&Default::default())
        .await.expect("nutek-core not removed");
    }
}

pub mod system {
    use std::{path::Path, fs};
    /// create Nutek working directories
    /// for future use and storage in home directory
    /// 
    /// # Examples
    /// 
    /// ```
    /// nutek_lib::system::create_working_dirs()
    /// ```
    pub fn create_working_dirs() {
        let nutek: bool = Path::new(format!("{}/.nutek/", 
            home::home_dir().unwrap().display()).as_str())
            .exists();
        if !nutek {
            fs::create_dir(format!("{}/.nutek/", home::home_dir().unwrap().display()))
                .expect("can't create .nutek directory");
        }
        let network_scan: bool = Path::new(format!("{}/.nutek/network_scan", 
        home::home_dir().unwrap().display()).as_str())
        .exists();
        if !network_scan {
            fs::create_dir(format!("{}/.nutek/network_scan", home::home_dir().unwrap().display()))
                .expect("can't create .nutek/rustscan directory");
        }
        let run_cmd: bool = Path::new(format!("{}/.nutek/run_cmd/", 
        home::home_dir().unwrap().display()).as_str())
        .exists();
        if !run_cmd {
            fs::create_dir(format!("{}/.nutek/run_cmd/", home::home_dir().unwrap().display()))
                .expect("can't create .nutek/run_cmd directory");
        }
        let cve: bool = Path::new(format!("{}/.nutek/cve/", 
        home::home_dir().unwrap().display()).as_str())
        .exists();
        if !cve {
            fs::create_dir(format!("{}/.nutek/cve/", home::home_dir().unwrap().display()))
                .expect("can't create .nutek/cve directory");
        }
        let cve_db: bool = Path::new(format!("{}/.nutek/cve/database", 
        home::home_dir().unwrap().display()).as_str())
        .exists();
        if !cve_db {
            fs::create_dir(format!("{}/.nutek/cve/database", home::home_dir().unwrap().display()))
                .expect("can't create .nutek/cve/database directory");
        }
    }
}

/// # networking capabilities
/// 
/// currently uses nmap & rustscan
/// planned features are gobuster,
/// raccoon, nmap-analyze and others
/// like recon-ng, metasploit...
pub mod network {
    use std::path::Path;
    use std::time::{SystemTime};
    use std::{fs, time};
    use docker_api::{Exec};
    use docker_api::api::{ExecContainerOpts};
    use futures::{StreamExt};
    use std::io::Error;





    /// # Rustscan
    ///
    /// dummy wrapper around RustScan
    /// 
    /// mostly used in aggressive scanning, fast port discovery
    /// 
    /// # Arguments:
    /// 
    /// * `cmd: String` arguments for fastscan
    /// 
    /// # Output:
    /// 
    /// * filename suffix which is the key in
    /// 
    ///     `.nutek/network_scan` folder
    /// * writes raw command output
    /// 
    ///     to `terminal_cmd_`_suffix_`.txt`
    /// 
    /// # Examples
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
        fs::write(format!("{}/.nutek/network_scan/terminal_cmd_{}.txt", 
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
    /// # Arguments:
    /// 
    /// * `cmd: String` - the _command_
    /// 
    /// # Output:
    /// 
    /// * filename **suffix** which is the key in
    /// 
    ///     `.nutek/run_cmd/terminal_cmd_`*suffix*`.txt`
    /// 
    /// # Examples
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
        fs::write(format!("{}/.nutek/run_cmd/terminal_cmd_{}.txt", 
            home::home_dir().unwrap().display(),
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

    use crate::docker::{create_nutek_core, start_nutek_core, stop_nutek_core, remove_nutek_core, connect_to_docker_api};
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
    /// # Arguments:
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
    /// # Output:
    /// 
    /// * writes webisite with report
    ///     in `.nutek/network_scan/scan_`_suffix_`.html`
    /// 
    /// * returns `path` to created website with report
    /// 
    /// # Examples
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
            // let mut stylesheet = lines.get(2).expect("no style line in file");
            // let stylesheet = 
            // {
                // let mut style_line = &mut ; 
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
    /// # Arguments
    /// 
    /// * path - system path to your file
    /// 
    /// # Outputs
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

pub mod cve {
    use std::{io::Error, fs};
    use futures::{StreamExt};
    use docker_api::{ExecContainerOpts, Exec};

    use crate::docker::{connect_to_docker_api, create_nutek_core, start_nutek_core, stop_nutek_core, remove_nutek_core};

    /// # CVE Databse
    /// 
    /// Search for errors and exploits,
    /// 
    /// attack vectors, and info on
    /// 
    /// vulnerebilities
    /// 
    /// # Arguments
    /// 
    /// * cmd start with nvd_cve and try with --help
    /// 
    /// # Returns
    /// 
    /// - Nothing
    /// 
    /// * writes to files in `.nutek/cve` directory
    /// 
    /// # Examples
    /// 
    /// 
    /// sync with remote CVE database
    /// 
    /// you might need to run this command few times
    /// 
    /// as the remote database is not an Uzi
    /// ```
    /// #[tokio::main]
    /// async fn sync_cve_db() {
    ///     let _ = nutek_lib::cve::nvd_cve("nvd_cve sync".to_string())
    ///         .await.expect("no vulnerabilities found");
    /// }
    /// ```
    /// 
    /// for more info look here:
    /// ```
    /// #[tokio::main]
    /// async fn sync_cve_db() {
    ///     let _ = nutek_lib::cve::nvd_cve("nvd_cve search --help".to_string())
    ///         .await.expect("no vulnerabilities found");
    /// }
    /// ```
    pub async fn nvd_cve(cmd: String) -> Result<(), Error> {

        let command = cmd.split_ascii_whitespace();
        let mut cmd: Vec<String> = command.map(|x| x.to_string()).collect();
        
        let docker = &connect_to_docker_api();

        let help_dash_dash = cmd.iter().position(|r| r == "--help");//.unwrap();
        let help_dash = cmd.iter().position(|r| r == "-h");//.unwrap();
        if help_dash == None && help_dash_dash == None {
            cmd.append(&mut vec!["--db".to_string(), 
                "/root/.nutek/cve/database/sync.db".to_string()]);
        }
        let search_cmd = cmd.iter().position(|r| r == "search");
        let text_dash_dash = cmd.iter().position(|r| r == "--text");//.unwrap();
        let text_dash = cmd.iter().position(|r| r == "-t");//.unwrap();
        let mut cve_one_filename = "".to_string();
        let mut cve_list_filename = "".to_string();
        if search_cmd != None && text_dash == None && text_dash_dash == None{
            cve_one_filename = cmd.get(2).expect("no cve supplied").to_string();
        } else if search_cmd != None && (text_dash != None || text_dash_dash != None) {
            let cmd_len = cmd.len();
            cve_list_filename = cmd[3..cmd_len].join("_").to_string();
            cve_list_filename = cve_list_filename.strip_suffix("_--db_/root/.nutek/cve/database/sync.db").unwrap_or_else(|| &cve_list_filename).to_string();
            cve_list_filename = cve_list_filename.strip_prefix("'").unwrap_or_else(|| &cve_list_filename).to_string();
            cve_list_filename = cve_list_filename.strip_suffix("'").unwrap_or_else(|| &cve_list_filename).to_string();
            cve_list_filename = cve_list_filename.strip_prefix('"').unwrap_or_else(|| &cve_list_filename).to_string();
            cve_list_filename = cve_list_filename.strip_suffix('"').unwrap_or_else(|| &cve_list_filename).to_string();
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
        if cve_one_filename != "".to_string() {
            fs::write(format!("{}/.nutek/cve/{}.json", 
                home::home_dir().unwrap().display(),
                cve_one_filename),
            cmd_result.clone())
                .expect("unable to write report file");
        } else if cve_list_filename != "".to_string() {
            fs::write(format!("{}/.nutek/cve/{}.txt", 
                home::home_dir().unwrap().display(),
                cve_list_filename),
            cmd_result.clone())
                .expect("unable to write report file");
        }
        stop_nutek_core(docker.clone(), nutek_id).await;
        remove_nutek_core(docker.clone(), nutek_id).await;
        Ok(())
    }
}

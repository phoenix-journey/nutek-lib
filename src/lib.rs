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
###    ####  ########      ###     ########## ###    ### "#
    }
}

pub mod network {
    use std::time::{SystemTime};
    use std::{fs, time};
    use std::io::{Error};
    use docker_api::{Docker, Exec};
    use docker_api::api::{ExecContainerOpts, ContainerCreateOpts};
    use futures::{StreamExt};

    #[cfg(unix)]
    fn new_docker() -> docker_api::Result<Docker> {
        Ok(Docker::unix("/var/run/docker.sock"))
    }
        
    #[cfg(not(unix))]
    fn new_docker() -> docker_api::Result<Docker> {
        Docker::new("tcp://127.0.0.1:8080")
    }

    fn connect_to_docker_api() -> Docker {
        let docker = new_docker()
            .expect("no Docker!");
        return docker
    }

    use std::path::Path;
    pub fn create_working_dirs() {
        let nutek: bool = Path::new(format!("{}/.nutek/", home::home_dir().unwrap().display()).as_str()).is_dir();
        if !nutek {
            fs::create_dir(format!("{}/.nutek/", home::home_dir().unwrap().display()))
                .expect("can't create .nutek directory");
        }
        let rustscan: bool = Path::new(format!("{}/.nutek/rustscan/", home::home_dir().unwrap().display()).as_str()).is_dir();
        if !rustscan {
            fs::create_dir(format!("{}/.nutek/rustscan/", home::home_dir().unwrap().display()))
                .expect("can't create .nutek/rustscan directory");
        }
        let nmap: bool = Path::new(format!("{}/.nutek/rustscan/nmap/", home::home_dir().unwrap().display()).as_str()).is_dir();
        if !nmap {
            fs::create_dir(format!("{}/.nutek/rustscan/nmap/", home::home_dir().unwrap().display()))
                .expect("can't create .nutek/rustscan/nmap directory");
        }
        let run_cmd: bool = Path::new(format!("{}/.nutek/run_cmd/", home::home_dir().unwrap().display()).as_str()).is_dir();
        if !run_cmd {
            fs::create_dir(format!("{}/.nutek/run_cmd/", home::home_dir().unwrap().display()))
                .expect("can't create .nutek/run_cmd directory");
        }
    }

    async fn create_nutek_core(docker: Docker) -> String {
        create_working_dirs();
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
        return d
    }

    async fn start_nutek_core(docker: Docker, nutek_id: &str) {
        let _ = docker.containers().get(nutek_id)
            .start().await.expect("nutek-core didn't started");
    }

    async fn stop_nutek_core(docker: Docker, nutek_id: &str) {
        let _ = docker.containers().get(nutek_id)
        .stop(Default::default()).await.expect("nutek-core didn't stoped");
    }

    async fn remove_nutek_core(docker: Docker, nutek_id: &str) {
        let _ = docker.containers().get(nutek_id)
        .remove(&Default::default())
        .await.expect("nutek-core not removed");
    }

    /// # Rustscan
    ///
    ///
    pub async fn rustscan(cmd: String) -> Result<String, Error> {

        let command = cmd.split_ascii_whitespace();
        let mut cmd: Vec<String> = command.map(|x| x.to_string()).collect();
        
        let docker = &connect_to_docker_api();
        let suffix: u128;
        match SystemTime::now().duration_since(time::UNIX_EPOCH) {
            Ok(n) => {
                suffix = n.as_micros()
            },
            Err(_) => panic!("SystemTime before UNIX EPOCH!"),
        };
        let help_dash_dash = cmd.iter().position(|r| r == "--help");//.unwrap();
        let help_dash = cmd.iter().position(|r| r == "-h");//.unwrap();
        if help_dash == None && help_dash_dash == None {
            cmd.append(&mut vec!["-oX".to_string(), 
                format!("/root/.nutek/rustscan/nmap/scan_result_{}.xml", suffix)]);
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
            &docker, 
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
        fs::write(format!("{}/.nutek/rustscan/scan_terminal_{}.txt", 
            home::home_dir().unwrap().display(),
            suffix),
        cmd_result.clone())
            .expect("unable to write report file");
        Ok(format!("{}", suffix))
    }

    async fn run_cmd(cmd: String) -> Result<String, Error> {
        let command = cmd.split_ascii_whitespace();
        let cmd: Vec<String> = command.map(|x| x.to_string()).collect();
        let docker = &connect_to_docker_api();
        let suffix: u128;
        match SystemTime::now().duration_since(time::UNIX_EPOCH) {
            Ok(n) => {
                suffix = n.as_micros()
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
            &docker, 
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

    pub async fn nmap_xml_to_html(file: String, suffix: String) -> Result<String, Error> {
        if file == String::from("") && suffix != String::from("") {
            run_cmd(format!("xsltproc /root/.nutek/rustscan/nmap/scan_result_{}.xml 
                -o /root/.nutek/rustscan/nmap/scan_{}.html", suffix, suffix))
                .await.expect("can't creat nmap html report");
        } else if file != String::from("") && suffix == String::from("") {
            let suffix: u128;
            match SystemTime::now().duration_since(time::UNIX_EPOCH) {
                Ok(n) => {
                    suffix = n.as_micros()
                },
                Err(_) => panic!("SystemTime before UNIX EPOCH!"),
            };
            fs::copy(file, 
                format!("{}/.nutek/rustscan/nmap/scan_{}.xml", 
                home::home_dir().unwrap().display(),
                suffix))
                .expect("can't copy file to nmap folder");
            run_cmd(format!("xsltproc /root/.nutek/rustscan/nmap/scan_{}.xml
            -o /root/.nutek/rustscan/nmap/scan_{}.html", suffix, suffix))
                .await.expect("can't creat nmap html report from file");
        }
        let report_path = format!("{}/.nutek/rustscan/nmap/scan_{}.html",
            home::home_dir().unwrap().display(),
            suffix);
        return Ok(report_path)
    }

    pub async fn open_nmap_html_report(path: String) -> Result<(), Error> {
        create_working_dirs();
        open::that(format!("{}",
            path))
            .expect("can't open nmap scan website with report");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }

    use crate::hello::hi_nutek;
    #[tokio::test]
    async fn hello_msg() {
        eprintln!("{}", hi_nutek())
    }

    use crate::network::create_working_dirs;
    use std::fs;
    use std::path::Path;
    #[tokio::test]
    async fn create_dirs() {
        create_working_dirs();
        let nutek: bool = Path::new(format!("{}/.nutek", home::home_dir().unwrap().display()).as_str()).is_dir();
        assert!(nutek);
        let rustscan: bool = Path::new(format!("{}/.nutek/rustscan", home::home_dir().unwrap().display()).as_str()).is_dir();
        assert!(rustscan);
        let nmap: bool = Path::new(format!("{}/.nutek/rustscan/nmap", home::home_dir().unwrap().display()).as_str()).is_dir();
        assert!(nmap);
        let run_cmd: bool = Path::new(format!("{}/.nutek/run_cmd", home::home_dir().unwrap().display()).as_str()).is_dir();
        assert!(run_cmd);
    }

    use std::{process::Command, time::{SystemTime, self}};
    #[tokio::test]
    async fn docker_presence() {
        let _ = Command::new("docker")
            .args(["--version"])
            .spawn()
            .expect("docker command failed to start");
    }

    use crate::network::rustscan;
    #[tokio::test]
    async fn rustscan_help() {
        let res = rustscan("rustscan --help".to_string());
        let suffix = res
        .await
        .expect("no rustscan result");
        let f = fs::read(
            format!("{}/.nutek/rustscan/scan_terminal_{}.txt",
            home::home_dir().unwrap().display(), suffix))
            .expect("can't open terminal logs of rustscan");
        let txt = String::from_utf8_lossy(&f);
        txt.find("rustscan 2.1.0")
        .expect("rustscan version 2.1.0 not found");
    }

    use crate::network::nmap_xml_to_html;
    #[tokio::test]
    async fn scan_me_rustscan() {
        let suffix: u128;
        match SystemTime::now().duration_since(time::UNIX_EPOCH) {
            Ok(n) => {
                suffix = n.as_millis()
            },
            Err(_) => panic!("SystemTime before UNIX EPOCH!"),
        };
        let _ = rustscan(format!("rustscan --addresses scanme.nmap.org 
            --ports 80 -- -A -T4 -O 
            -oX /root/.nutek/rustscan/nmap/scan_result_{}.xml", suffix))
            .await.expect("can't scan scanme.nmap.org");
    }

    #[tokio::test]
    async fn scan_me_with_report() {
        let report_suffix = rustscan(format!("rustscan --addresses scanme.nmap.org 
            --ports 80 -- -A -T4 -O"))
            .await.expect("can't scan scanme.nmap.org");
        let _ = nmap_xml_to_html("".to_string(), report_suffix)
            .await.expect("can't create nmap website report");
    }

    use crate::network::open_nmap_html_report;
    #[tokio::test]
    async fn scan_me_open_report() {
        let report_suffix = rustscan(format!("rustscan --addresses scanme.nmap.org 
            --ports 80 -- -A -T4 -O"))
            .await.expect("can't scan scanme.nmap.org");
        let path = 
            nmap_xml_to_html("".to_string(), report_suffix)
            .await.expect("can't create nmap website report");
        let _ = open_nmap_html_report(path)
            .await
            .expect("can't open website with nmap report");
    }
}   

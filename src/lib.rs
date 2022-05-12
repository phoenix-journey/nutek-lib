pub mod website;
pub mod network;
pub mod docker;
pub mod cve;
pub mod search;

pub mod hello {
    /// # This is my cat's drawing of the key
    /// ___
    ///
    /// ## Examples
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



pub mod system {
    use std::{path::Path, fs, io::Error, time::{SystemTime, self}};

    use shiplift::{ExecContainerOptions, Exec};

    use futures::{StreamExt};

    use crate::docker::runners::{connect_to_shiplift, create_nutek_core, start_nutek_core, stop_nutek_core, remove_nutek_core};
    /// create Nutek working directories
    /// for future use and storage in home directory
    /// 
    /// ## Examples
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
        let bing: bool = Path::new(format!("{}/.nutek/search", 
        home::home_dir().unwrap().display()).as_str())
        .exists();
        if !bing {
            fs::create_dir(format!("{}/.nutek/search", home::home_dir().unwrap().display()))
                .expect("can't create .nutek/search directory");
        }
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
    ///     let suffix = nutek_lib::system::run_cmd(
    ///         "echo 'Hi Nutek!'".to_string()
    ///     ).await.expect("Nutek no run :(");
    /// }
    /// ```
    pub async fn run_cmd(cmd: String) -> Result<String, Error> {
        let command = cmd.split_ascii_whitespace();
        let cmd: Vec<&str> = command.map(|x| x).collect();
        let cmdlet = cmd.get(0).unwrap().to_owned();
        let docker = &connect_to_shiplift();
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
        let options = ExecContainerOptions::builder()
            .cmd(cmd)
            .attach_stdout(true)
            .attach_stderr(true)
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
}

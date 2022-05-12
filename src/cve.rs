pub mod cves {
    use std::{io::Error, fs};
    use futures::{StreamExt};
    use docker_api::{ExecContainerOpts, Exec};

    use crate::docker::runners::{connect_to_docker_api, create_nutek_core, start_nutek_core, stop_nutek_core, remove_nutek_core};

    /// nvd_cve 0.1.0
    /// Travis Paul <Tr@visPaul.me>
    ///
    /// USAGE:
    ///     nvd_cve [SUBCOMMAND]
    ///
    /// FLAGS:
    ///     -h, --help       Prints help information
    ///     -V, --version    Prints version information
    ///
    /// SUBCOMMANDS:
    ///     help      Prints this message or the help of the given subcommand(s)
    ///     search    Search for a CVE by ID in the local cache
    ///     sync      Sync CVE feeds to local database
    pub async fn nvd_cve_help() -> Result<(), Error> {
        let docker = &connect_to_docker_api();

        let nutek_core_id = 
            create_nutek_core(docker.clone())
            .await;
        let nutek_id = nutek_core_id.as_str();
        start_nutek_core(docker.clone(), nutek_id).await;
        
        let options = ExecContainerOpts::builder()
            .cmd(vec!["raccoon", "--help"])
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

    /// # CVE Databse
    /// 
    /// Search for errors and exploits,
    /// 
    /// attack vectors, and info on
    /// 
    /// vulnerebilities
    /// 
    /// ## Arguments
    /// 
    /// * cmd start with nvd_cve and try with --help
    /// 
    /// ## Returns
    /// 
    /// - Nothing
    /// 
    /// * writes to files in `.nutek/cve` directory
    /// 
    /// ## Examples
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
    ///     let _ = nutek_lib::cve::cves::nvd_cve("nvd_cve sync".to_string())
    ///         .await.expect("no vulnerabilities found");
    /// }
    /// ```
    /// 
    /// for more info look here:
    /// ```
    /// #[tokio::main]
    /// async fn sync_cve_db() {
    ///     let _ = nutek_lib::cve::cves::nvd_cve("nvd_cve search --help".to_string())
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

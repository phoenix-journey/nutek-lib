pub mod cves {
    use std::{io::Error, fs};
    use futures::{StreamExt};
    use shiplift::{ExecContainerOptions, Exec};

    use crate::docker::runners::{connect_to_shiplift, create_nutek_core, start_nutek_core, stop_nutek_core, remove_nutek_core};

    /// # nvd_cve 0.1.0
    /// 
    /// Travis Paul <Tr@visPaul.me>
    ///
    /// ## USAGE:
    /// 
    /// `nvd_cve [SUBCOMMAND]`
    ///
    /// ## FLAGS:
    /// 
    /// `-h, --help`       Prints help information
    /// `-V, --version`    Prints version information
    ///
    /// ## SUBCOMMANDS:
    /// 
    ///  `help`      Prints this message or the help of the given subcommand(s)
    ///
    /// `search`    Search for a CVE by ID in the local cache
    ///
    /// `sync`      Sync CVE feeds to local database
    /// 
    /// # nvd_cve-sync 0.1.0
    ///
    ///  Sync CVE feeds to local database
    ///
    /// ## USAGE:
    /// 
    /// `nvd_cve sync [FLAGS] [OPTIONS]`
    ///
    /// ## FLAGS:
    /// `-f, --force`           Ignore existing Metafiles and force update all feeds
    /// 
    /// `-h, --help`            Prints help information
    /// 
    /// `-n, --no-progress`     Don't show progress bar when syncing feeds
    /// 
    /// `-s, --show-default`    Show default config values and exit
    /// 
    /// `-V, --version`         Prints version information
    ///
    /// `-v, --verbose`         Print verbose logs (Set level with RUST_LOG)
    ///
    /// ## OPTIONS:
    /// 
    /// `-d, --db <FILE>`       Path to SQLite database where CVE feed data will be stored
    /// 
    /// `-l, --feeds <LIST>`   Comma separated list of CVE feeds to fetch and sync, defaults to: all known feeds
    /// 
    /// `-u, --url <URL>`       URL to use for fetching feeds, defaults to: https://nvd.nist.gov/feeds/json/cve/1.1
    /// 
    /// other one https://www.harmless.systems/mirror/nvd/feeds/json/cve/1.1/ 
    /// 
    /// # nvd_cve-search 0.1.0
    /// 
    /// Search for a CVE by ID in the local cache
    ///
    /// ## USAGE:
    /// 
    /// `nvd_cve search [FLAGS] [OPTIONS] [CVE]`
    ///
    /// ## FLAGS:
    /// 
    /// `-h, --help`      Prints help information
    /// 
    /// `-V, --version`    Prints version information
    /// 
    /// `-v, --verbose`    Print verbose logs (Set level with RUST_LOG)
    ///
    /// ##OPTIONS:
    /// 
    /// `-d, --db <FILE>`        Path to SQLite database where CVE feed data will be stored
    /// 
    /// `-t, --text <STRING>`    Search the CVE descriptions instead.
    ///
    /// ## ARGS:
    /// 
    /// `<CVE>`    CVE ID to retrieve
    pub async fn nvd_cve_help() -> Result<(), Error> {
        let docker = &connect_to_shiplift();

        let nutek_core_id = 
            create_nutek_core(docker.clone())
            .await;
        let nutek_id = nutek_core_id.as_str();
        start_nutek_core(docker.clone(), nutek_id).await;
        
        let options = ExecContainerOptions::builder()
            .cmd(vec!["nvd_cve", "--help"])
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
        let mut cmd: Vec<&str> = command.map(|x| x).collect();
        
        let docker = &connect_to_shiplift();

        let help_dash_dash = cmd.iter().position(|r| *r == "--help");//.unwrap();
        let help_dash = cmd.iter().position(|r| *r == "-h");//.unwrap();
        
        if help_dash == None && help_dash_dash == None {
            cmd.append(&mut vec!["--db", 
                "/root/.nutek/cve/database/sync.db"]);
        }
        let search_cmd = cmd.iter().position(|r| *r == "search");
        let text_dash_dash = cmd.iter().position(|r| *r == "--text");//.unwrap();
        let text_dash = cmd.iter().position(|r| *r == "-t");//.unwrap();
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

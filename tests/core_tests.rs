
    #[cfg(test)]
    use nutek_lib::hello::hi_nutek;
    #[test]
    pub fn hello_msg() {
        println!("{}", hi_nutek())
    }

    use nutek_lib::system::create_working_dirs;
    use std::path::Path;
    #[test]
    pub fn create_dirs() {
        create_working_dirs();
        let nutek: bool = Path::new(format!("{}/.nutek", home::home_dir().unwrap().display()).as_str()).is_dir();
        assert!(nutek);
        let network_scan: bool = Path::new(format!("{}/.nutek/network_scan", home::home_dir().unwrap().display()).as_str()).is_dir();
        assert!(network_scan);
        let run_cmd: bool = Path::new(format!("{}/.nutek/run_cmd", home::home_dir().unwrap().display()).as_str()).is_dir();
        assert!(run_cmd);
        let cve: bool = Path::new(format!("{}/.nutek/cve", home::home_dir().unwrap().display()).as_str()).is_dir();
        assert!(cve);
        let cve_db: bool = Path::new(format!("{}/.nutek/cve/database", home::home_dir().unwrap().display()).as_str()).is_dir();
        assert!(cve_db);
        let bing: bool = Path::new(format!("{}/.nutek/search", home::home_dir().unwrap().display()).as_str()).is_dir();
        assert!(bing);
    }

    use std::process::Command;
    #[tokio::test]
    async fn docker_presence() {
        hello_msg();
        let _ = Command::new("docker")
            .args(["--version"])
            .spawn()
            .expect("docker command failed to start");
    }    

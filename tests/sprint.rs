#[cfg(test)]
mod core_tests {
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

    

    
}   

#[cfg(test)]
mod network_tests {

    use std::fs;
    use nutek_lib::network::scanners::rustscan;
    use crate::core_tests::hello_msg;
    use crate::core_tests::create_dirs;

    #[tokio::test]
    async fn rustscan_help() {
        hello_msg();
        create_dirs();
        let res = rustscan("rustscan --help".to_string());
        let suffix = res
        .await
        .expect("no rustscan result");
        let f = fs::read(
            format!("{}/.nutek/network_scan/rustscan_cmd_{}.txt",
            home::home_dir().unwrap().display(), suffix))
            .expect("can't open rustscan logs of rustscan");
        let txt = String::from_utf8_lossy(&f);
        txt.find("rustscan 2.1.0")
        .expect("rustscan version 2.1.0 not found");
    }

    use nutek_lib::network::scanners::nmap_xml_to_html;
    use std::time;
    use std::time::SystemTime;
    #[tokio::test]
    async fn scan_me_rustscan() {
        hello_msg();
        create_dirs();
        let suffix: u128;
        match SystemTime::now().duration_since(time::UNIX_EPOCH) {
            Ok(n) => {
                suffix = n.as_millis()
            },
            Err(_) => panic!("SystemTime before UNIX EPOCH!"),
        };
        let _ = rustscan(format!("rustscan --addresses scanme.nmap.org 
            --ports 80 -- -A -T4 -O 
            -oX /root/.nutek/network_scan/scan_result_{}.xml", suffix))
            .await.expect("can't scan scanme.nmap.org");
    }

    #[tokio::test]
    async fn scan_me_with_report() {
        hello_msg();
        create_dirs();
        let report_suffix = rustscan(format!("rustscan --addresses scanme.nmap.org 
            --ports 80 -- -A -T4 -O"))
            .await.expect("can't scan scanme.nmap.org");
        let _ = nmap_xml_to_html("".to_string(), report_suffix)
            .await.expect("can't create nmap website report");
    }

    #[tokio::test]
    async fn report_from_local_file() {
        hello_msg();
        create_dirs();
        let home = nmap_xml_to_html(format!("tests/data/beginning-nmap.xml"), "".to_string())
            .await.expect("can't create nmap website report");
        println!("{}", home);
    }

    use nutek_lib::network::scanners::open_nmap_html_report;
    #[tokio::test]
    #[ignore]
    async fn scan_me_open_report() {
        hello_msg();
        create_dirs();
        // can't open on headless client so... 
        // display path to the website with report
        // AND #[ignore]
        let path = "tests/data/beginning-nmap.xml";
        let home = nmap_xml_to_html(path.to_string(), "".to_string())
            .await.expect("can't create nmap website report");
        let _ = open_nmap_html_report(home.clone())
            .await
            .expect("can't open website with nmap report");
        println!("Website with scan report:");
        println!("{}", home.clone());
    }
}

#[cfg(test)]
mod cve_tests {
    use crate::core_tests::hello_msg;
    use crate::core_tests::create_dirs;
    
    use nutek_lib::cve::nvd_cve;
    #[tokio::test]
    async fn sync_cve() {
        hello_msg();
        create_dirs();
        let _ = nvd_cve("nvd_cve sync".to_string())
            .await.expect("no vulnerabilities found");
    }

    #[tokio::test]
    async fn search_cve_id() {
        hello_msg();
        create_dirs();
        let _ = nvd_cve("nvd_cve search CVE-2011-4929".to_string())
            .await.expect("no exploits");
    }

    #[tokio::test]
    async fn search_cve_text() {
        hello_msg();
        create_dirs();
        let _ = nvd_cve("nvd_cve search --text 'remote ruby'".to_string())
            .await.expect("no exploits");
    }
}

#[cfg(test)]
mod search_tests {
    use std::path::Path;

    use crate::core_tests::hello_msg;
    use crate::core_tests::create_dirs;
    
    use nutek_lib::search::bing_search;
    #[tokio::test]
    async fn search_on_bing() {
        hello_msg();
        create_dirs();
        let suffix = bing_search("exploit".to_string(), 
            30,
            "".to_string())
            .await.expect("no Bing in scope");
        let bing_file: bool = Path::new(format!("{}/.nutek/search/bing_{}.txt", 
            home::home_dir().unwrap().display(),
            suffix).as_str())
            .exists();
        assert!(bing_file);
    }
}
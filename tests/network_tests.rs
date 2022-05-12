mod core_tests;

#[cfg(test)]
mod network_tests {
    use nutek_lib::network::scanners::rustscan;
    use nutek_lib::network::scanners::rustscan_help;
    use crate::core_tests::create_dirs;
    use crate::core_tests::hello_msg;

    #[tokio::test]
    async fn print_rustscan_help() {
        hello_msg();
        create_dirs();
        match rustscan_help().await {
            Ok(_) => {}
            _ => {
                assert!(false)
            }
        }
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
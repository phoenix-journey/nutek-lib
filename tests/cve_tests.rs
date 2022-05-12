mod core_tests;

#[cfg(test)]
mod cve_tests {
    use crate::core_tests::hello_msg;
    use crate::core_tests::create_dirs;
    
    use nutek_lib::cve::cves::nvd_cve;
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
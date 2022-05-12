mod core_tests;

#[cfg(test)]
mod search_tests {
    use std::path::Path;

    use crate::core_tests::hello_msg;
    use crate::core_tests::create_dirs;

    use nutek_lib::search::bing::bing_search;
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
pub mod website;
pub mod network;
pub mod docker;

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
    use std::{path::Path, fs};
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
}



pub mod cve {
    use std::{io::Error, fs};
    use futures::{StreamExt};
    use docker_api::{ExecContainerOpts, Exec};

    use crate::docker::runners::{connect_to_docker_api, create_nutek_core, start_nutek_core, stop_nutek_core, remove_nutek_core};

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

pub mod search {
    use std::{vec, fs::{File}, time::{SystemTime, self}, io::{Write, Error}};

    use reqwest;
    use soup::prelude::*;

    /// # Bing Search
    ///
    /// ## Arguments
    /// 
    /// - arg1 - query
    /// - arg2 - max results
    /// - arg3 - cvid
    /// 
    /// https://support.microsoft.com/en-gb/topic/advanced-search-keywords-ea595928-5d63-4a0b-9c6b-0b769865e78a
    /// https://support.microsoft.com/en-gb/topic/advanced-search-options-b92e25f1-0085-4271-bdf9-14aaea720930
    /// 
    /// ## Examples
    /// 
    /// ```
    /// async fn search() {
    ///     let _ = nutek_lib::search::bing_search("lulzsec".to_string(), 30, 
    ///         "".to_string()).await.expect("no boss");
    /// }
    /// ```
    pub async fn bing_search(query: String, max_results: i32, cvid_in: String) -> Result<String, Error> {
        let cvid: String;
        if cvid_in == "".to_string() {
            cvid = String::from("4D2EA03FB1D5439C994D1F5C7D902272");
        } else {
            cvid = cvid_in.clone();
        }

        let mut full_search: Vec<String> = vec![];
        let mut query_num = 1;
        loop {
            let test = query_num - 1;
            if test > max_results {
                break
            }
            let user_agent = "{'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}";
            let client = reqwest::Client::builder()
                .user_agent(user_agent)
                .build();
            let query = format!("https://www.bing.com/search?q={}&qs=n&form=QBRE&sp=-1&sc=8-9&sk=&cvid={}&setlang=en&first={}", query, cvid, query_num);
            let c = client.expect("Internal error, cal 911!");
            let resp = c.get(query).send().await.unwrap().text().await;
            let soup = Soup::new(resp.unwrap().as_str());
            let ol_opt = soup.tag("ol").find();
            let ol = ol_opt.expect("No results returned!");
            let li = ol.tag("li").find_all();
            let mut tmp_s_v: Vec<String> = vec![];
            li.for_each(|l| {
                let children = l.children();
                for (_, child) in children.enumerate() {
                    let h2 = child.tag("h2").find_all();
                    for (_, h) in h2.enumerate() {
                        let ha = h.tag("a").find();
                        match ha {
                            Some(ha) => {
                                let href = ha.get("href");
                                match href {
                                    Some(href) => {
                                        if href.get(0..4) != Some(&"http".to_string()) {
                                            continue;
                                        }
                                        if href.get(0..28) == Some(&"https://www.bing.com/aclick?".to_string()) {
                                            continue;
                                        }

                                        let mut tmp_s_h = format!("{} - {}\n", href, h.text());
                                        let div_out = child.tag("div").find_all();
                                        let mut tmp_s_p: String = String::from("");
                                        let mut last_p: String = String::from("");
                                        for (_, div) in div_out.enumerate() {
                                            let p = div.tag("p").find();
                                            match p {
                                                Some(p) => {
                                                    let p_t = p.text();
                                                    if last_p == p_t {
                                                        continue
                                                    }
                                                    last_p = p.text();
                                                    tmp_s_p = format!("{}\n{}\n", tmp_s_p, p_t)
                                                }
                                                _ => {}
                                            }
                                        }
                                        tmp_s_h = format!("{}{}\n", tmp_s_h, tmp_s_p);
                                        let mut tmp: Vec<String> = vec![tmp_s_h];
                                        tmp_s_v.append(&mut tmp);
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        }
                    }
                }
            });
            tmp_s_v.dedup();
            full_search.append(&mut tmp_s_v);
            for s in tmp_s_v.iter() {
                println!("{}", s);
            }
            query_num += 10;
        }
        let suffix: u128 = match SystemTime::now().duration_since(time::UNIX_EPOCH) {
            Ok(n) => {
                n.as_micros()
            },
            Err(_) => panic!("SystemTime before UNIX EPOCH!"),
        };
        let mut f = File::create(format!("{}/.nutek/search/bing_{}.txt",
            home::home_dir().unwrap().display(), suffix))
            .expect("unable to create Bing file");                                                                                                          
        for i in &full_search{                                                                                                                                                                  
            f.write_all(i.as_bytes()).expect("unable to write Bing data");                                                                                                                            
        }
        return Ok(format!("{}", suffix));
    }
}

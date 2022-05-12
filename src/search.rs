pub mod bing {
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
    /// [search keywords](https://support.microsoft.com/en-gb/topic/advanced-search-keywords-ea595928-5d63-4a0b-9c6b-0b769865e78a)
    /// 
    /// [advanced search options](https://support.microsoft.com/en-gb/topic/advanced-search-options-b92e25f1-0085-4271-bdf9-14aaea720930)
    /// 
    /// ## Examples
    /// 
    /// ```
    /// async fn search() {
    ///     let _ = nutek_lib::search::bing::bing_search("lulzsec".to_string(), 30, 
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
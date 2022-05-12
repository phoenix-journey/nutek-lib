pub mod crawlers {
    use std::io::Error;

    use docker_api::{ExecContainerOpts, Exec};

    use crate::docker::runners::{connect_to_docker_api, create_nutek_core, start_nutek_core};

    use futures::{StreamExt};

    /// # Raccoon
    /// 
    /// Usage: raccoon [OPTIONS] TARGET
    ///
    /// ## Options:
    /// 
    /// `--version`                      Show the version and exit.
    /// 
    /// `-d, --dns-records TEXT`         Comma separated DNS records to query.
    ///                                Defaults to: A,MX,NS,CNAME,SOA,TXT
    /// 
    /// `--tor-routing`                  Route HTTP traffic through Tor (uses port
    ///                                9050). Slows total runtime significantly
    /// 
    /// `--proxy-list TEXT`              Path to proxy list file that would be used
    ///                                for routing HTTP traffic. A proxy from the
    ///                                list will be chosen at random for each
    ///                                request. Slows total runtime
    /// 
    /// `-c, --cookies TEXT`             Comma separated cookies to add to the
    ///                                requests. Should be in the form of key:value
    ///                                Example: PHPSESSID:12345,isMobile:false
    /// `--proxy TEXT`                   Proxy address to route HTTP traffic through.
    ///                                Slows total runtime
    /// 
    /// `-w, --wordlist TEXT`            Path to wordlist that would be used for URL
    ///                                fuzzing
    /// 
    /// `-T, --threads INTEGER`          Number of threads to use for URL
    ///                                Fuzzing/Subdomain enumeration. Default: 25
    /// 
    /// `--ignored-response-codes TEXT`  Comma separated list of HTTP status code to
    ///                                ignore for fuzzing. Defaults to:
    ///                                302,400,401,402,403,404,503,504
    /// 
    /// `--subdomain-list TEXT`          Path to subdomain list file that would be
    ///                                used for enumeration
    /// 
    /// `-sc, --scripts`                 Run Nmap scan with -sC flag
    /// 
    /// `-sv, --services`                Run Nmap scan with -sV flag
    /// 
    /// `-f, --full-scan`                Run Nmap scan with both -sV and -sC
    /// 
    /// `-p, --port TEXT`                Use this port range for Nmap scan instead of
    ///                                the default
    /// 
    /// `--vulners-nmap-scan`            Perform an NmapVulners scan. Runs instead of
    ///                                the regular Nmap scan and is longer.
    /// 
    /// `--vulners-path TEXT`            Path to the custom nmap_vulners.nse script.If
    ///                               not used, Raccoon uses the built-in script it
    ///                                ships with.
    /// 
    /// `-fr, --follow-redirects`        Follow redirects when fuzzing. Default: False
    ///                                (will not follow redirects)
    /// 
    /// `--tls-port INTEGER`             Use this port for TLS queries. Default: 443
    /// 
    /// `--skip-health-check`            Do not test for target host availability
    /// 
    /// `--no-url-fuzzing`               Do not fuzz URLs
    /// 
    /// `--no-sub-enum`                  Do not bruteforce subdomains
    /// 
    /// `--skip-nmap-scan`               Do not perform an Nmap scan
    /// 
    /// `-q, --quiet`                    Do not output to stdout
    /// 
    /// `-o, --outdir TEXT`              Directory destination for scan output
    /// 
    /// `--help`                         Show this message and exit.
    pub async fn raccoon_help() -> Result<(), Error> {
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

    /// # feroxbuster 2.7.0
    /// 
    /// Ben 'epi' Risher (@epi052)
    /// 
    /// A fast, simple, recursive content discovery tool.
    ///
    /// ## USAGE:
    /// 
    /// `feroxbuster [OPTIONS]`
    ///
    /// ## OPTIONS:
    /// 
    /// `-h, --help`
    ///             Print help information
    ///
    /// `-V, --version`
    ///             Print version information
    ///
    /// ## Target selection:
    /// 
    /// `--resume-from <STATE_FILE>`
    ///             State file from which to resume a partially complete scan (ex. `--resume-from
    ///             ferox-1606586780.state`)
    ///
    /// `--stdin`
    ///             Read url(s) from STDIN
    ///
    /// `-u, --url <URL>`
    ///            The target URL (required, unless [`--stdin` || `--resume-from`] used)
    ///
    /// ## Composite settings:
    /// 
    /// `--burp`
    ///             Set `--proxy` to `http://127.0.0.1:8080` and set `--insecure` to `true`
    ///
    /// `--burp-replay`
    ///             Set `--replay-proxy` to `http://127.0.0.1:8080` and set `--insecure` to `true`
    ///
    /// `--smart`
    ///             Set `--extract-links`, `--auto-tune`, `--collect-words`, and `--collect-backups` to `true`
    ///
    /// `--thorough`
    ///             Use the same settings as `--smart` and set `--collect-extensions` to `true`
    ///
    /// ## Proxy settings:
    /// 
    /// `-p, --proxy <PROXY>`
    ///             Proxy to use for requests (ex: `http(s)://host:port`, `socks5(h)://host:port`)
    ///
    /// `-P, --replay-proxy <REPLAY_PROXY>`
    ///             Send only unfiltered requests through a Replay Proxy, instead of all requests
    ///
    /// `-R, --replay-codes <REPLAY_CODE>...`
    ///             Status Codes to send through a Replay Proxy when found (default: `--status-codes value`)
    ///
    /// ## Request settings:
    /// 
    /// `-a, --user-agent <USER_AGENT>`
    ///             Sets the User-Agent (default: `feroxbuster/2.7.0`)
    ///
    /// `-A, --random-agent`
    ///             Use a random User-Agent
    ///
    /// `-b, --cookies <COOKIE>...`
    ///             Specify HTTP cookies to be used in each request (ex: `-b stuff=things`)
    ///
    /// `--data <DATA>`
    ///             Request's Body; can read data from a file if input starts with an @ (ex: `@post.bin`)
    ///
    /// `-f, --add-slash`
    ///             Append / to each request's URL
    ///
    /// `-H, --headers <HEADER>...`
    ///             Specify HTTP headers to be used in each request (ex: `-H Header:val -H 'stuff: things'`)
    ///
    /// `-m, --methods <HTTP_METHODS>...`
    ///             Which HTTP request method(s) should be sent (default: GET)
    ///
    /// `-Q, --query <QUERY>...`
    ///             Request's URL query parameters (ex: `-Q token=stuff -Q secret=key`)
    ///
    /// `-x, --extensions <FILE_EXTENSION>...`
    ///             File extension(s) to search for (ex: `-x php -x pdf js`)
    ///
    /// ## Request filters:
    ///
    /// `--dont-scan <URL>...`
    ///             URL(s) or Regex Pattern(s) to exclude from recursion/scans
    ///
    /// ## Response filters:
    /// 
    /// `-C, --filter-status <STATUS_CODE>...`
    ///             Filter out status codes (deny list) (ex: `-C 200 -C 401`)
    ///
    /// `--filter-similar-to <UNWANTED_PAGE>...`
    ///             Filter out pages that are similar to the given page (ex. `--filter-similar-to
    ///             http://site.xyz/soft404`)
    ///
    /// `-N, --filter-lines <LINES>...`
    ///             Filter out messages of a particular line count (ex: `-N 20 -N 31,30`)
    ///
    /// `-s, --status-codes <STATUS_CODE>...`
    ///             Status Codes to include (allow list) (default: 200 204 301 302 307 308 401 403 405)
    ///
    /// `-S, --filter-size <SIZE>...`
    ///             Filter out messages of a particular size (ex: `-S 5120 -S 4927,1970`)
    ///
    /// `-W, --filter-words <WORDS>...`
    ///             Filter out messages of a particular word count (ex: `-W 312 -W 91,82`)
    ///
    /// `-X, --filter-regex <REGEX>...`
    ///             Filter out messages via regular expression matching on the response's body (ex: `-X
    ///             '^ignore me$'`)
    ///
    /// ## Client settings:
    /// 
    /// `-k, --insecure`
    ///             Disables TLS certificate validation in the client
    ///
    /// `-r, --redirects`
    ///             Allow client to follow redirects
    ///
    /// `-T, --timeout <SECONDS>`
    ///             Number of seconds before a client's request times out (default: 7)
    ///
    /// ## Scan settings:
    /// 
    /// `--auto-bail`
    ///             Automatically stop scanning when an excessive amount of errors are encountered
    ///
    /// `--auto-tune`
    ///             Automatically lower scan rate when an excessive amount of errors are encountered
    ///
    /// `-d, --depth <RECURSION_DEPTH>`
    ///             Maximum recursion depth, a depth of 0 is infinite recursion (default: 4)
    ///
    /// `-D, --dont-filter`
    ///             Don't auto-filter wildcard responses
    ///
    /// `-e, --extract-links`
    ///             Extract links from response body (html, javascript, etc...); make new requests based on
    ///             findings
    ///
    /// `--force-recursion`
    ///             Force recursion attempts on all 'found' endpoints (still respects recursion depth)
    ///
    /// `-L, --scan-limit <SCAN_LIMIT>`
    ///             Limit total number of concurrent scans (default: 0, i.e. no limit)
    ///
    /// `-n, --no-recursion`
    ///             Do not scan recursively
    ///
    /// `--parallel <PARALLEL_SCANS>`
    ///             Run parallel feroxbuster instances (one child process per url passed via stdin)
    ///
    /// `--rate-limit <RATE_LIMIT>`
    ///             Limit number of requests per second (per directory) (default: 0, i.e. no limit)
    ///
    /// `-t, --threads <THREADS>`
    ///             Number of concurrent threads (default: 50)
    ///
    /// `--time-limit <TIME_SPEC>`
    ///             Limit total run time of all scans (ex: `--time-limit 10m`)
    ///
    /// `-w, --wordlist <FILE>`
    ///             Path to the wordlist
    ///
    /// ## Dynamic collection settings:
    /// 
    /// `-B, --collect-backups`
    ///             Automatically request likely backup extensions for "found" urls
    ///
    /// `-E, --collect-extensions`
    ///             Automatically discover extensions and add them to `--extensions` (unless they're in
    ///             `--dont-collect`)
    ///
    /// `-g, --collect-words`
    ///             Automatically discover important words from within responses and add them to the wordlist
    ///
    /// `-I, --dont-collect <FILE_EXTENSION>...`
    ///             File extension(s) to Ignore while collecting extensions (only used with
    ///             `--collect-extensions`)
    ///
    /// ## Output settings:
    /// 
    /// `--debug-log <FILE>`
    ///             Output file to write log entries (use w/ `--json` for JSON entries)
    ///
    /// `--json`
    ///             Emit JSON logs to `--output` and `--debug-log` instead of normal text
    ///
    /// `--no-state`
    ///             Disable state output file (*.state)
    ///
    /// `-o, --output <FILE>`
    ///             Output file to write results to (use w/ `--json` for JSON entries)
    ///
    /// `-q, --quiet`
    ///             Hide progress bars and banner (good for tmux windows w/ notifications)
    ///
    /// `--silent`
    ///             Only print URLs + turn off logging (good for piping a list of urls to other commands)
    ///
    /// `-v, --verbosity`
    ///             Increase verbosity level (use -vv or more for greater effect. [CAUTION] 4 -v's is probably
    ///             too much)
    ///
    /// ## NOTE:
    /// 
    /// Options that take multiple values are very flexible.  Consider the following ways of specifying
    /// extensions:
    ///         `./feroxbuster -u http://127.1 -x pdf -x js,html -x php txt json,docx`
    ///
    /// The command above adds `.pdf`, `.js`, `.html`, `.php`, `.txt`, `.json`, and `.docx` to each url
    ///
    /// All of the methods above (multiple flags, space separated, comma separated, etc...) are valid
    /// 
    /// and interchangeable.  The same goes for urls, headers, status codes, queries, and size filters.
    ///
    /// ## EXAMPLES:
    /// 
    /// Multiple headers:
    ///         `./feroxbuster -u http://127.1 -H Accept:application/json "Authorization: Bearer {token}"`
    ///
    /// IPv6, non-recursive scan with INFO-level logging enabled:
    ///         `./feroxbuster -u http://[::1] --no-recursion -vv`
    ///
    /// Read urls from STDIN; pipe only resulting urls out to another tool
    ///         `cat targets | ./feroxbuster --stdin --silent -s 200 301 302 --redirects -x js | fff -s 200 -o
    /// js-files`
    ///
    /// Proxy traffic through Burp
    ///         `./feroxbuster -u http://127.1 --burp`
    ///
    /// Proxy traffic through a SOCKS proxy
    ///         `./feroxbuster -u http://127.1 --proxy socks5://127.0.0.1:9050`
    ///
    /// Pass auth token via query parameter
    ///         `./feroxbuster -u http://127.1 --query token=0123456789ABCDEF`
    ///
    /// Find links in javascript/html and make additional requests based on results
    ///         `./feroxbuster -u http://127.1 --extract-links`
    ///
    /// Ludicrous speed... go!
    ///         `./feroxbuster -u http://127.1 -threads 200`
    ///
    /// Limit to a total of 60 active requests at any given time (threads * scan limit)
    ///         `./feroxbuster -u http://127.1 --threads 30 --scan-limit 2`
    ///
    /// Send all 200/302 responses to a proxy (only proxy requests/responses you care about)
    ///         `./feroxbuster -u http://127.1 --replay-proxy http://localhost:8080 --replay-codes 200 302`
    /// 
    /// `--insecure`
    /// Abort or reduce scan speed to individual directory scans when too many errors have occurred
    ///         `./feroxbuster -u http://127.1 --auto-bail`
    ///         `./feroxbuster -u http://127.1 --auto-tune`
    ///
    /// Examples and demonstrations of all features
    ///         https://epi052.github.io/feroxbuster-docs/docs/examples/
    pub async fn feroxbuster_help() -> Result<(), Error> {
        let docker = &connect_to_docker_api();

        let nutek_core_id = 
            create_nutek_core(docker.clone())
            .await;
        let nutek_id = nutek_core_id.as_str();
        start_nutek_core(docker.clone(), nutek_id).await;
        
        let options = ExecContainerOpts::builder()
            .cmd(vec!["feroxbuster", "--help"])
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
}
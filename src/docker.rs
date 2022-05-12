/// # Docker
/// 
/// docker specific set of functions
/// 
/// create, start, stop, remove
pub mod runners {
    use shiplift::{Docker, ContainerOptions};

    #[cfg(unix)]
    fn new_docker() -> shiplift::Result<Docker> {
        Ok(Docker::unix("/var/run/docker.sock"))
    }
        
    #[cfg(not(unix))]
    fn new_docker() -> shiplift::Result<Docker> {
        Docker::new("http:\\localhost:2375")
    }

    /// connect to docker api 
    pub fn connect_to_shiplift() -> Docker {
        new_docker()
            .expect("no Docker!")
    }

    /// create nutek-core container
    /// 
    /// basically everything starts here
    pub async fn create_nutek_core(docker: Docker) -> String {
        let container_name_base = "nutek-core";
        let name = format!("{}-{}", container_name_base, uuid::Uuid::new_v4());
        let core_img = "neosb/nutek-core:latest";
        let opts = 
            ContainerOptions::builder(core_img)
            .name(&name)
            .attach_stdout(true)
            .attach_stderr(true)
            .attach_stdin(true)
            .volumes(vec![format!("{}/.nutek:/root/.nutek", home::home_dir().unwrap().display()).as_str()])
            .build();
        let d = docker.containers()
            .create(&opts)
            .await
            .expect("nutek-core not created").id;
        d
    }

    /// start nutek-core container
    /// 
    /// for nutek-lib api usage
    pub async fn start_nutek_core(docker: Docker, nutek_id: &str) {
        let _ = docker.containers().get(nutek_id)
            .start().await.expect("nutek-core didn't started");
    }

    /// stop nutek-core container
    /// 
    /// cleanu-up #1
    pub async fn stop_nutek_core(docker: Docker, nutek_id: &str) {
        let _ = docker.containers().get(nutek_id)
        .stop(Default::default()).await.expect("nutek-core didn't stoped");
    }

    /// remove nutek-core container
    /// 
    /// clean-up #2
    pub async fn remove_nutek_core(docker: Docker, nutek_id: &str) {
        let _ = docker.containers().get(nutek_id)
        .remove(shiplift::RmContainerOptions::default())
        .await.expect("nutek-core not removed");
    }
}
use risc0_build::{embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder};
use std::collections::HashMap;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let mut builder = GuestOptionsBuilder::default();
    if std::env::var("USE_DOCKER").is_ok() {
        let docker_options = DockerOptionsBuilder::default()
            .root_dir(manifest_dir.join("../../"))
            .build()
            .unwrap();

        builder.use_docker(docker_options);
    }
    let guest_options = builder.build().unwrap();
    embed_methods_with_options(HashMap::from([("risc0-verifier", guest_options)]));
}
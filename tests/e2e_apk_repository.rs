//! End-to-end tests for the APK repository functionality.
//!
//! These tests verify that a real APK client (apk) can successfully
//! interact with the inapt repository server.
//!
//! These tests require Docker and are only compiled when the `e2e-docker` feature is enabled.
//! Run with: `cargo test --features e2e-docker`

#![cfg(feature = "e2e-docker")]

use anyhow::{Context, Result, bail};
use bollard::models::{ContainerCreateBody, HostConfig, NetworkCreateRequest};
use bollard::query_parameters::{
    BuildImageOptions, CreateContainerOptions, CreateImageOptions, LogsOptions,
    RemoveContainerOptions, StartContainerOptions, WaitContainerOptions,
};
use bollard::{Docker, body_full};
use bytes::Bytes;
use futures::StreamExt;
use std::time::Duration;
use walkdir::WalkDir;

const ALPINE_IMAGE: &str = "alpine:3.21";

const INAPT_IMAGE_NAME: &str = "inapt-e2e-test";

/// Build the inapt Docker image from the project's Dockerfile
async fn build_inapt_image(docker: &Docker) -> Result<()> {
    println!("Building inapt Docker image...");

    let mut tar_builder = tar::Builder::new(Vec::new());

    let project_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    let dockerfile_content = std::fs::read(project_root.join("tests/e2e.dockerfile"))
        .context("Failed to read e2e.dockerfile")?;
    let mut header = tar::Header::new_gnu();
    header.set_path("Dockerfile")?;
    header.set_size(dockerfile_content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar_builder.append(&header, dockerfile_content.as_slice())?;

    add_file_to_tar(&mut tar_builder, project_root, "Cargo.toml")?;
    add_file_to_tar(&mut tar_builder, project_root, "Cargo.lock")?;

    add_dir_to_tar(&mut tar_builder, project_root, "src")?;
    add_dir_to_tar(&mut tar_builder, project_root, "migrations")?;

    let tar_bytes = tar_builder.into_inner()?;

    let build_options = BuildImageOptions {
        dockerfile: "Dockerfile".to_string(),
        t: Some(INAPT_IMAGE_NAME.to_string()),
        rm: true,
        ..Default::default()
    };

    let mut build_stream =
        docker.build_image(build_options, None, Some(body_full(Bytes::from(tar_bytes))));

    while let Some(result) = build_stream.next().await {
        match result {
            Ok(output) => {
                if let Some(stream) = output.stream {
                    print!("{}", stream);
                }
                if let Some(error_detail) = output.error_detail {
                    let error_msg = error_detail.message.unwrap_or_default();
                    eprintln!("Build error: {}", error_msg);
                    bail!("Docker build error: {}", error_msg);
                }
            }
            Err(err) => {
                eprintln!("Build stream error: {}", err);
                return Err(err).context("Docker build stream error");
            }
        }
    }

    println!("Successfully built inapt image");
    Ok(())
}

fn add_file_to_tar(
    tar_builder: &mut tar::Builder<Vec<u8>>,
    base_path: &std::path::Path,
    relative_path: &str,
) -> Result<()> {
    let full_path = base_path.join(relative_path);
    let content = std::fs::read(&full_path)?;

    let mut header = tar::Header::new_gnu();
    header.set_path(relative_path)?;
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();

    tar_builder.append(&header, content.as_slice())?;
    Ok(())
}

fn add_dir_to_tar(
    tar_builder: &mut tar::Builder<Vec<u8>>,
    base_path: &std::path::Path,
    relative_dir: &str,
) -> Result<()> {
    let full_dir = base_path.join(relative_dir);

    for entry in walk_directory(full_dir.as_path(), relative_dir)? {
        let (rel_path, content, is_dir) = entry;
        let mut header = tar::Header::new_gnu();
        header.set_path(&rel_path)?;

        if is_dir {
            header.set_size(0);
            header.set_mode(0o755);
            header.set_entry_type(tar::EntryType::Directory);
            header.set_cksum();
            tar_builder.append(&header, &[] as &[u8])?;
        } else {
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder.append(&header, content.as_slice())?;
        }
    }

    Ok(())
}

fn walk_directory(path: &std::path::Path, prefix: &str) -> Result<Vec<(String, Vec<u8>, bool)>> {
    let mut results = Vec::new();

    for entry in WalkDir::new(path) {
        let entry = entry?;
        let entry_path = entry.path();
        let rel_path = entry_path.strip_prefix(path)?;
        let full_rel_path = if rel_path.as_os_str().is_empty() {
            prefix.to_string()
        } else {
            format!("{}/{}", prefix, rel_path.to_string_lossy())
        };

        if entry_path.is_dir() {
            results.push((format!("{}/", full_rel_path), Vec::new(), true));
        } else {
            let content = std::fs::read(entry_path)?;
            results.push((full_rel_path, content, false));
        }
    }

    Ok(results)
}

/// Create a test configuration for inapt
fn create_test_config(inapt_port: u16) -> String {
    format!(
        r#"[core]
repositories = ["jdrouet/inapt"]

[github]
base_url = "https://api.github.com"

[http_server]
address = "0.0.0.0"
port = {}

[pgp_cipher]
private_key_path = "/app/private-key.pem"

[rsa_signer]
private_key_path = "/app/rsa-private-key.pem"

[sqlite]
path = "/tmp/inapt.db"

[worker]
interval = 3600
"#,
        inapt_port
    )
}

/// Pull a Docker image if it doesn't exist locally
async fn pull_image(docker: &Docker, image: &str) -> Result<()> {
    println!("Pulling image: {}...", image);

    let options = CreateImageOptions {
        from_image: Some(image.to_string()),
        ..Default::default()
    };

    let mut stream = docker.create_image(Some(options), None, None);

    while let Some(result) = stream.next().await {
        match result {
            Ok(info) => {
                if let Some(status) = info.status {
                    print!("{}", status);
                    if let Some(progress_detail) = info.progress_detail
                        && let Some(current) = progress_detail.current
                    {
                        print!(" {}", current);
                    }
                    println!();
                }
            }
            Err(err) => {
                eprintln!("Pull error: {}", err);
                return Err(err).context(format!("Failed to pull image {}", image));
            }
        }
    }

    println!("Successfully pulled {}", image);
    Ok(())
}

/// Setup the test network with a unique name
async fn setup_network(docker: &Docker, test_name: &str) -> Result<String> {
    let network_name = format!("inapt-e2e-{}", test_name);

    let _ = docker.remove_network(&network_name).await;

    let network_config = NetworkCreateRequest {
        name: network_name.clone(),
        driver: Some("bridge".to_string()),
        ..Default::default()
    };

    docker
        .create_network(network_config)
        .await
        .context("Failed to create Docker network")?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let network_info = docker.inspect_network(&network_name, None).await?;
    println!(
        "Created network {} with ID {:?}",
        network_name, network_info.id
    );

    Ok(network_name)
}

/// Start the inapt container
async fn start_inapt_container(
    docker: &Docker,
    network_name: &str,
    test_name: &str,
) -> Result<String> {
    let project_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let private_key_path = project_root.join("resources/private-key.pem");
    let public_key_path = project_root.join("resources/public-key.pem");

    let config_content = create_test_config(3000);

    let temp_dir = tempfile::tempdir()?;
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, config_content)?;

    // Generate an RSA private key for APK signing in the temp directory
    let rsa_key_path = temp_dir.path().join("rsa-private-key.pem");
    generate_rsa_private_key(&rsa_key_path)?;

    let container_name = format!("inapt-e2e-server-{}", test_name);

    let _ = docker
        .remove_container(
            &container_name,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;

    let host_config = HostConfig {
        binds: Some(vec![
            format!("{}:/app/config.toml:ro", config_path.to_string_lossy()),
            format!(
                "{}:/app/private-key.pem:ro",
                private_key_path.to_string_lossy()
            ),
            format!(
                "{}:/app/public-key.pem:ro",
                public_key_path.to_string_lossy()
            ),
            format!(
                "{}:/app/rsa-private-key.pem:ro",
                rsa_key_path.to_string_lossy()
            ),
        ]),
        network_mode: Some(network_name.to_string()),
        ..Default::default()
    };

    let config = ContainerCreateBody {
        image: Some(INAPT_IMAGE_NAME.to_string()),
        hostname: Some(container_name.clone()),
        env: Some(vec!["CONFIG_PATH=/app/config.toml".to_string()]),
        host_config: Some(host_config),
        ..Default::default()
    };

    let create_options = CreateContainerOptions {
        name: Some(container_name.clone()),
        ..Default::default()
    };

    let container = docker
        .create_container(Some(create_options), config)
        .await
        .context("Failed to create inapt container")?;

    docker
        .start_container(&container.id, None::<StartContainerOptions>)
        .await
        .context("Failed to start inapt container")?;

    let container_info = docker.inspect_container(&container.id, None).await?;
    println!(
        "Server container networks: {:?}",
        container_info
            .network_settings
            .as_ref()
            .and_then(|ns| ns.networks.as_ref())
    );

    tokio::time::sleep(Duration::from_secs(5)).await;

    // Keep temp_dir alive by leaking it (it will be cleaned up when the test ends)
    std::mem::forget(temp_dir);

    Ok(container.id)
}

/// Generate an RSA private key in PKCS#1 PEM format for APK index signing
fn generate_rsa_private_key(path: &std::path::Path) -> Result<()> {
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::EncodeRsaPrivateKey;

    let mut rng = rand::thread_rng();
    let private_key =
        RsaPrivateKey::new(&mut rng, 2048).context("Failed to generate RSA private key")?;
    let pem = private_key
        .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .context("Failed to encode RSA private key as PEM")?;
    std::fs::write(path, pem.as_bytes()).context("Failed to write RSA private key")?;
    Ok(())
}

/// Run `apk update` in an Alpine container and verify it works
async fn run_apk_client_test(
    docker: &Docker,
    network_name: &str,
    inapt_hostname: &str,
    test_name: &str,
) -> Result<()> {
    let container_name = format!("inapt-e2e-client-{}", test_name);

    let _ = docker
        .remove_container(
            &container_name,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;

    let host_config = HostConfig {
        network_mode: Some(network_name.to_string()),
        ..Default::default()
    };

    let test_script = format!(
        r#"#!/bin/sh
set -e

echo "=== Starting APK client test ==="

# Add the inapt repository (allow untrusted since we use a test key)
echo "Adding inapt repository..."
echo "http://{}:3000" >> /etc/apk/repositories

# Show the repositories configuration
echo "Repository configuration:"
cat /etc/apk/repositories

# Run apk update (allow untrusted packages for testing)
echo "Running apk update..."
apk update --allow-untrusted 2>&1

echo "=== APK client test completed ==="
"#,
        inapt_hostname
    );

    let config = ContainerCreateBody {
        image: Some(ALPINE_IMAGE.to_string()),
        hostname: Some("apk-client".to_string()),
        cmd: Some(vec![
            "sh".to_string(),
            "-c".to_string(),
            test_script.clone(),
        ]),
        host_config: Some(host_config),
        ..Default::default()
    };

    let create_options = CreateContainerOptions {
        name: Some(container_name.clone()),
        ..Default::default()
    };

    let container = docker
        .create_container(Some(create_options), config)
        .await
        .context("Failed to create APK client container")?;

    docker
        .start_container(&container.id, None::<StartContainerOptions>)
        .await
        .context("Failed to start APK client container")?;

    let mut wait_stream = docker.wait_container(
        &container.id,
        Some(WaitContainerOptions {
            condition: "not-running".to_string(),
        }),
    );

    let mut exit_code = 0i64;
    while let Some(result) = wait_stream.next().await {
        match result {
            Ok(response) => {
                exit_code = response.status_code;
            }
            Err(err) => {
                eprintln!("Wait error: {}", err);
            }
        }
    }

    let log_options = LogsOptions {
        stdout: true,
        stderr: true,
        ..Default::default()
    };

    let mut logs_stream = docker.logs(&container.id, Some(log_options));
    let mut logs = String::new();

    while let Some(result) = logs_stream.next().await {
        match result {
            Ok(output) => {
                logs.push_str(&output.to_string());
            }
            Err(err) => {
                eprintln!("Log error: {}", err);
            }
        }
    }

    println!("=== Client container logs ===\n{}", logs);

    docker
        .remove_container(
            &container.id,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await?;

    if exit_code != 0 {
        bail!("apk update failed with exit code {}", exit_code);
    }

    if !logs.contains("APK client test completed") {
        bail!("Test did not complete successfully");
    }

    Ok(())
}

/// Cleanup test resources
async fn cleanup(
    docker: &Docker,
    inapt_container_id: Option<&str>,
    network_id: Option<&str>,
    test_name: &str,
) {
    if let Some(container_id) = inapt_container_id {
        let _ = docker
            .remove_container(
                container_id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;
    }

    let server_name = format!("inapt-e2e-server-{}", test_name);
    let _ = docker
        .remove_container(
            &server_name,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;

    let client_name = format!("inapt-e2e-client-{}", test_name);
    let _ = docker
        .remove_container(
            &client_name,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;

    if let Some(network) = network_id {
        let _ = docker.remove_network(network).await;
    }
}

#[tokio::test]
async fn should_update_apk_index_from_inapt_repository() {
    let docker = Docker::connect_with_local_defaults().expect("Failed to connect to Docker");
    let test_name = "apk-update";

    let mut inapt_container_id: Option<String> = None;
    let mut network_id: Option<String> = None;

    let result = async {
        build_inapt_image(&docker).await?;
        pull_image(&docker, ALPINE_IMAGE).await?;

        let net_id = setup_network(&docker, test_name).await?;
        network_id = Some(net_id.clone());

        let server_hostname = format!("inapt-e2e-server-{}", test_name);
        let container_id = start_inapt_container(&docker, &net_id, test_name).await?;
        inapt_container_id = Some(container_id.clone());

        println!("Waiting for inapt to sync packages from GitHub...");
        tokio::time::sleep(Duration::from_secs(30)).await;

        run_apk_client_test(&docker, &net_id, &server_hostname, test_name).await?;

        Ok::<(), anyhow::Error>(())
    }
    .await;

    cleanup(
        &docker,
        inapt_container_id.as_deref(),
        network_id.as_deref(),
        test_name,
    )
    .await;

    result.expect("E2E APK test failed");
}

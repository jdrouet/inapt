//! End-to-end tests for the APT repository functionality.
//!
//! These tests verify that a real APT client (apt-get) can successfully
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

const DEBIAN_IMAGE: &str = "debian:bookworm";

const INAPT_IMAGE_NAME: &str = "inapt-e2e-test";

/// Build the inapt Docker image from the project's Dockerfile
async fn build_inapt_image(docker: &Docker) -> Result<()> {
    println!("Building inapt Docker image...");

    // Create a tar archive of the build context
    let mut tar_builder = tar::Builder::new(Vec::new());

    // Add necessary files to the tar archive
    let project_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    // Add the e2e Dockerfile (renamed to Dockerfile in the archive)
    let dockerfile_content = std::fs::read(project_root.join("tests/e2e.dockerfile"))
        .context("Failed to read e2e.dockerfile")?;
    let mut header = tar::Header::new_gnu();
    header.set_path("Dockerfile")?;
    header.set_size(dockerfile_content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar_builder.append(&header, dockerfile_content.as_slice())?;

    // Add Cargo files
    add_file_to_tar(&mut tar_builder, project_root, "Cargo.toml")?;
    add_file_to_tar(&mut tar_builder, project_root, "Cargo.lock")?;

    // Add source directory
    add_dir_to_tar(&mut tar_builder, project_root, "src")?;

    // Add migrations directory
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
            Err(e) => {
                eprintln!("Build stream error: {}", e);
                return Err(e).context("Docker build stream error");
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
            Err(e) => {
                eprintln!("Pull error: {}", e);
                return Err(e).context(format!("Failed to pull image {}", image));
            }
        }
    }

    println!("Successfully pulled {}", image);
    Ok(())
}

/// Setup the test network with a unique name
async fn setup_network(docker: &Docker, test_name: &str) -> Result<String> {
    let network_name = format!("inapt-e2e-{}", test_name);

    // Try to remove existing network first
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

    // Wait a moment for the network to be fully ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Debug: verify network was created
    let network_info = docker.inspect_network(&network_name, None).await?;
    println!(
        "Created network {} with ID {:?}",
        network_name, network_info.id
    );

    // Return the network name for DNS resolution (not the ID)
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

    // Create a temp directory for the config
    let temp_dir = tempfile::tempdir()?;
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, config_content)?;

    let container_name = format!("inapt-e2e-server-{}", test_name);

    // Remove existing container if it exists
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

    // Debug: inspect container to verify network
    let container_info = docker.inspect_container(&container.id, None).await?;
    println!(
        "Server container networks: {:?}",
        container_info
            .network_settings
            .as_ref()
            .and_then(|ns| ns.networks.as_ref())
    );

    // Wait for the server to be ready
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Keep temp_dir alive by leaking it (it will be cleaned up when the test ends)
    std::mem::forget(temp_dir);

    Ok(container.id)
}

/// Run apt-get update in a Debian container and verify it works
async fn run_apt_client_test(
    docker: &Docker,
    network_name: &str,
    inapt_hostname: &str,
    test_name: &str,
) -> Result<()> {
    let container_name = format!("inapt-e2e-client-{}", test_name);

    // Remove existing container if it exists
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

    // Create a script that:
    // 1. Adds the inapt repository (with trusted=yes to bypass GPG verification for testing)
    // 2. Runs apt-get update
    // 3. Verifies packages are available
    let test_script = format!(
        r#"#!/bin/bash
set -e

echo "=== Starting APT client test ==="

# Add the repository with trusted=yes (bypasses GPG for testing purposes)
echo "Adding inapt repository..."
echo "deb [trusted=yes] http://{}:3000 stable main" > /etc/apt/sources.list.d/inapt.list

# Show the sources list
echo "Repository configuration:"
cat /etc/apt/sources.list.d/inapt.list

# Run apt-get update
echo "Running apt-get update..."
apt-get update 2>&1

# Verify the inapt repository was accessed by checking if packages are available
echo "Checking available packages from inapt..."
apt-cache policy inapt || echo "inapt package check done"

echo "=== APT client test completed ==="
"#,
        inapt_hostname
    );

    let config = ContainerCreateBody {
        image: Some(DEBIAN_IMAGE.to_string()),
        hostname: Some("apt-client".to_string()),
        cmd: Some(vec![
            "bash".to_string(),
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
        .context("Failed to create APT client container")?;

    docker
        .start_container(&container.id, None::<StartContainerOptions>)
        .await
        .context("Failed to start APT client container")?;

    // Wait for the container to finish and collect logs
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
            Err(e) => {
                eprintln!("Wait error: {}", e);
            }
        }
    }

    // Get logs
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
            Err(e) => {
                eprintln!("Log error: {}", e);
            }
        }
    }

    println!("=== Client container logs ===\n{}", logs);

    // Cleanup
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
        bail!("apt-get update failed with exit code {}", exit_code);
    }

    // Verify the logs contain expected output
    if !logs.contains("APT client test completed") {
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

    // Also try to remove by name
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
async fn test_apt_get_update_against_inapt_repository() {
    let docker = Docker::connect_with_local_defaults().expect("Failed to connect to Docker");
    let test_name = "apt-update";

    let mut inapt_container_id: Option<String> = None;
    let mut network_id: Option<String> = None;

    // Ensure cleanup happens even on panic
    let result = async {
        // Build the inapt image and pull Debian image
        build_inapt_image(&docker).await?;
        pull_image(&docker, DEBIAN_IMAGE).await?;

        // Setup network
        let net_id = setup_network(&docker, test_name).await?;
        network_id = Some(net_id.clone());

        // Start inapt container
        let server_hostname = format!("inapt-e2e-server-{}", test_name);
        let container_id = start_inapt_container(&docker, &net_id, test_name).await?;
        inapt_container_id = Some(container_id.clone());

        // Give the server more time to sync from GitHub
        println!("Waiting for inapt to sync packages from GitHub...");
        tokio::time::sleep(Duration::from_secs(30)).await;

        // Run the APT client test
        run_apt_client_test(&docker, &net_id, &server_hostname, test_name).await?;

        Ok::<(), anyhow::Error>(())
    }
    .await;

    // Cleanup
    cleanup(
        &docker,
        inapt_container_id.as_deref(),
        network_id.as_deref(),
        test_name,
    )
    .await;

    // Propagate error after cleanup
    result.expect("E2E test failed");
}

#[tokio::test]
async fn test_apt_get_update_with_by_hash() {
    let docker = Docker::connect_with_local_defaults().expect("Failed to connect to Docker");
    let test_name = "by-hash";

    let mut inapt_container_id: Option<String> = None;
    let mut network_id: Option<String> = None;

    let result = async {
        // Build the inapt image and pull Debian image
        build_inapt_image(&docker).await?;
        pull_image(&docker, DEBIAN_IMAGE).await?;

        // Setup network
        let net_id = setup_network(&docker, test_name).await?;
        network_id = Some(net_id.clone());

        // Start inapt container
        let server_hostname = format!("inapt-e2e-server-{}", test_name);
        let container_id = start_inapt_container(&docker, &net_id, test_name).await?;
        inapt_container_id = Some(container_id.clone());

        // Give the server time to sync
        println!("Waiting for inapt to sync packages from GitHub...");
        tokio::time::sleep(Duration::from_secs(30)).await;

        // Check if server is still running
        let server_info = docker.inspect_container(&container_id, None).await?;
        let is_running = server_info
            .state
            .as_ref()
            .and_then(|s| s.running)
            .unwrap_or(false);
        let exit_code = server_info.state.as_ref().and_then(|s| s.exit_code);
        println!(
            "Server container running: {}, exit_code: {:?}",
            is_running, exit_code
        );

        // Always get logs
        let log_options = LogsOptions {
            stdout: true,
            stderr: true,
            ..Default::default()
        };
        let mut logs_stream = docker.logs(&container_id, Some(log_options));
        let mut logs = String::new();
        while let Some(result) = logs_stream.next().await {
            if let Ok(output) = result {
                logs.push_str(&output.to_string());
            }
        }
        println!("Server logs:\n{}", logs);

        if !is_running {
            bail!(
                "Server container stopped unexpectedly with exit code {:?}",
                exit_code
            );
        }

        // Run a test that specifically checks by-hash is being used
        run_by_hash_verification_test(&docker, &net_id, &server_hostname, test_name).await?;

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

    result.expect("E2E by-hash test failed");
}

/// Run a test that verifies by-hash is advertised in the Release file
async fn run_by_hash_verification_test(
    docker: &Docker,
    network_name: &str,
    inapt_hostname: &str,
    test_name: &str,
) -> Result<()> {
    let container_name = format!("inapt-e2e-client-{}", test_name);

    // Remove existing container if it exists
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

    // Create a script that verifies by-hash support
    let test_script = format!(
        r#"#!/bin/bash
set -e

echo "=== Starting by-hash verification test ==="

# Install curl
apt-get update -qq
apt-get install -y -qq curl ca-certificates

# Debug: check DNS resolution and connectivity
echo "Checking DNS for {}..."
getent hosts {} || echo "WARNING: DNS lookup failed for {}"

echo "Network info:"
cat /etc/resolv.conf

# Try direct DNS query
apt-get install -y -qq dnsutils 2>/dev/null || true
nslookup {} 127.0.0.11 2>&1 || echo "nslookup failed"

# Try with the server's IP directly by checking /etc/hosts alternative
echo "Checking hosts file:"
cat /etc/hosts

# Fetch the Release file and check for Acquire-By-Hash
echo "Fetching Release file from http://{}:3000/dists/stable/Release ..."
RELEASE_CONTENT=$(curl -sf http://{}:3000/dists/stable/Release) || {{
    echo "ERROR: curl failed with exit code $?"
    echo "Trying with verbose output..."
    curl -v http://{}:3000/dists/stable/Release 2>&1 || true
    exit 1
}}

echo "Release file content:"
echo "$RELEASE_CONTENT"

# Check for Acquire-By-Hash: yes
if echo "$RELEASE_CONTENT" | grep -q "Acquire-By-Hash: yes"; then
    echo "SUCCESS: Acquire-By-Hash is enabled!"
else
    echo "FAILURE: Acquire-By-Hash not found in Release file"
    exit 1
fi

# Extract a SHA256 hash from the Release file and try to fetch via by-hash
echo "Testing by-hash endpoint..."
SHA256_HASH=$(echo "$RELEASE_CONTENT" | grep -A100 "SHA256:" | grep "main/binary-" | head -1 | awk '{{print $1}}')
ARCH=$(echo "$RELEASE_CONTENT" | grep -A100 "SHA256:" | grep "main/binary-" | head -1 | sed 's/.*binary-\([^/]*\).*/\1/')

if [ -n "$SHA256_HASH" ] && [ -n "$ARCH" ]; then
    echo "Found hash: $SHA256_HASH for architecture: $ARCH"
    BY_HASH_URL="http://{}:3000/dists/stable/main/binary-$ARCH/by-hash/SHA256/$SHA256_HASH"
    echo "Fetching: $BY_HASH_URL"

    HTTP_CODE=$(curl -s -o /dev/null -w "%{{http_code}}" "$BY_HASH_URL")
    if [ "$HTTP_CODE" = "200" ]; then
        echo "SUCCESS: by-hash endpoint returned 200!"
    else
        echo "FAILURE: by-hash endpoint returned $HTTP_CODE"
        exit 1
    fi
else
    echo "No SHA256 hashes found in Release file (repository might be empty)"
fi

echo "=== By-hash verification test completed ==="
"#,
        inapt_hostname,
        inapt_hostname,
        inapt_hostname,
        inapt_hostname,
        inapt_hostname,
        inapt_hostname,
        inapt_hostname,
        inapt_hostname
    );

    let config = ContainerCreateBody {
        image: Some(DEBIAN_IMAGE.to_string()),
        hostname: Some("apt-client-byhash".to_string()),
        cmd: Some(vec![
            "bash".to_string(),
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
        .context("Failed to create by-hash verification container")?;

    docker
        .start_container(&container.id, None::<StartContainerOptions>)
        .await
        .context("Failed to start by-hash verification container")?;

    // Debug: inspect client container to verify network
    let client_info = docker.inspect_container(&container.id, None).await?;
    println!(
        "Client container networks: {:?}",
        client_info
            .network_settings
            .as_ref()
            .and_then(|ns| ns.networks.as_ref())
    );

    // Debug: check network state to verify both containers are connected
    let network_state = docker.inspect_network(network_name, None).await?;
    println!(
        "Network {} has {} containers: {:?}",
        network_name,
        network_state
            .containers
            .as_ref()
            .map(|c| c.len())
            .unwrap_or(0),
        network_state
            .containers
            .as_ref()
            .map(|c| c.keys().collect::<Vec<_>>())
    );

    // Wait for completion
    let mut wait_stream = docker.wait_container(
        &container.id,
        Some(WaitContainerOptions {
            condition: "not-running".to_string(),
        }),
    );

    let mut exit_code = 0i64;
    while let Some(result) = wait_stream.next().await {
        if let Ok(response) = result {
            exit_code = response.status_code;
        }
    }

    // Get logs
    let log_options = LogsOptions {
        stdout: true,
        stderr: true,
        ..Default::default()
    };

    let mut logs_stream = docker.logs(&container.id, Some(log_options));
    let mut logs = String::new();

    while let Some(result) = logs_stream.next().await {
        if let Ok(output) = result {
            logs.push_str(&output.to_string());
        }
    }

    println!("=== By-hash client container logs ===\n{}", logs);

    // Cleanup
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
        bail!("by-hash verification failed with exit code {}", exit_code);
    }

    if !logs.contains("Acquire-By-Hash is enabled") {
        bail!("by-hash verification did not find Acquire-By-Hash");
    }

    Ok(())
}

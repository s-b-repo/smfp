use rand::Rng;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::time::sleep;

const PORTS: [u16; 2] = [21, 25]; // FTP and SMTP ports
const MAX_CONCURRENT_TASKS: usize = 100; // Limit concurrency to avoid overwhelming your system

/// Check if the IP is public.
fn is_public_ip(ip: Ipv4Addr) -> bool {
    // Exclude private, loopback, and link-local addresses.
    !ip.is_private() && !ip.is_loopback() && !ip.is_link_local()
}

/// Generate a random public IPv4 address.
fn random_public_ip() -> Ipv4Addr {
    let mut rng = rand::thread_rng();
    loop {
        let ip = Ipv4Addr::new(
            rng.gen_range(1..=223),
            rng.gen_range(0..=255),
            rng.gen_range(0..=255),
            rng.gen_range(0..=255),
        );
        if is_public_ip(ip) {
            return ip;
        }
    }
}

/// Uses RustScan to scan the target IP for the specified ports.
/// This function assumes that `rustscan` is installed and available in your system PATH.
async fn scan_with_rustscan(target_ip: &str) -> Result<Vec<u16>, String> {
    // Build a comma-separated list of ports.
    let ports_str = PORTS
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(",");

    // Run rustscan with the specified parameters.
    // The "-- -Pn" part passes arguments to rustscan's underlying nmap (disabling ping).
    let output = Command::new("rustscan")
        .args(&["-a", target_ip, "-p", &ports_str, "--", "-Pn"])
        .output()
        .await
        .map_err(|e| format!("Failed to execute rustscan: {}", e))?;

    if !output.status.success() {
        return Err(format!("RustScan failed with status: {:?}", output.status));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut open_ports = Vec::new();

    // Parse rustscan output: we assume that lines indicating an open port include "Open".
    for line in stdout.lines() {
        if line.contains("Open") {
            // Assume the first token is the port number.
            if let Some(port_str) = line.split_whitespace().next() {
                if let Ok(port) = port_str.parse::<u16>() {
                    open_ports.push(port);
                }
            }
        }
    }
    Ok(open_ports)
}

/// Append the scan result to a file if any open port is found.
async fn save_result(ip: Ipv4Addr, ports: &[u16]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("results.txt")
        .await
        .map_err(|e| format!("Failed to open results.txt: {}", e))?;

    let line = format!(
        "{}: {:?} - \n",
        ip, ports
    );

    file.write_all(line.as_bytes())
        .await
        .map_err(|e| format!("Failed to write to results.txt: {}", e))
}

#[tokio::main]
async fn main() {
    println!("Starting white hat scanner. Press Ctrl+C to stop.");
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_TASKS));

    loop {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let ip = random_public_ip();
        let ip_str = ip.to_string();

        // Spawn a task for each scan
        tokio::spawn(async move {
            println!("Scanning IP: {}", ip_str);
            match scan_with_rustscan(&ip_str).await {
                Ok(open_ports) => {
                    if !open_ports.is_empty() {
                        println!("Found open ports on {}: {:?}", ip_str, open_ports);
                        if let Err(e) = save_result(ip, &open_ports).await {
                            eprintln!("Error saving result: {}", e);
                        }
                    } else {
                        println!("No open ports found on {}", ip_str);
                    }
                }
                Err(e) => {
                    eprintln!("Error scanning {}: {}", ip_str, e);
                }
            }
            // Release the semaphore permit.
            drop(permit);
        });

        // A brief delay to avoid overloading the system.
        sleep(Duration::from_millis(100)).await;
    }
}

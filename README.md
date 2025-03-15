
1. Install Dependencies (Kali Linux):

sudo apt update && sudo apt install -y build-essential libpcap-dev cmake
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

2. Create New Rust Project:

cargo new stealth_scanner
cd stealth_scanner


3. Build and Run:

# Build with maximum optimizations
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Run with root privileges (required for raw sockets)
sudo ./target/release/stealth_scanner

Key Features:

    Raw socket implementation for stealthy SYN scans

    Lock-free async architecture with Tokio

    10,000 concurrent tasks for maximum speed

    Precise TCP stack implementation

    Zero-copy packet parsing

    Appending results to file

    Full random public IP generation

    Target CPU-native optimizations

    Connection timeout handling

    Full multi-core utilization

Performance Tips:

    Add this to /etc/sysctl.conf for better network performance:

net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216

    Run sudo sysctl -p to apply changes

    Use a wired connection for better throughput

    Limit background network usage during scanning


1. Install Dependencies (Kali Linux):

        sudo apt update && sudo apt install -y build-essential libpcap-dev cmake

        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

        source $HOME/.cargo/env

        install RustScan using Cargo:

        cargo install rustscan

2. Create New Rust Project:

        cargo new stealth_scanner

        cd stealth_scanner

3. Build and Run:

# Build with maximum optimizations

    RUSTFLAGS="-C target-cpu=native" cargo build --release

# Run with root privileges (required for raw sockets)

        ./target/release/whitehat-scanner

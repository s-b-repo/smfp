use std::{
    fs::OpenOptions,
    io::Write,
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use futures::stream::StreamExt;
use ipnetwork::Ipv4Network;
use pnet::{
    packet::{
        ip::IpNextHeaderProtocols,
        tcp::{TcpFlags, TcpOption, TcpOptionNumbers},
        Packet,
    },
    transport::{
        tcp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
        TransportReceiver, TransportSender,
    },
};
use rand::Rng;
use tokio::{
    sync::Mutex,
    time::{sleep, timeout},
};

const PORTS: [u16; 2] = [21, 25]; // FTP and SMTP
const MAX_CONCURRENT_TASKS: usize = 10_000;
const TIMEOUT_MS: u64 = 750;

struct Scanner {
    tx: TransportSender,
    rx: TransportReceiver,
}

impl Scanner {
    fn new() -> Result<Self, String> {
        let (tx, rx) = transport_channel(
            4096,
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
        )?;
        Ok(Self { tx, rx })
    }

    async fn send_syn(&self, ip: Ipv4Addr, port: u16) -> Result<(), String> {
        let mut rng = rand::thread_rng();
        let mut tcp_packet = pnet::packet::tcp::MutableTcpPacket::new(vec![0u8; 20]).unwrap();
        
        tcp_packet.set_source(rng.gen());
        tcp_packet.set_destination(port);
        tcp_packet.set_sequence(rng.gen());
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(64240);
        tcp_packet.set_options(&[TcpOption {
            number: TcpOptionNumbers::NOP,
            length: 1,
            data: Vec::new(),
        }]);

        let mut ip_packet = pnet::packet::ipv4::MutableIpv4Packet::new(vec![0u8; 20]).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(40);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_packet.set_source(ip.octets().into());
        ip_packet.set_destination(ip.octets().into());

        self.tx.send_to(ip_packet, pnet::transport::TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp))?;
        Ok(())
    }
}

fn is_public_ip(ip: Ipv4Addr) -> bool {
    !Ipv4Network::from(ip).is_private()
}

fn random_public_ip() -> Ipv4Addr {
    let mut rng = rand::thread_rng();
    loop {
        let a = rng.gen_range(1..=223);
        let b = rng.gen_range(0..=255);
        let c = rng.gen_range(0..=255);
        let d = rng.gen_range(0..=255);
        let ip = Ipv4Addr::new(a, b, c, d);
        if is_public_ip(ip) {
            return ip;
        }
    }
}

async fn scan_target(scanner: Arc<Mutex<Scanner>>, ip: Ipv4Addr) -> Option<Vec<u16>> {
    let mut open_ports = Vec::new();
    
    for &port in &PORTS {
        let scanner = scanner.clone();
        if let Ok(()) = scanner.lock().await.send_syn(ip, port).await {
            let mut receiver = { scanner.lock().await.rx.clone() };
            let mut iter = tcp_packet_iter(&mut receiver);
            
            if let Ok(Some((packet, _))) = timeout(
                Duration::from_millis(TIMEOUT_MS),
                async { iter.next().await }.await,
            ) {
                if packet.get_destination() == port 
                    && packet.get_flags() == TcpFlags::SYN | TcpFlags::ACK 
                {
                    open_ports.push(port);
                }
            }
        }
    }
    
    if !open_ports.is_empty() { Some(open_ports) } else { None }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = Arc::new(Mutex::new(Scanner::new()?));
    let file = Arc::new(Mutex::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open("results.txt")?,
    ));

    println!("Starting stealth scanner (Ctrl+C to exit)...");
    
    let (tx, mut rx) = tokio::sync::mpsc::channel(MAX_CONCURRENT_TASKS);
    
    // Producer task
    tokio::spawn(async move {
        loop {
            let ip = random_public_ip();
            tx.send(ip).await.unwrap();
        }
    });

    // Consumer tasks
    let mut handles = vec![];
    for _ in 0..MAX_CONCURRENT_TASKS {
        let scanner = scanner.clone();
        let file = file.clone();
        let mut rx = rx.clone();
        
        handles.push(tokio::spawn(async move {
            while let Some(ip) = rx.recv().await {
                if let Some(ports) = scan_target(scanner.clone(), ip).await {
                    if ports.contains(&21) && ports.contains(&25) {
                        let mut file = file.lock().await;
                        writeln!(file, "{}", ip).ok();
                        println!("Found valid target: {}", ip);
                    }
                }
            }
        }));
    }

    for handle in handles {
        handle.await?;
    }

    Ok(())
}

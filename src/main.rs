use anyhow::Result;
use clap::Parser;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;
use colored::*;

const BANNER: &str = r#"
╔════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                            ║
║__________                   __    __________ .__                     __                    ║
║\______   \  ____  _______ _/  |_  \______   \|  |  _____     _______/  |_   ____  _______  ║
║ |     ___/ /  _ \ \_  __ \\   __\  |    |  _/|  |  \__  \   /  ___/\   __\_/ __ \ \_  __ \ ║
║ |    |    (  <_> ) |  | \/ |  |    |    |   \|  |__ / __ \_ \___ \  |  |  \  ___/  |  | \/ ║
║ |____|     \____/  |__|    |__|    |______  /|____/(____  //____  > |__|   \___  > |__|    ║
║                                            \/            \/      \/             \/         ║
║                                                                                            ║
║   Port Blaster v1.0                                                                        ║
║   https://github.com/KodakSec   --> OpenSource Project                                     ║
╚════════════════════════════════════════════════════════════════════════════════════════════╝
"#;

#[derive(Parser, Debug)]
#[command(author, version, about = "Port Blaster KodakSec")]
struct Args {
    #[arg(short = 'H', long = "host")]
    target: String,
    #[arg(short, long, default_value = "1")]
    start_port: u16,
    #[arg(short, long, default_value = "1000")]
    end_port: u16,
    #[arg(short = 'T', long = "timeout", default_value = "1000")]
    timeout_ms: u64,
}

async fn scan_port(addr: IpAddr, port: u16, timeout_ms: u64) -> Result<Option<String>> {
    let socket = SocketAddr::new(addr, port);
    let timeout_duration = Duration::from_millis(timeout_ms);

    if let Ok(Ok(_)) = timeout(timeout_duration, TcpStream::connect(&socket)).await {
        let service = match port {
            1 => "TCPMUX",
            7 => "ECHO",
            9 => "DISCARD",
            13 => "DAYTIME",
            17 => "QOTD",
            19 => "CHARGEN",
            20 => "FTP-DATA",
            21 => "FTP",
            22 => "SSH",
            23 => "TELNET",
            25 => "SMTP",
            26 => "RSFTP",
            37 => "TIME",
            49 => "TACACS",
            53 => "DNS",
            67 => "DHCP-SERVER",
            68 => "DHCP-CLIENT",
            69 => "TFTP",
            79 => "FINGER",
            80 => "HTTP",
            81 => "TOR",
            88 => "KERBEROS",
            110 => "POP3",
            111 => "RPCBIND",
            119 => "NNTP",
            123 => "NTP",
            135 => "MSRPC",
            137 => "NETBIOS-NS",
            138 => "NETBIOS-DGM",
            139 => "NETBIOS-SSN",
            143 => "IMAP",
            161 => "SNMP",
            162 => "SNMP-TRAP",
            179 => "BGP",
            389 => "LDAP",
            443 => "HTTPS",
            445 => "MICROSOFT-DS",
            465 => "SMTPS",
            500 => "ISAKMP",
            513 => "RLOGIN",
            514 => "SYSLOG",
            515 => "LPD",
            520 => "RIP",
            523 => "IBM-DB2",
            548 => "AFP",
            554 => "RTSP",
            587 => "SUBMISSION",
            631 => "IPP",
            636 => "LDAPS",
            873 => "RSYNC",
            989 => "FTPS-DATA",
            990 => "FTPS",
            993 => "IMAPS",
            995 => "POP3S",
            25565 => "MINECRAFT",
            27015 => "SOURCE-ENGINE",
            27016 => "SOURCE-RCON",
            3724 => "WORLD-OF-WARCRAFT",
            6112 => "BATTLE.NET",
            6113 => "BATTLE.NET-2",
            6114 => "BATTLE.NET-3",
            3478 => "PLAYSTATION-NETWORK",
            3479 => "PLAYSTATION-NETWORK-2",
            3480 => "PLAYSTATION-NETWORK-3",
            3074 => "XBOX-LIVE",
            3075 => "XBOX-LIVE-2",
            3076 => "XBOX-LIVE-3",
            5222 => "LEAGUE-OF-LEGENDS",
            5223 => "LEAGUE-OF-LEGENDS-2",
            27014 => "STEAM",
            27015 => "STEAM-GAME",
            27016 => "STEAM-VOICE",
            27017 => "STEAM-RCON",
            27018 => "STEAM-QUERY",
            27019 => "STEAM-BROADCAST",
            1935 => "RTMP",
            3478 => "STUN",
            3479 => "TURN",
            5060 => "SIP",
            5061 => "SIPS",
            5222 => "XMPP-CLIENT",
            5223 => "XMPP-CLIENT-SSL",
            5228 => "GOOGLE-TALK",
            5242 => "WHATSAPP",
            5243 => "WHATSAPP-VOICE",
            5222 => "DISCORD",
            5223 => "DISCORD-VOICE",
            3478 => "TELEGRAM",
            3479 => "TELEGRAM-VOICE",
            5060 => "SKYPE",
            5061 => "SKYPE-VOICE",
            5222 => "SLACK",
            5223 => "SLACK-VOICE",
            1433 => "MSSQL",
            1434 => "MSSQL-UDP",
            1521 => "ORACLE",
            1527 => "ORACLE-XE",
            3306 => "MYSQL",
            5432 => "POSTGRESQL",
            6379 => "REDIS",
            27017 => "MONGODB",
            27018 => "MONGODB-SHARD",
            27019 => "MONGODB-CONFIG",
            28017 => "MONGODB-WEB",
            7474 => "NEO4J",
            7687 => "NEO4J-BOLT",
            8529 => "ARANGODB",
            9042 => "CASSANDRA",
            9160 => "CASSANDRA-THRIFT",
            11211 => "MEMCACHED",
            5984 => "COUCHDB",
            8086 => "INFLUXDB",
            8080 => "JENKINS",
            8443 => "JENKINS-SSL",
            8080 => "TOMCAT",
            8443 => "TOMCAT-SSL",
            9000 => "SONARQUBE",
            9418 => "GIT",
            9443 => "GITLAB",
            3000 => "NODE",
            4200 => "ANGULAR",
            8000 => "DJANGO",
            8080 => "SPRING-BOOT",
            9090 => "PROMETHEUS",
            9091 => "PROMETHEUS-PUSHGATEWAY",
            9093 => "ALERTMANAGER",
            9100 => "NODE-EXPORTER",
            9200 => "ELASTICSEARCH",
            9300 => "ELASTICSEARCH-NODE",
            1883 => "MQTT",
            8883 => "MQTT-SSL",
            1900 => "UPNP",
            5353 => "MDNS",
            32400 => "PLEX",
            8123 => "HOME-ASSISTANT",
            1880 => "NODE-RED",
            1883 => "MOSQUITTO",
            9100 => "PHILIPS-HUE",
            9999 => "NEST",
            554 => "RTSP-CAMERAS",
            8554 => "RTSP-CAMERAS-ALT",
            4444 => "METASPLOIT",
            31337 => "BACK-ORIFICE",
            8834 => "NESSUS",
            9390 => "OPENVAS",
            9391 => "OPENVAS-ADMIN",
            1241 => "NESSUS-OLD",
            102 => "S7COMM",
            502 => "MODBUS",
            20000 => "DNP3",
            44818 => "ETHERNET-IP",
            47808 => "BACNET",
            1089 => "FF-ANNUNC",
            1090 => "FF-FIELDBUS",
            1091 => "FF-SYSTEM",
            2222 => "EtherCAT",
            34962 => "PROFINET-1",
            34963 => "PROFINET-2",
            34964 => "PROFINET-3",
            2049 => "AWS-EFS",
            3389 => "AWS-WORKSPACES",
            5439 => "AWS-REDSHIFT",
            8080 => "AWS-ELASTIC-BEANSTALK",
            9092 => "AWS-MSK",
            9200 => "AWS-ELASTICSEARCH",
            9300 => "AWS-ELASTICSEARCH-NODE",
            2375 => "DOCKER",
            2376 => "DOCKER-SSL",
            2377 => "DOCKER-SWARM",
            4243 => "DOCKER-API",
            6443 => "KUBERNETES-API",
            10250 => "KUBELET",
            10255 => "KUBELET-READ",
            10256 => "KUBE-PROXY",
            1935 => "RTMP",
            554 => "RTSP",
            8554 => "RTSP-ALT",
            1755 => "MMS",
            8088 => "ICECAST",
            6970 => "QUICKTIME",
            7070 => "REALSERVER",
            8090 => "SPOTIFY",
            8091 => "SPOTIFY-WEB",
            8092 => "SPOTIFY-CONNECT",
            _ => "Unknown",
        };
        Ok(Some(service.to_string()))
    } else {
        Ok(None)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Enable colored output on Windows
    #[cfg(windows)]
    colored::control::set_virtual_terminal(true).unwrap_or(());
    
    print!("{}", BANNER.bright_cyan());
    
    let args = Args::parse();
    let start_time = Instant::now();

    println!("{}", "╔═══════════════════════════════════════════════════╗".bright_blue());
    println!("{}", "║                SCAN INFORMATION                   ║".bright_blue());
    println!("{}", "╚═══════════════════════════════════════════════════╝".bright_blue());
    println!("  🎯 Target    : {}", args.target.bright_yellow());

    let addr = format!("{}:80", args.target)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Could not resolve address: {}", args.target))?
        .ip();

    println!("  📡 IP        : {}", addr.to_string().bright_green());
    println!("  🔍 Ports     : {} → {}", args.start_port.to_string().bright_yellow(), args.end_port.to_string().bright_yellow());
    println!("  ⏱️  Timeout   : {}ms", args.timeout_ms.to_string().bright_yellow());
    println!();

    println!("{}", "╔═══════════════════════════════════════════════════╗".bright_blue());
    println!("{}", "║                   RESULTS                         ║".bright_blue());
    println!("{}", "╚═══════════════════════════════════════════════════╝".bright_blue());

    let mut open_ports = 0;
    for port in args.start_port..=args.end_port {
        if port % 100 == 0 {
            print!("\r  ⏳ Progress: Port {}/{} ({:>3}%)", 
                port.to_string().bright_yellow(),
                args.end_port.to_string().bright_yellow(),
                ((port as f32 / args.end_port as f32) * 100.0) as u32
            );
            std::io::Write::flush(&mut std::io::stdout())?;
        }

        if let Some(service) = scan_port(addr, port, args.timeout_ms).await? {
            println!("\r  🔓 Port {:>5} : {} ({})", 
                port.to_string().bright_green(),
                "OPEN".bright_green(),
                service.bright_yellow()
            );
            open_ports += 1;
        }
    }

    let duration = start_time.elapsed();
    println!("\n{}", "╔═══════════════════════════════════════════════════╗".bright_blue());
    println!("{}",   "║                 STATISTICS                        ║".bright_blue());
    println!("{}",   "╚═══════════════════════════════════════════════════╝".bright_blue());
    println!("  📊 Scanned ports : {}", (args.end_port - args.start_port + 1).to_string().bright_yellow());
    println!("  🔓 Open ports    : {}", open_ports.to_string().bright_green());
    println!("  ⏱️ Elapsed time  : {:.2}s", duration.as_secs_f32().to_string().bright_yellow());
    println!();

    Ok(())
} 

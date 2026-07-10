//! Smart SIEM — Realistic Log Simulator
//!
//! Generates security logs that look like real Filebeat/Winlogbeat
//! telemetry and sends them to the SIEM backend.
//!
//! Usage:
//!   cargo run -- --help
//!   cargo run -- --target http://localhost:3000
//!   cargo run -- --target http://localhost:3000 --brute-force --count 100
//!   cargo run -- --target http://localhost:3000 --nmap-scan
//!
//! The simulator sends logs in the exact same array-of-objects
//! format the SIEM collector API expects.

use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use serde::Serialize;
use std::time::SystemTime;

// ═══════════════════════════════════════════════════════════════
//  Log payload — matches CreateLogDto on the backend
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
struct LogEntry {
    collected_at: String,
    source_type: String,
    hostname: String,
    source_ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_principal: Option<String>,
    event_taxonomy: String,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<String>,
    severity: u8,
    raw_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
}

// ═══════════════════════════════════════════════════════════════
//  Scenario definitions
// ═══════════════════════════════════════════════════════════════

/// Linux SSH brute-force attempts from an external attacker
fn linux_ssh_brute_force(
    now: DateTime<Utc>,
    attacker_ip: &str,
    target_host: &str,
    usernames: &[&str],
    count: usize,
) -> Vec<LogEntry> {
    let mut logs = Vec::with_capacity(count);
    for i in 0..count {
        let ts = now - Duration::seconds(rand::thread_rng().gen_range(0..120));
        let user = usernames[i % usernames.len()];
        let raw = format!(
            "{{\"@timestamp\":\"{}\",\"@metadata\":{{\"beat\":\"filebeat\",\"type\":\"_doc\"}},\
             \"message\":\"{} {} sshd[{}]: Failed password for {} from {} port {} ssh2\",\
             \"log\":{{\"file\":{{\"path\":\"/var/log/auth.log\"}}}},\
             \"host\":{{\"name\":\"{}\"}},\"agent\":{{\"type\":\"filebeat\"}},\"ecs\":{{\"version\":\"8.0.0\"}}}}",
            ts.to_rfc3339(),
            ts.format("%Y-%m-%dT%H:%M:%S"),
            target_host,
            4000 + i % 500,
            user,
            attacker_ip,
            40000 + i % 5000,
            target_host.to_uppercase(),
        );

        logs.push(LogEntry {
            collected_at: ts.to_rfc3339(),
            source_type: "linux".into(),
            hostname: target_host.to_lowercase().into(),
            source_ip: attacker_ip.into(),
            destination_ip: None,
            source_port: Some(40000 + (i % 5000) as u16),
            destination_port: Some(22),
            user_principal: Some(user.to_string()),
            event_taxonomy: "authentication".into(),
            action: "user_login".into(),
            outcome: Some("failure".into()),
            severity: 4,
            raw_message: raw,
            tags: Some(vec!["linux".into(), "ssh".into(), "brute-force".into()]),
        });
    }
    logs
}

/// Windows Event 4625 login failures (XML format like Winlogbeat)
fn windows_4625_failures(
    now: DateTime<Utc>,
    attacker_ip: &str,
    target_host: &str,
    usernames: &[&str],
    count: usize,
) -> Vec<LogEntry> {
    let mut logs = Vec::with_capacity(count);
    for i in 0..count {
        let ts = now - Duration::seconds(rand::thread_rng().gen_range(0..120));
        let user = usernames[i % usernames.len()];
        let raw = format!(
            "<?xml version=\"1.0\"?><Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
             <System><EventID>4625</EventID><Computer>{}</Computer></System>\
             <EventData>\
             <Data Name=\"LogonType\">3</Data>\
             <Data Name=\"TargetUserName\">{}</Data>\
             <Data Name=\"WorkstationName\">-</Data>\
             <Data Name=\"IpAddress\">{}</Data>\
             <Data Name=\"IpPort\">{}</Data>\
             <Data Name=\"FailureReason\">%%2313</Data>\
             </EventData></Event>",
            target_host.to_uppercase(),
            user,
            attacker_ip,
            50000 + i % 5000,
        );

        logs.push(LogEntry {
            collected_at: ts.to_rfc3339(),
            source_type: "windows_security".into(),
            hostname: target_host.to_lowercase().into(),
            source_ip: attacker_ip.into(),
            destination_ip: Some(target_host.to_string()),
            source_port: Some(50000 + (i % 5000) as u16),
            destination_port: Some(3389),
            user_principal: Some(user.to_string()),
            event_taxonomy: "authentication".into(),
            action: "failed_login".into(),
            outcome: Some("failure".into()),
            severity: 5,
            raw_message: raw,
            tags: Some(vec!["windows".into(), "rdp".into(), "brute-force".into()]),
        });
    }
    logs
}

/// Windows 4624 successful logon
fn windows_4624_success(
    now: DateTime<Utc>,
    source_ip: &str,
    target_host: &str,
    user: &str,
) -> LogEntry {
    let ts = now - Duration::seconds(rand::thread_rng().gen_range(0..600));
    let raw = format!(
        "<?xml version=\"1.0\"?><Event xmlns=\"...\"><System><EventID>4624</EventID>\
         <Computer>{}</Computer></System>\
         <EventData>\
         <Data Name=\"LogonType\">3</Data>\
         <Data Name=\"TargetUserName\">{}</Data>\
         <Data Name=\"WorkstationName\">-</Data>\
         <Data Name=\"IpAddress\">{}</Data>\
         <Data Name=\"AuthenticationPackageName\">NTLM</Data>\
         </EventData></Event>",
        target_host.to_uppercase(),
        user,
        source_ip,
    );

    LogEntry {
        collected_at: ts.to_rfc3339(),
        source_type: "windows_security".into(),
        hostname: target_host.to_lowercase().into(),
        source_ip: source_ip.into(),
        destination_ip: Some(target_host.to_string()),
        source_port: Some(rand::thread_rng().gen_range(49000..65000)),
        destination_port: Some(3389),
        user_principal: Some(user.to_string()),
        event_taxonomy: "authentication".into(),
        action: "user_login".into(),
        outcome: Some("success".into()),
        severity: 2,
        raw_message: raw,
        tags: Some(vec!["windows".into(), "rdp".into()]),
    }
}

/// Windows log cleared (Event 1102) — suspicious
fn windows_log_cleared(now: DateTime<Utc>, hostname: &str, user: &str) -> LogEntry {
    let ts = now - Duration::seconds(rand::thread_rng().gen_range(0..3600));
    let raw = format!(
        "<Event xmlns=\"...\"><System><EventID>1102</EventID>\
         <Computer>{}</Computer></System>\
         <EventData>\
         <Data Name=\"SubjectUserName\">{}</Data>\
         </EventData></Event>",
        hostname.to_uppercase(),
        user,
    );

    LogEntry {
        collected_at: ts.to_rfc3339(),
        source_type: "windows_security".into(),
        hostname: hostname.to_lowercase().into(),
        source_ip: "127.0.0.1".into(),
        destination_ip: None,
        source_port: None,
        destination_port: None,
        user_principal: Some(user.to_string()),
        event_taxonomy: "system".into(),
        action: "log_cleared".into(),
        outcome: Some("success".into()),
        severity: 7,
        raw_message: raw,
        tags: Some(vec!["windows".into(), "defense-evasion".into(), "T1070".into()]),
    }
}

/// Nmap-style port scan detected by the target
fn nmap_scan_events(
    now: DateTime<Utc>,
    scanner_ip: &str,
    target_host: &str,
) -> Vec<LogEntry> {
    let ports = [22, 80, 443, 3389, 445, 135, 1433, 3306, 8080, 8443];
    let mut logs = Vec::new();
    for (i, &port) in ports.iter().enumerate() {
        let ts = now - Duration::seconds(rand::thread_rng().gen_range(0..300));
        let raw = format!(
            "{{\"@timestamp\":\"{}\",\"message\":\"{} {} sshd[{}]: Connection from {} port {}\",\
             \"log\":{{\"file\":{{\"path\":\"/var/log/syslog\"}}}},\
             \"host\":{{\"name\":\"{}\"}}}}",
            ts.to_rfc3339(),
            ts.format("%Y-%m-%dT%H:%M:%S"),
            target_host,
            4500 + i,
            scanner_ip,
            port,
            target_host.to_uppercase(),
        );

        logs.push(LogEntry {
            collected_at: ts.to_rfc3339(),
            source_type: "firewall".into(),
            hostname: target_host.to_lowercase().into(),
            source_ip: scanner_ip.into(),
            destination_ip: Some(target_host.to_string()),
            source_port: Some(rand::thread_rng().gen_range(30000..60000) as u16),
            destination_port: Some(port),
            user_principal: None,
            event_taxonomy: "reconnaissance".into(),
            action: "port_scan".into(),
            outcome: Some("failure".into()),
            severity: 5,
            raw_message: raw,
            tags: Some(vec!["network".into(), "scan".into(), "recon".into(), "T1046".into()]),
        });
    }
    logs
}

/// Firewall deny logs (pfSense / Windows Defender)
fn firewall_deny(
    now: DateTime<Utc>,
    source_ip: &str,
    target_host: &str,
    count: usize,
) -> Vec<LogEntry> {
    let mut logs = Vec::new();
    for i in 0..count {
        let ts = now - Duration::seconds(rand::thread_rng().gen_range(0..3600));
        let dst_port = rand::thread_rng().gen_range(1..65535);
        let raw = format!(
            "<134>{} {} filterlog: BLOCK in on wan: {}:{} -> {}:{} proto TCP",
            ts.format("%b %d %H:%M:%S"),
            target_host,
            source_ip,
            40000 + i,
            target_host,
            dst_port,
        );

        logs.push(LogEntry {
            collected_at: ts.to_rfc3339(),
            source_type: "firewall".into(),
            hostname: target_host.to_lowercase().into(),
            source_ip: source_ip.into(),
            destination_ip: Some(target_host.to_string()),
            source_port: Some(40000 + i as u16),
            destination_port: Some(dst_port as u16),
            user_principal: None,
            event_taxonomy: "network".into(),
            action: "connection_blocked".into(),
            outcome: Some("failure".into()),
            severity: 3,
            raw_message: raw,
            tags: Some(vec!["firewall".into(), "block".into()]),
        });
    }
    logs
}

/// Web server 404/401/500 errors (suspicious scanning)
fn web_server_errors(
    now: DateTime<Utc>,
    attacker_ip: &str,
    target_host: &str,
    count: usize,
) -> Vec<LogEntry> {
    let paths = [
        "/admin", "/wp-admin", "/.env", "/config.php", "/manager/html",
        "/phpmyadmin", "/actuator/health", "/api/docs", "/debug",
        "/console", "/server-status", "/.git/config", "/backup",
        "/wp-content", "/shell.php", "/cgi-bin/test.cgi",
    ];
    let methods = ["GET", "POST", "HEAD", "OPTIONS"];
    let statuses = [401, 403, 404, 500];
    let mut logs = Vec::new();
    for i in 0..count {
        let ts = now - Duration::seconds(rand::thread_rng().gen_range(0..600));
        let path = paths[i % paths.len()];
        let method = methods[i % methods.len()];
        let status = statuses[i % statuses.len()];
        let raw = format!(
            "{} - - [{}] \"{} {} HTTP/1.1\" {} {} \"-\" \"Mozilla/5.0\"",
            attacker_ip,
            ts.format("%d/%b/%Y:%H:%M:%S +0000"),
            method,
            path,
            status,
            rand::thread_rng().gen_range(100..5000),
        );

        logs.push(LogEntry {
            collected_at: ts.to_rfc3339(),
            source_type: "web_server".into(),
            hostname: target_host.to_lowercase().into(),
            source_ip: attacker_ip.into(),
            destination_ip: Some(target_host.to_string()),
            source_port: Some(rand::thread_rng().gen_range(40000..60000) as u16),
            destination_port: Some(443),
            user_principal: None,
            event_taxonomy: "web".into(),
            action: match status {
                401 | 403 => "access_denied".into(),
                404 => "page_not_found".into(),
                _ => "server_error".into(),
            },
            outcome: Some("failure".into()),
            severity: if status >= 500 { 5 } else { 3 },
            raw_message: raw,
            tags: Some(vec!["web".into(), "scan".into(), "reconnaissance".into()]),
        });
    }
    logs
}

/// Normal background noise — legitimate events to make the
/// simulation look like a real environment
fn background_noise(
    now: DateTime<Utc>,
    hosts: &[(&str, &str)],
    count: usize,
) -> Vec<LogEntry> {
    let actions = [
        ("authentication", "session_event", "success"),
        ("system", "process_started", "success"),
        ("network", "dns_query", "success"),
        ("system", "service_state", "success"),
    ];
    let mut logs = Vec::new();
    for _ in 0..count {
        let ts = now - Duration::seconds(rand::thread_rng().gen_range(0..7200));
        let (hostname, ip) = hosts[rand::thread_rng().gen_range(0..hosts.len())];
        let (tax, act, out) = actions[rand::thread_rng().gen_range(0..actions.len())];
        let src_type = ["syslog", "linux", "windows_appl"][rand::thread_rng().gen_range(0..3)];
        let raw = format!(
            "{{\"message\":\"{} background event from {}\",\"host\":{{\"name\":\"{}\"}}}}",
            ts.to_rfc3339(),
            ip,
            hostname.to_uppercase(),
        );

        logs.push(LogEntry {
            collected_at: ts.to_rfc3339(),
            source_type: src_type.into(),
            hostname: (*hostname).into(),
            source_ip: (*ip).into(),
            destination_ip: None,
            source_port: None,
            destination_port: None,
            user_principal: None,
            event_taxonomy: tax.into(),
            action: act.into(),
            outcome: Some(out.into()),
            severity: rand::thread_rng().gen_range(0..3),
            raw_message: raw,
            tags: Some(vec!["system".into()]),
        });
    }
    logs
}

/// Data exfiltration simulation — large outbound connections
fn data_exfil_events(now: DateTime<Utc>) -> Vec<LogEntry> {
    let mut logs = Vec::new();
    let internal_hosts = [
        ("192.168.243.20", "target-win"),
        ("192.168.243.15", "web-01"),
    ];
    let external_ips = [
        ("185.220.101.42", 443),
        ("91.121.87.34", 8080),
        ("51.15.43.132", 4444),
    ];
    for (internal_ip, hostname) in &internal_hosts {
        for (ext_ip, port) in &external_ips {
            let ts = Utc::now() - Duration::seconds(rand::thread_rng().gen_range(600..3600));
            let bytes = rand::thread_rng().gen_range(500_000..5_000_000);
            let raw = format!(
                "{{\"@timestamp\":\"{}\",\"message\":\"Large outbound connection: {} -> {}:{}, {} bytes\",\
                 \"event\":{{\"category\":[\"network\"],\"type\":[\"connection\"]}},\
                 \"network\":{{\"bytes\":{}}}}}",
                ts.to_rfc3339(),
                internal_ip,
                ext_ip,
                port,
                bytes,
                bytes,
            );
            logs.push(LogEntry {
                collected_at: ts.to_rfc3339(),
                source_type: "network".into(),
                hostname: (*hostname).into(),
                source_ip: (*internal_ip).into(),
                destination_ip: Some(ext_ip.to_string()),
                source_port: Some(rand::thread_rng().gen_range(49000..65000)),
                destination_port: Some(*port),
                user_principal: None,
                event_taxonomy: "network".into(),
                action: "data_transfer".into(),
                outcome: Some("success".into()),
                severity: 6,
                raw_message: raw,
                tags: Some(vec!["network".into(), "exfil".into(), "T1048".into()]),
            });
        }
    }
    logs
}

// ═══════════════════════════════════════════════════════════════
//  CLI & main
// ═══════════════════════════════════════════════════════════════

#[derive(Debug)]
struct Args {
    target: String,
    api_key: String,
    brute_force: bool,
    nmap_scan: bool,
    web_scan: bool,
    windows_rdp: bool,
    log_cleared: bool,
    firewall: bool,
    data_exfil: bool,
    count: usize,
    sleep_ms: u64,
}

fn parse_args() -> Args {
    let mut target = "http://localhost:3000".to_string();
    let mut api_key = "test-attack-001".to_string();
    let mut brute_force = false;
    let mut nmap_scan = false;
    let mut web_scan = false;
    let mut windows_rdp = false;
    let mut log_cleared = false;
    let mut firewall = false;
    let mut data_exfil = false;
    let mut count = 20;
    let mut sleep_ms = 50;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--target" | "-t" => {
                target = args.next().expect("--target needs a value");
            }
            "--api-key" | "-k" => {
                api_key = args.next().expect("--api-key needs a value");
            }
            "--brute-force" | "-b" => brute_force = true,
            "--nmap-scan" | "-n" => nmap_scan = true,
            "--web-scan" | "-w" => web_scan = true,
            "--windows-rdp" | "-r" => windows_rdp = true,
            "--log-cleared" | "-l" => log_cleared = true,
            "--firewall" | "-f" => firewall = true,
            "--data-exfil" | "-x" => data_exfil = true,
            "--count" | "-c" => {
                count = args
                    .next()
                    .expect("--count needs a value")
                    .parse()
                    .expect("--count must be a number");
            }
            "--sleep" | "-s" => {
                sleep_ms = args
                    .next()
                    .expect("--sleep needs a value")
                    .parse()
                    .expect("--sleep must be a number");
            }
            "--all" | "-a" => {
                brute_force = true;
                nmap_scan = true;
                web_scan = true;
                windows_rdp = true;
                log_cleared = true;
                firewall = true;
                data_exfil = true;
            }
            "--help" | "-h" => {
                println!(
                    r#"Smart SIEM — Realistic Log Simulator

USAGE:
  cargo run -- [OPTIONS]

SCENARIOS:
  -a, --all            All scenarios at once
  -b, --brute-force    Linux SSH + Windows RDP brute force (triggers R001)
  -n, --nmap-scan      Port scan (reconnaissance, triggers R005)
  -w, --web-scan       Web server scan (404/403/500 probes)
  -r, --windows-rdp    Windows RDP brute force (4625 events)
  -l, --log-cleared    Windows log cleared (1102, triggers R004)
  -f, --firewall       Firewall deny logs
  -x, --data-exfil     Data exfiltration (large transfers, triggers R003)

OPTIONS:
  -c, --count N       Events per scenario (default: 20)
  -s, --sleep MS       Milliseconds between batches (default: 50)
  -t, --target URL     SIEM API URL (default: http://localhost:3000)
  -k, --api-key KEY    API key (default: test-attack-001)
  -h, --help           Print this help

EXAMPLES:
  cargo run -- --all --count 50
  cargo run -- --brute-force --count 200    (trigger R001 in one shot)
  cargo run -- --target http://10.0.0.5:3000 --all --sleep 10
"#
                );
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {arg}. Use --help");
                std::process::exit(1);
            }
        }
    }
    Args {
        target,
        api_key,
        brute_force,
        nmap_scan,
        web_scan,
        windows_rdp,
        log_cleared,
        firewall,
        data_exfil,
        count,
        sleep_ms,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();
    let now = Utc::now();
    let mut rng = rand::thread_rng();

    // Realistic actors
    let attacker_kali = "192.168.243.10";
    let attacker_ext = "100.73.15.100";
    let attacker_ext2 = "178.43.12.87";
    let attacker_ext3 = "45.33.32.156";
    let attacker_ext4 = "103.235.46.191";

    let target_win = "target-win";
    let target_linux = "naren-pc";
    let target_dc = "dc-01";
    let target_web = "web-01";

    let usernames_ext = &["admin", "administrator", "root", "user", "naren", "test", "guest", "backup"];
    let usernames_int = &["naren", "jdoe", "asmith", "bkane", "administrator"];

    let mut all_logs: Vec<LogEntry> = Vec::new();

    if args.brute_force {
        // Windows RDP brute force from Kali to target-win
        all_logs.extend(windows_4625_failures(
            now, attacker_kali, target_win, usernames_int, args.count,
        ));
        // SSH brute force from external to naren-pc
        all_logs.extend(linux_ssh_brute_force(
            now, attacker_ext, target_linux, usernames_ext, args.count,
        ));
        // More RDP failures from other attackers to target-win
        all_logs.extend(windows_4625_failures(
            now, attacker_ext2, target_win, usernames_ext, args.count,
        ));
        // SSH attempts on DC-01
        all_logs.extend(linux_ssh_brute_force(
            now, attacker_ext3, target_dc, usernames_ext, args.count / 2,
        ));
    }

    if args.nmap_scan {
        all_logs.extend(nmap_scan_events(now, attacker_kali, target_win));
        all_logs.extend(nmap_scan_events(now, attacker_ext, target_linux));
    }

    if args.web_scan {
        all_logs.extend(web_server_errors(now, attacker_ext, target_web, args.count));
        all_logs.extend(web_server_errors(now, attacker_ext4, target_web, args.count / 2));
    }

    if args.windows_rdp {
        all_logs.push(windows_4624_success(now, attacker_kali, target_win, "naren"));
        all_logs.push(windows_4624_success(now, "192.168.243.1", target_win, "administrator"));
        all_logs.extend(windows_4625_failures(
            now, attacker_ext3, target_win, usernames_ext, args.count / 2,
        ));
        all_logs.extend(windows_4625_failures(
            now, attacker_ext4, target_win, usernames_ext, args.count / 2,
        ));
    }

    if args.log_cleared {
        all_logs.push(windows_log_cleared(now, target_win, "naren"));
        all_logs.push(windows_log_cleared(now, target_linux, "root"));
    }

    if args.firewall {
        all_logs.extend(firewall_deny(now, attacker_kali, target_win, args.count / 2));
        all_logs.extend(firewall_deny(now, attacker_ext, target_win, args.count / 3));
        all_logs.extend(firewall_deny(now, attacker_ext2, target_linux, args.count / 3));
    }

    if args.data_exfil {
        all_logs.extend(data_exfil_events(now));
    }

    // Background noise — 40% of count
    let noise_count = (args.count as f64 * 0.4).ceil() as usize;
    let hosts = &[
        (target_win, "192.168.243.20"),
        (target_linux, "172.28.96.229"),
        (target_dc, "192.168.243.5"),
        (target_web, "192.168.243.15"),
    ];
    all_logs.extend(background_noise(now, hosts, noise_count));

    // Shuffle so events are interleaved, not grouped by type
    use rand::seq::SliceRandom;
    all_logs.shuffle(&mut rng);

    // ══════════════════════════════════════════════════════════
    //  Send to the API in batches of 50
    // ══════════════════════════════════════════════════════════

    let url = format!("{}/api/v1/logs", args.target.trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    println!(
        " Sending {} log events to {} in batches of 50 ({}ms sleep/batch)...",
        all_logs.len(),
        url,
        args.sleep_ms,
    );

    let mut sent = 0;
    let mut accepted = 0;

    for chunk in all_logs.chunks(50) {
        let batch = chunk.to_vec();
        match client
            .post(&url)
            .header("X-API-Key", &args.api_key)
            .header("Content-Type", "application/json")
            .json(&batch)
            .send()
        {
            Ok(resp) => {
                let status = resp.status();
                let body: serde_json::Value = resp.json().unwrap_or_default();
                let ack = body.get("accepted").and_then(|v| v.as_u64()).unwrap_or(0);
                sent += chunk.len();
                accepted += ack as usize;
                print!(
                    "\r  Batch {}: {} sent, {} accepted (HTTP {})",
                    sent / 50,
                    chunk.len(),
                    ack,
                    status.as_u16(),
                );
            }
            Err(e) => {
                eprintln!("\n  Error sending batch: {e}");
            }
        }

        if args.sleep_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(args.sleep_ms));
        }
    }

    println!();
    println!(" Done. Sent: {sent}, Accepted: {accepted}");

    println!("\nSummary:");
    if args.brute_force { println!("  R001 SSH/RDP Brute force: x{count} per target", count = args.count); }
    if args.nmap_scan { println!("  R005 Port scan: 10 ports x 2 targets"); }
    if args.web_scan { println!("  Web scan: {count} suspicious HTTP probes", count = args.count); }
    if args.windows_rdp { println!("  Windows RDP: failures + 2 legit logins"); }
    if args.log_cleared { println!("  R004 Log cleared (T1070): 2 events"); }
    if args.firewall { println!("  Firewall blocks: ~{} events", args.count / 2 + args.count / 3 + args.count / 3); }
    if args.data_exfil { println!("  R003 Data exfil (T1048): 6 large transfers"); }
    println!("  Noise: {noise_count} background events");

    println!("\nCheck the UI or:");
    println!("  curl -s http://localhost:3000/api/v1/incidents | jq .");
    println!("  curl -s http://localhost:3000/api/v1/soar/actions | jq .");

    Ok(())
}

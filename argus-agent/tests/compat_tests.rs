//! Cross-platform tests for procfs parsing and RHEL kernel detection logic.
//!
//! These test pure parsing functions that don't require Linux syscalls,
//! extracted here so they run on CI regardless of host OS.

// --- Procfs parsing (uses the same logic as the Linux-only module) ---

#[test]
fn parse_proc_interrupts_multi_cpu() {
    let content = "\
           CPU0       CPU1       CPU2       CPU3
  0:         20          0          0          0   IO-APIC   2-edge      timer
  1:          9          0          0          0   IO-APIC   1-edge      i8042
  8:          0          0          0          1   IO-APIC   8-edge      rtc0
LOC:     100500      99200      98700     101000   Local timer interrupts
";
    let per_cpu = parse_interrupts_test(content);
    assert_eq!(per_cpu.len(), 4);
    assert_eq!(per_cpu[0], 100529); // 20 + 9 + 0 + 100500
    assert_eq!(per_cpu[1], 99200);
    assert_eq!(per_cpu[2], 98700);
    assert_eq!(per_cpu[3], 101001); // 1 + 101000
}

#[test]
fn parse_proc_softnet_stat_hex() {
    let content = "\
00001234 00000000 00000005 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
0000abcd 00000002 00000010 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
";
    let rows = parse_softnet_test(content);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], (0x1234, 0, 5));
    assert_eq!(rows[1], (0xabcd, 2, 0x10));
}

#[test]
fn parse_proc_slabinfo_basic() {
    let content = "\
slabinfo - version: 2.1
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
kmalloc-256         1000       1200    256   32    2 : tunables    0    0    0 : slabdata     38     38      0
kmalloc-128          500        600    128   64    2 : tunables    0    0    0 : slabdata     10     10      0
";
    let (active, total, slabs) = parse_slabinfo_test(content);
    assert_eq!(active, 1500);
    assert_eq!(total, 1800);
    assert_eq!(slabs, 48);
}

#[test]
fn rhel_suffix_extraction() {
    assert_eq!(extract_rhel_suffix("4.18.0-305.el8.x86_64"), Some(8));
    assert_eq!(extract_rhel_suffix("5.14.0-70.22.1.el9_0.x86_64"), Some(9));
    assert_eq!(extract_rhel_suffix("6.2.0-100.el10.x86_64"), Some(10));
    assert_eq!(extract_rhel_suffix("5.15.148-tegra"), None);
    assert_eq!(extract_rhel_suffix("6.8.0-45-generic"), None);
}

#[test]
fn rhel_build_number_extraction() {
    assert_eq!(extract_rhel_build("4.18.0-305.el8.x86_64"), Some(305));
    assert_eq!(extract_rhel_build("4.18.0-553.el8.x86_64"), Some(553));
    assert_eq!(extract_rhel_build("5.14.0-70.22.1.el9_0.x86_64"), Some(70));
    assert_eq!(extract_rhel_build("5.14.0-503.el9.x86_64"), Some(503));
}

#[test]
fn kernel_version_parsing() {
    assert_eq!(parse_kver("5.15.148-tegra"), Some((5, 15)));
    assert_eq!(parse_kver("6.8.0-45-generic"), Some((6, 8)));
    assert_eq!(parse_kver("4.18.0-305.el8.x86_64"), Some((4, 18)));
    assert_eq!(parse_kver("not-a-version"), None);
}

// --- Helpers: re-implement the pure parsing logic for cross-platform testing ---
// These mirror the private functions in procfs.rs and kallsyms.rs exactly.

fn parse_interrupts_test(content: &str) -> Vec<u64> {
    let mut lines = content.lines();
    let header = match lines.next() {
        Some(h) => h,
        None => return Vec::new(),
    };
    let num_cpus = header.split_whitespace().count();
    let mut per_cpu = vec![0u64; num_cpus];

    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < num_cpus + 1 {
            continue;
        }
        for (i, part) in parts[1..=num_cpus].iter().enumerate() {
            if let Ok(val) = part.parse::<u64>() {
                per_cpu[i] += val;
            }
        }
    }
    per_cpu
}

fn parse_softnet_test(content: &str) -> Vec<(u64, u64, u64)> {
    content
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 3 {
                return None;
            }
            let processed = u64::from_str_radix(cols[0], 16).ok()?;
            let dropped = u64::from_str_radix(cols[1], 16).ok()?;
            let time_squeeze = u64::from_str_radix(cols[2], 16).ok()?;
            Some((processed, dropped, time_squeeze))
        })
        .collect()
}

fn parse_slabinfo_test(content: &str) -> (u64, u64, u64) {
    let mut active = 0u64;
    let mut total = 0u64;
    let mut slabs = 0u64;

    for line in content.lines().skip(2) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 14 {
            continue;
        }
        if let (Ok(a), Ok(t)) = (parts[1].parse::<u64>(), parts[2].parse::<u64>()) {
            active += a;
            total += t;
        }
        if let Ok(s) = parts[13].parse::<u64>() {
            slabs += s;
        }
    }
    (active, total, slabs)
}

fn extract_rhel_suffix(release: &str) -> Option<u32> {
    let idx = release.find(".el")?;
    let after = &release[idx + 3..];
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn extract_rhel_build(release: &str) -> Option<u32> {
    let dash_idx = release.find('-')?;
    let after_dash = &release[dash_idx + 1..];
    let digits: String = after_dash
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

fn parse_kver(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor_str = parts.next()?;
    let minor_digits: String = minor_str
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let minor: u32 = minor_digits.parse().ok()?;
    Some((major, minor))
}

//! Parse tracepoint format files from tracefs to discover field offsets at runtime.
//!
//! Tracepoint struct layouts vary across kernel versions. Rather than hardcoding
//! offsets that silently read garbage on the wrong kernel, we read the canonical
//! layout from `/sys/kernel/tracing/events/{category}/{name}/format` (or the
//! debugfs fallback) and pass the discovered offsets to BPF via the OFFSETS map.

use std::collections::HashMap;
use std::path::Path;

/// OFFSETS map index assignments. Must match `argus-ebpf/src/main.rs`.
pub const OFF_IRQ_IRQ: u32 = 0;
pub const OFF_NAPI_WORK: u32 = 1;
pub const OFF_NAPI_BUDGET: u32 = 2;
pub const OFF_SLAB_BYTES_REQ: u32 = 3;
pub const OFF_SLAB_BYTES_ALLOC: u32 = 4;

#[derive(Debug, Clone)]
pub struct TracepointField {
    pub name: String,
    pub offset: u32,
    pub size: u32,
}

/// Parse a tracefs format file and return a map of field_name -> TracepointField
/// for all non-common fields.
pub fn parse_format_file(content: &str) -> HashMap<String, TracepointField> {
    let mut fields = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if !line.starts_with("field:") {
            continue;
        }

        // Format: "field:<type> <name>;\toffset:<N>;\tsize:<N>;\tsigned:<N>;"
        let parts: Vec<&str> = line.split(';').collect();
        if parts.len() < 3 {
            continue;
        }

        let field_decl = parts[0].trim().trim_start_matches("field:");
        let field_name = extract_field_name(field_decl);

        if field_name.is_empty() || field_name.starts_with("common_") {
            continue;
        }

        let offset = parse_kv(parts[1].trim(), "offset:");
        let size = parse_kv(parts[2].trim(), "size:");

        if let (Some(offset), Some(size)) = (offset, size) {
            fields.insert(
                field_name.clone(),
                TracepointField {
                    name: field_name,
                    offset,
                    size,
                },
            );
        }
    }
    fields
}

fn extract_field_name(decl: &str) -> String {
    let decl = decl.trim();
    let last_token = decl.split_whitespace().next_back().unwrap_or("");
    last_token
        .trim_start_matches('*')
        .split('[')
        .next()
        .unwrap_or("")
        .to_string()
}

fn parse_kv(s: &str, prefix: &str) -> Option<u32> {
    s.strip_prefix(prefix)?.trim().parse().ok()
}

/// Read and parse a tracepoint format file from tracefs.
/// Tries `/sys/kernel/tracing/events/` first, then `/sys/kernel/debug/tracing/events/`.
pub fn read_tracepoint_fields(
    category: &str,
    name: &str,
) -> Result<HashMap<String, TracepointField>, String> {
    let paths = [
        format!("/sys/kernel/tracing/events/{category}/{name}/format"),
        format!("/sys/kernel/debug/tracing/events/{category}/{name}/format"),
    ];

    for path in &paths {
        if Path::new(path).exists() {
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("failed to read {path}: {e}"))?;
            return Ok(parse_format_file(&content));
        }
    }

    Err(format!(
        "tracepoint format not found for {category}/{name} (tried tracefs and debugfs)"
    ))
}

/// Discover all offsets needed by ARGUS probes and return them as (map_index, offset) pairs.
/// Logs warnings for any fields that can't be resolved.
pub fn discover_offsets() -> Vec<(u32, u32)> {
    let mut offsets = Vec::new();

    // #region agent log
    {
        use std::io::Write;
        eprintln!("[ARGUS-DEBUG] discover_offsets called");
        for path in &["/home/kevin/Projects/networking/ARGUS/.cursor/debug.log", "/tmp/argus-debug.log"] {
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(f, r#"{{"id":"log_discover_start","timestamp":{},"location":"tracepoint_format.rs:discover_offsets","message":"discover_offsets called","data":{{}},"runId":"run1","hypothesisId":"H1"}}"#, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis());
            } else {
                eprintln!("[ARGUS-DEBUG] FAILED to open {path}");
            }
        }
    }
    // #endregion

    if let Ok(fields) = read_tracepoint_fields("irq", "irq_handler_entry") {
        if let Some(f) = fields.get("irq") {
            tracing::info!(field = "irq", offset = f.offset, size = f.size, "irq_handler_entry");
            offsets.push((OFF_IRQ_IRQ, f.offset));
        } else {
            tracing::warn!("irq_handler_entry: 'irq' field not found in format file");
        }
    } else {
        tracing::warn!("could not read irq/irq_handler_entry format file");
    }

    if let Ok(fields) = read_tracepoint_fields("napi", "napi_poll") {
        // #region agent log
        {
            use std::io::Write;
            let field_names: Vec<String> = fields.iter().map(|(k, v)| format!("{}@{}({}B)", k, v.offset, v.size)).collect();
            let msg = format!("[ARGUS-DEBUG] napi_poll fields: {:?}, has_work={}, has_budget={}", field_names, fields.contains_key("work"), fields.contains_key("budget"));
            eprintln!("{msg}");
            for path in &["/home/kevin/Projects/networking/ARGUS/.cursor/debug.log", "/tmp/argus-debug.log"] {
                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                    let _ = writeln!(f, r#"{{"id":"log_napi_fields","timestamp":{},"location":"tracepoint_format.rs:discover_offsets","message":"napi_poll fields","data":{{"fields":"{}"}},"runId":"run1","hypothesisId":"H3"}}"#, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis(), msg);
                }
            }
        }
        // #endregion
        if let Some(f) = fields.get("work") {
            tracing::info!(field = "work", offset = f.offset, size = f.size, "napi_poll");
            offsets.push((OFF_NAPI_WORK, f.offset));
        } else {
            tracing::warn!("napi_poll: 'work' field not found in format file");
        }
        if let Some(f) = fields.get("budget") {
            tracing::info!(field = "budget", offset = f.offset, size = f.size, "napi_poll");
            offsets.push((OFF_NAPI_BUDGET, f.offset));
        } else {
            tracing::warn!("napi_poll: 'budget' field not found in format file");
        }
    } else {
        tracing::warn!("could not read napi/napi_poll format file");
    }

    if let Ok(fields) = read_tracepoint_fields("kmem", "kmem_cache_alloc") {
        if let Some(f) = fields.get("bytes_req") {
            tracing::info!(field = "bytes_req", offset = f.offset, size = f.size, "kmem_cache_alloc");
            offsets.push((OFF_SLAB_BYTES_REQ, f.offset));
        } else {
            tracing::warn!("kmem_cache_alloc: 'bytes_req' field not found in format file");
        }
        if let Some(f) = fields.get("bytes_alloc") {
            tracing::info!(field = "bytes_alloc", offset = f.offset, size = f.size, "kmem_cache_alloc");
            offsets.push((OFF_SLAB_BYTES_ALLOC, f.offset));
        } else {
            tracing::warn!("kmem_cache_alloc: 'bytes_alloc' field not found in format file");
        }
    } else {
        tracing::warn!("could not read kmem/kmem_cache_alloc format file");
    }

    // #region agent log
    {
        use std::io::Write;
        let msg = format!("[ARGUS-DEBUG] discover_offsets result: count={}, offsets={:?}", offsets.len(), offsets);
        eprintln!("{msg}");
        for path in &["/home/kevin/Projects/networking/ARGUS/.cursor/debug.log", "/tmp/argus-debug.log"] {
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(f, r#"{{"id":"log_discover_result","timestamp":{},"location":"tracepoint_format.rs:discover_offsets","message":"discover result","data":{{"msg":"{}"}},"runId":"run1","hypothesisId":"H1"}}"#, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis(), msg.replace('"', "'"));
            }
        }
    }
    // #endregion

    offsets
}

#[cfg(test)]
mod tests {
    use super::*;

    const IRQ_FORMAT: &str = r#"name: irq_handler_entry
ID: 44
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int irq;	offset:8;	size:4;	signed:1;
	field:__data_loc char[] name;	offset:12;	size:4;	signed:0;

print fmt: "irq=%d name=%s", REC->irq, __get_str(name)
"#;

    const NAPI_FORMAT: &str = r#"name: napi_poll
ID: 1340
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:struct napi_struct * napi;	offset:8;	size:8;	signed:0;
	field:__data_loc char[] dev_name;	offset:16;	size:4;	signed:0;
	field:int work;	offset:20;	size:4;	signed:1;
	field:int budget;	offset:24;	size:4;	signed:1;

print fmt: "napi poll on napi struct %p for device %s work %d budget %d", REC->napi, __get_str(dev_name), REC->work, REC->budget
"#;

    const KMEM_FORMAT: &str = r#"name: kmem_cache_alloc
ID: 456
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long call_site;	offset:8;	size:8;	signed:0;
	field:const void * ptr;	offset:16;	size:8;	signed:0;
	field:size_t bytes_req;	offset:24;	size:8;	signed:0;
	field:size_t bytes_alloc;	offset:32;	size:8;	signed:0;
	field:unsigned long gfp_flags;	offset:40;	size:8;	signed:0;
	field:int node;	offset:48;	size:4;	signed:1;
	field:bool accounted;	offset:52;	size:1;	signed:0;

print fmt: "call_site=%pS ptr=%p bytes_req=%zu bytes_alloc=%zu gfp_flags=%s node=%d accounted=%s", (void *)REC->call_site, REC->ptr, REC->bytes_req, REC->bytes_alloc, ...
"#;

    #[test]
    fn parse_irq_handler_entry() {
        let fields = parse_format_file(IRQ_FORMAT);
        assert!(fields.contains_key("irq"));
        assert_eq!(fields["irq"].offset, 8);
        assert_eq!(fields["irq"].size, 4);
        assert!(fields.contains_key("name"));
        assert!(!fields.contains_key("common_type"));
    }

    #[test]
    fn parse_napi_poll() {
        let fields = parse_format_file(NAPI_FORMAT);
        assert_eq!(fields["work"].offset, 20);
        assert_eq!(fields["work"].size, 4);
        assert_eq!(fields["budget"].offset, 24);
        assert_eq!(fields["budget"].size, 4);
        assert_eq!(fields["napi"].offset, 8);
        assert_eq!(fields["napi"].size, 8);
    }

    #[test]
    fn parse_kmem_cache_alloc() {
        let fields = parse_format_file(KMEM_FORMAT);
        assert_eq!(fields["bytes_req"].offset, 24);
        assert_eq!(fields["bytes_req"].size, 8);
        assert_eq!(fields["bytes_alloc"].offset, 32);
        assert_eq!(fields["bytes_alloc"].size, 8);
        assert_eq!(fields["call_site"].offset, 8);
        assert_eq!(fields["ptr"].offset, 16);
        assert_eq!(fields["node"].offset, 48);
    }

    #[test]
    fn parse_empty_content() {
        let fields = parse_format_file("");
        assert!(fields.is_empty());
    }

    #[test]
    fn parse_malformed_lines() {
        let content = "field:int foo;\n\tfield:int bar;\toffset:xyz;\tsize:4;\n";
        let fields = parse_format_file(content);
        assert!(fields.is_empty());
    }

    #[test]
    fn field_name_extraction() {
        assert_eq!(extract_field_name("int irq"), "irq");
        assert_eq!(extract_field_name("struct napi_struct * napi"), "napi");
        assert_eq!(extract_field_name("__data_loc char[] name"), "name");
        assert_eq!(extract_field_name("unsigned long gfp_flags"), "gfp_flags");
        assert_eq!(extract_field_name("const void * ptr"), "ptr");
        assert_eq!(extract_field_name("char name[16]"), "name");
        assert_eq!(extract_field_name("size_t bytes_req"), "bytes_req");
    }
}

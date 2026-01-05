//! Utility functions for package repository operations.
//! These are extracted for benchmarking and reuse.

use sha2::{Digest, Sha256};
use sha1::Sha1;

/// Calculate the Cargo index path for a crate name per Cargo spec
/// - 1 char: 1/{name}
/// - 2 chars: 2/{name}
/// - 3 chars: 3/{first_char}/{name}
/// - 4+ chars: {first_two}/{third_fourth}/{name}
#[inline]
pub fn cargo_index_path(crate_name: &str) -> String {
    let name = crate_name.to_lowercase();
    match name.len() {
        0 => name,
        1 => format!("1/{}", name),
        2 => format!("2/{}", name),
        3 => format!("3/{}/{}", &name[0..1], name),
        _ => format!("{}/{}/{}", &name[0..2], &name[2..4], name),
    }
}

/// Optimized Cargo index path using pre-allocated string
#[inline]
pub fn cargo_index_path_optimized(crate_name: &str) -> String {
    let name_lower: String = crate_name.chars().map(|c| c.to_ascii_lowercase()).collect();
    let len = name_lower.len();

    match len {
        0 => name_lower,
        1 => {
            let mut result = String::with_capacity(2 + len);
            result.push_str("1/");
            result.push_str(&name_lower);
            result
        }
        2 => {
            let mut result = String::with_capacity(2 + len);
            result.push_str("2/");
            result.push_str(&name_lower);
            result
        }
        3 => {
            let mut result = String::with_capacity(4 + len);
            result.push_str("3/");
            result.push(name_lower.chars().next().unwrap());
            result.push('/');
            result.push_str(&name_lower);
            result
        }
        _ => {
            let mut result = String::with_capacity(6 + len);
            result.push_str(&name_lower[0..2]);
            result.push('/');
            result.push_str(&name_lower[2..4]);
            result.push('/');
            result.push_str(&name_lower);
            result
        }
    }
}

/// Compare version strings (semantic versioning style)
#[inline]
pub fn version_compare(a: &str, b: &str) -> std::cmp::Ordering {
    let a_parts: Vec<&str> = a.split(|c| c == '.' || c == '-').collect();
    let b_parts: Vec<&str> = b.split(|c| c == '.' || c == '-').collect();

    for (a_part, b_part) in a_parts.iter().zip(b_parts.iter()) {
        match (a_part.parse::<u64>(), b_part.parse::<u64>()) {
            (Ok(a_num), Ok(b_num)) => {
                if a_num != b_num {
                    return a_num.cmp(&b_num);
                }
            }
            _ => {
                if a_part != b_part {
                    return a_part.cmp(b_part);
                }
            }
        }
    }

    a_parts.len().cmp(&b_parts.len())
}

/// Optimized version comparison using iterators
#[inline]
pub fn version_compare_optimized(a: &str, b: &str) -> std::cmp::Ordering {
    let mut a_iter = a.split(|c: char| c == '.' || c == '-');
    let mut b_iter = b.split(|c: char| c == '.' || c == '-');

    loop {
        match (a_iter.next(), b_iter.next()) {
            (Some(a_part), Some(b_part)) => {
                let cmp = match (a_part.parse::<u64>(), b_part.parse::<u64>()) {
                    (Ok(a_num), Ok(b_num)) => a_num.cmp(&b_num),
                    _ => a_part.cmp(b_part),
                };
                if cmp != std::cmp::Ordering::Equal {
                    return cmp;
                }
            }
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (None, None) => return std::cmp::Ordering::Equal,
        }
    }
}

/// Extract a value from XML by tag name (simple implementation)
#[inline]
pub fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{}>", tag);
    let end_tag = format!("</{}>", tag);

    let start = xml.find(&start_tag)? + start_tag.len();
    let end = xml[start..].find(&end_tag)? + start;

    Some(xml[start..end].trim().to_string())
}

/// Optimized XML value extraction avoiding allocations for tag strings
#[inline]
pub fn extract_xml_value_optimized(xml: &str, tag: &str) -> Option<String> {
    // Build search patterns more efficiently
    let mut start_pattern = String::with_capacity(tag.len() + 2);
    start_pattern.push('<');
    start_pattern.push_str(tag);
    start_pattern.push('>');

    let start_idx = xml.find(&start_pattern)?;
    let content_start = start_idx + start_pattern.len();

    let mut end_pattern = String::with_capacity(tag.len() + 3);
    end_pattern.push_str("</");
    end_pattern.push_str(tag);
    end_pattern.push('>');

    let content_end = xml[content_start..].find(&end_pattern)? + content_start;

    Some(xml[content_start..content_end].trim().to_string())
}

/// Compute SHA256 hash and return hex string
#[inline]
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Compute SHA1 hash and return hex string
#[inline]
pub fn sha1_hex(data: &[u8]) -> String {
    hex::encode(Sha1::digest(data))
}

/// Validate crate name (lowercase alphanumeric, hyphens, underscores)
#[inline]
pub fn is_valid_crate_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Optimized crate name validation using byte iteration
#[inline]
pub fn is_valid_crate_name_optimized(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Normalize PyPI package name (PEP 503)
#[inline]
pub fn normalize_pypi_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c == '-' || c == '_' || c == '.' { '-' } else { c })
        .collect()
}

/// Optimized PyPI name normalization
#[inline]
pub fn normalize_pypi_name_optimized(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    for c in name.chars() {
        let normalized = match c {
            'A'..='Z' => (c as u8 + 32) as char,
            '-' | '_' | '.' => '-',
            _ => c,
        };
        result.push(normalized);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cargo_index_path() {
        assert_eq!(cargo_index_path("a"), "1/a");
        assert_eq!(cargo_index_path("ab"), "2/ab");
        assert_eq!(cargo_index_path("abc"), "3/a/abc");
        assert_eq!(cargo_index_path("abcd"), "ab/cd/abcd");
        assert_eq!(cargo_index_path("serde"), "se/rd/serde");
        assert_eq!(cargo_index_path("SERDE"), "se/rd/serde");
    }

    #[test]
    fn test_cargo_index_path_optimized() {
        assert_eq!(cargo_index_path_optimized("a"), "1/a");
        assert_eq!(cargo_index_path_optimized("ab"), "2/ab");
        assert_eq!(cargo_index_path_optimized("abc"), "3/a/abc");
        assert_eq!(cargo_index_path_optimized("abcd"), "ab/cd/abcd");
        assert_eq!(cargo_index_path_optimized("serde"), "se/rd/serde");
        assert_eq!(cargo_index_path_optimized("SERDE"), "se/rd/serde");
    }

    #[test]
    fn test_version_compare() {
        use std::cmp::Ordering;
        assert_eq!(version_compare("1.0.0", "1.0.0"), Ordering::Equal);
        assert_eq!(version_compare("1.0.0", "2.0.0"), Ordering::Less);
        assert_eq!(version_compare("2.0.0", "1.0.0"), Ordering::Greater);
        assert_eq!(version_compare("1.0.0", "1.0.1"), Ordering::Less);
        assert_eq!(version_compare("1.10.0", "1.2.0"), Ordering::Greater);
    }

    #[test]
    fn test_extract_xml_value() {
        let xml = r#"<package><id>MyPackage</id><version>1.0.0</version></package>"#;
        assert_eq!(extract_xml_value(xml, "id"), Some("MyPackage".to_string()));
        assert_eq!(extract_xml_value(xml, "version"), Some("1.0.0".to_string()));
        assert_eq!(extract_xml_value(xml, "missing"), None);
    }

    #[test]
    fn test_is_valid_crate_name() {
        assert!(is_valid_crate_name("serde"));
        assert!(is_valid_crate_name("my-crate"));
        assert!(is_valid_crate_name("my_crate"));
        assert!(is_valid_crate_name("crate123"));
        assert!(!is_valid_crate_name(""));
        assert!(!is_valid_crate_name("my crate"));
        assert!(!is_valid_crate_name("my.crate"));
    }

    #[test]
    fn test_normalize_pypi_name() {
        assert_eq!(normalize_pypi_name("MyPackage"), "mypackage");
        assert_eq!(normalize_pypi_name("my-package"), "my-package");
        assert_eq!(normalize_pypi_name("my_package"), "my-package");
        assert_eq!(normalize_pypi_name("my.package"), "my-package");
    }
}

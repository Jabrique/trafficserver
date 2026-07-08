#pragma once

#include <string>
#include <vector>

/// Maximum per-field size accepted by the parser (defense against oversized headers).
static const int MAX_LINK_FIELD_LEN = 8192;

std::vector<std::string> split_link_header_value(const std::string &header_value, int max_links);

/// Deduplicate a list of validated link segments by URL key (strongest-wins).
///
/// Two segments are considered duplicates if they share the same <URL> prefix
/// (up to and including the closing '>'), with host compared case-insensitively
/// (RFC 4343) and path compared case-sensitively (RFC 3986 section 6.2.2.1).
/// When a preload/modulepreload and a preconnect share the same URL, the stronger
/// type (preload) replaces the weaker (preconnect).
///
/// Extracted from origin-forward dedup logic in early_hints.cc so it can be
/// unit-tested independently of the ATS plugin API.
///
/// @param segments   Validated link segments (output of split_link_header_value
///                   filtered through is_valid_link_value).
/// @param max_links  Hard cap on total entries in the output vector.
/// @return           Deduplicated segment list, capped at max_links entries.
std::vector<std::string> dedup_link_segments(std::vector<std::string> segments, int max_links);

/// Lowercase only the scheme and host portion of a URL key string for
/// case-insensitive host comparison.
///
/// Per RFC 3986 section 6.2.2.1, scheme and host are case-insensitive.
/// Per RFC 4343, DNS names are case-insensitive.
/// Path, query, and fragment are case-sensitive and are left unchanged.
///
/// Input format: the <URL> bracket-enclosed portion of a Link segment,
/// for example "<https://CDN.Example.COM/Path/File.js>".
/// - Absolute URL "scheme://host/...": host lowercased, path preserved.
/// - Protocol-relative "//host/...": host lowercased, path preserved.
/// - Relative "/path/...": no lowercasing (no host present).
///
/// @param url_key  The <URL> string extracted from a Link segment.
/// @return         Same string with only scheme and host lowercased.
std::string lowercase_url_host(const std::string &url_key);

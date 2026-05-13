#pragma once

#include <string>
#include <vector>

/// Maximum per-field size accepted by the parser (defense against oversized headers).
static const int MAX_LINK_FIELD_LEN = 8192;

std::vector<std::string> split_link_header_value(const std::string &header_value, int max_links);

/// Deduplicate a list of validated link segments by <URL>+rel-type pair.
///
/// Two segments are considered duplicates if they share the same <URL> prefix
/// (up to and including the closing '>') AND the same rel type (preconnect vs
/// non-preconnect).  Only the first occurrence is kept.
///
/// Extracted from origin-forward dedup logic in early_hints.cc so it can be
/// unit-tested independently of the ATS plugin API.
///
/// @param segments   Validated link segments (output of split_link_header_value
///                   filtered through is_valid_link_value).
/// @param max_links  Hard cap on total entries in the output vector.
/// @return           Deduplicated segment list, capped at max_links entries.
std::vector<std::string> dedup_link_segments(std::vector<std::string> segments, int max_links);

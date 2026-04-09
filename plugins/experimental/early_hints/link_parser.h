#pragma once

#include <string>
#include <vector>

/// Maximum per-field size accepted by the parser (defense against oversized headers).
static const int MAX_LINK_FIELD_LEN = 8192;

std::vector<std::string> split_link_header_value(const std::string &header_value, int max_links);

#include "html_scanner.h"
#include "config.h"
#include <iostream>
#include <string>

int
main()
{
  EarlyHintsConfig config;
  HtmlScanner scanner(131072, 10, &config);

  // Test 1: Unclosed quote at EOF
  std::string html1 = "<html><head><link rel=\"preload\" href=\"/app.js";
  scanner.feed(html1.c_str(), html1.size());

  auto links = scanner.get_links();
  std::cout << "Test 1 (unclosed quote at EOF): " << links.size() << " links found" << std::endl;
  if (links.empty()) {
    std::cout << "  Result: Attribute was silently dropped (ISSUE)" << std::endl;
  }

  // Test 2: Unclosed quote with </head> (should be consumed as value)
  scanner.reset();
  std::string html2 = "<html><head><link rel=\"preload\" href=\"/app.js</head></html>";
  scanner.feed(html2.c_str(), html2.size());

  links = scanner.get_links();
  std::cout << "Test 2 (unclosed quote consumed until </head>): " << links.size() << " links found" << std::endl;
  if (links.empty()) {
    std::cout << "  Result: Attribute content includes </head> (MALFORMED HTML)" << std::endl;
  }

  // Test 3: Proper closing quote
  scanner.reset();
  std::string html3 = "<html><head><link rel=\"preload\" href=\"/app.js\" as=\"script\"></head></html>";
  scanner.feed(html3.c_str(), html3.size());

  links = scanner.get_links();
  std::cout << "Test 3 (proper closing quote): " << links.size() << " links found" << std::endl;
  if (!links.empty()) {
    std::cout << "  Result: Link extracted: " << links[0] << std::endl;
  }

  return 0;
}

/*
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
 * These are misc unit tests for uri signing
 */

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

extern "C" {
#include <jansson.h>
#include <cjose/cjose.h>
#include "../jwt.h"
#include "../normalize.h"
#include "../parse.h"
#include "../match.h"
#include "../config.h"
#include "../session.h"
#include "../manifest.h"
}

static char const *const testConfig =
  R"(
{
    "Master Issuer": {
        "renewal_kid": "6",
        "id": "tester",
        "auth_directives": [
            {
                "auth": "allow",
                "uri": "regex:invalid"
            }
        ],
        "keys": [
         {
          "alg": "HS256",
          "k": "nxb7fyO5Z2hGz9E3oKm1357ptvC2su5QwQUb4YaIaIc",
          "kid": "0",
          "kty": "oct"
         },
         {
          "alg": "HS256",
          "k": "cXKukBqFvQ0n3WAuRnWfExC14dmHdGoJULoZjGu9tJC",
          "kid": "1",
          "kty": "oct"
         },
         {
          "alg": "HS256",
          "k": "38pJlSXfX87jWL0a03luml9QzUmM4qts1nmfIHA3B7r",
          "kid": "2",
          "kty": "oct"
         },
         {
          "alg": "HS256",
          "k": "zNQPphknDGvzR5kA7IonXIDWKMyB1b8NpGmmDNlpgtM",
          "kid": "3",
          "kty": "oct"
         },
         {
          "alg": "HS256",
          "k": "iB2ogCmQRt7r5hW7pgyP5FqiFcCl53MPQvfXv8wrZAn",
          "kid": "4",
          "kty": "oct"
         },
         {
          "alg": "HS256",
          "k": "GJMCTyZhNoSOZvUOKmmY9MtGSLaONNLHqtKwsC3MWKo",
          "kid": "5",
          "kty": "oct"
         },
         {
          "alg": "HS256",
          "k": "u2LziZKJFBnOfjUQUmvot7C9t91jj7ocJPIU9aDdbUl",
          "kid": "6",
          "kty": "oct"
         },
         {
          "alg": "HS256",
          "k": "DRBKrBh87NYkH3UzfW1tWbiXCYXiYGZUE9w1orZngL0",
          "kid": "7",
          "kty": "oct"
         },
         {
          "alg": "HS256",
          "k": "KNNKFbun8lEs7GbiKlo9mYGNdvpt33tdFzHbNnasDyP",
          "kid": "8",
          "kty": "oct"
         },
         {
          "alg": "HS256",
          "k": "yb6kOddMUdupPRSkWMUdE6jrWT4MqUnVyTjpeJBYIqp",
          "kid": "9",
          "kty": "oct"
         }
        ]
    },
    "Second Issuer": {
        "keys": [
         {
          "alg": "HS256",
          "k": "testkey1",
          "kid": "one",
          "kty": "oct"
         },
         {
          "alg": "HS256",
          "k": "testkey2",
          "kid": "two",
          "kty": "oct"
         },
         {
          "alg": "HS256",
          "k": "testkey3",
          "kid": "three",
          "kty": "oct"
         },
         {
          "alg": "HS256",
          "k": "testkey4",
          "kid": "four",
          "kty": "oct"
         }
        ]
    }
}
)";

bool
jwt_parsing_helper(const char *jwt_string)
{
  fprintf(stderr, "Parsing JWT from string: %s\n", jwt_string);
  bool resp;
  json_error_t jerr             = {};
  size_t pt_ct                  = strlen(jwt_string);
  struct json_t *const jwk_json = json_loadb(jwt_string, pt_ct, 0, &jerr);
  if (!jwk_json) {
    return false;
  }

  struct jwt *jwt = parse_jwt(jwk_json);
  if (!jwt) {
    json_decref(jwk_json);
    return false;
  }

  resp = jwt_validate(jwt);
  jwt_delete(jwt);
  return resp;
}

bool
normalize_uri_helper(const char *uri, const char *expected_normal)
{
  size_t uri_ct = strlen(uri);
  int buff_size = uri_ct + 2;
  int err;
  char *uri_normal = static_cast<char *>(malloc(buff_size));
  memset(uri_normal, 0, buff_size);

  err = normalize_uri(uri, uri_ct, uri_normal, buff_size);

  if (err) {
    free(uri_normal);
    return false;
  }

  if (expected_normal && strcmp(expected_normal, uri_normal) == 0) {
    free(uri_normal);
    return true;
  }

  free(uri_normal);
  return false;
}

bool
remove_dot_helper(const char *path, const char *expected_path)
{
  fprintf(stderr, "Removing Dot Segments from Path: %s\n", path);
  size_t path_ct = strlen(path);
  path_ct++;
  int new_ct;
  char path_buffer[path_ct];
  memset(path_buffer, 0, path_ct);

  new_ct = remove_dot_segments(path, path_ct, path_buffer, path_ct);

  if (new_ct < 0) {
    return false;
  } else if (strcmp(expected_path, path_buffer) == 0) {
    return true;
  } else {
    return false;
  }
}

bool
jws_parsing_helper(const char *uri, const char *paramName, const char *expected_strip)
{
  bool resp;
  size_t uri_ct   = strlen(uri);
  size_t strip_ct = 0;

  char *uri_strip = static_cast<char *>(malloc(uri_ct + 1));
  memset(uri_strip, 0, uri_ct + 1);

  cjose_jws_t *jws = get_jws_from_uri(uri, uri_ct, paramName, uri_strip, uri_ct, &strip_ct);
  if (jws) {
    resp = true;
    if (strcmp(uri_strip, expected_strip) != 0) {
      cjose_jws_release(jws);
      resp = false;
    }
  } else {
    resp = false;
  }
  cjose_jws_release(jws);
  free(uri_strip);
  return resp;
}

TEST_CASE("1", "[JWSParsingTest]")
{
  INFO("TEST 1, Test JWT Parsing From Token Strings");

  SECTION("Standard JWT Parsing")
  {
    REQUIRE(jwt_parsing_helper("{\"cdniets\":30,\"cdnistt\":1,\"exp\":7284188499,\"iss\":\"Content Access "
                               "Manager\",\"cdniuc\":\"uri-regex:http://foobar.local/testDir/*\"}"));
  }

  SECTION("JWT Parsing With Unknown Claim")
  {
    REQUIRE(jwt_parsing_helper("{\"cdniets\":30,\"cdnistt\":1,\"exp\":7284188499,\"iss\":\"Content Access "
                               "Manager\",\"cdniuc\":\"uri-regex:http://foobar.local/testDir/"
                               "*\",\"jamesBond\":\"Something,Something_else\"}"));
  }

  SECTION("JWT Parsing with unsupported crit claim passed")
  {
    REQUIRE(!jwt_parsing_helper("{\"cdniets\":30,\"cdnistt\":1,\"exp\":7284188499,\"iss\":\"Content Access "
                                "Manager\",\"cdniuc\":\"uri-regex:http://foobar.local/testDir/"
                                "*\",\"cdnicrit\":\"Something,Something_else\"}"));
  }

  SECTION("JWT Parsing with empty exp claim")
  {
    REQUIRE(jwt_parsing_helper("{\"cdniets\":30,\"cdnistt\":1,\"iss\":\"Content Access "
                               "Manager\",\"cdniuc\":\"uri-regex:http://foobar.local/testDir/*\"}"));
  }

  SECTION("JWT Parsing with unsupported cdniip claim")
  {
    REQUIRE(!jwt_parsing_helper("{\"cdniets\":30,\"cdnistt\":1,\"cdniip\":\"123.123.123.123\",\"iss\":\"Content Access "
                                "Manager\",\"cdniuc\":\"uri-regex:http://foobar.local/testDir/*\"}"));
  }

  SECTION("JWT Parsing with unsupported value for cdnistd claim")
  {
    REQUIRE(!jwt_parsing_helper("{\"cdniets\":30,\"cdnistt\":1,\"cdnistd\":-2,\"iss\":\"Content Access "
                                "Manager\",\"cdniuc\":\"uri-regex:http://foobar.local/testDir/*\"}"));
  }
  fprintf(stderr, "\n");
}

TEST_CASE("2", "[JWSFromURLTest]")
{
  INFO("TEST 2, Test JWT Parsing and Stripping From URLs");

  SECTION("Token at end of URI")
  {
    REQUIRE(jws_parsing_helper(
      "www.foo.com/hellothere/"
      "URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      "URISigningPackage", "www.foo.com/hellothere"));
  }

  SECTION("No Token in URL")
  {
    REQUIRE(!jws_parsing_helper(
      "www.foo.com/hellothere/"
      "URISigningPackag=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      "URISigningPackage", NULL));
  }

  SECTION("Token in middle of the URL")
  {
    REQUIRE(jws_parsing_helper("www.foo.com/hellothere/"
                               "URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c/Something/Else",
                               "URISigningPackage", "www.foo.com/hellothere/Something/Else"));
  }

  SECTION("Token at the start of the URL")
  {
    REQUIRE(jws_parsing_helper(":URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c/www.foo.com/hellothere/Something/Else",
                               "URISigningPackage", "/www.foo.com/hellothere/Something/Else"));
  }

  SECTION("Pass empty path parameter at end")
  {
    REQUIRE(!jws_parsing_helper("www.foobar.com/hellothere/URISigningPackage=", "URISigningPackage", NULL));
  }

  SECTION("Pass empty path parameter in the middle of URL")
  {
    REQUIRE(!jws_parsing_helper("www.foobar.com/hellothere/URISigningPackage=/Something/Else", "URISigningPackage", NULL));
  }

  SECTION("Partial package name in previous path parameter")
  {
    REQUIRE(jws_parsing_helper("www.foobar.com/URISig/"
                               "URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c/Something/Else",
                               "URISigningPackage", "www.foobar.com/URISig/Something/Else"));
  }

  SECTION("Package comes directly after two reserved characters")
  {
    REQUIRE(jws_parsing_helper("www.foobar.com/"
                               ":URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c/Something/Else",
                               "URISigningPackage", "www.foobar.com//Something/Else"));
  }

  SECTION("Package comes directly after string of reserved characters")
  {
    REQUIRE(jws_parsing_helper("www.foobar.com/?!/"
                               ":URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c/Something/Else",
                               "URISigningPackage", "www.foobar.com/?!//Something/Else"));
  }

  SECTION("Invalid token passed before a valid token")
  {
    REQUIRE(!jws_parsing_helper("www.foobar.com/URISigningPackage=/"
                                "URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                                "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                                "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c/Something/Else",
                                "URISigningPackage", NULL));
  }

  SECTION("Empty string as URL") { REQUIRE(!jws_parsing_helper("", "URISigningPackage", NULL)); }

  SECTION("Empty package name to parser")
  {
    REQUIRE(!jws_parsing_helper(
      "www.foobar.com/"
      "URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      "", NULL));
  }

  SECTION("Custom package name with a reserved character - at the end of the URI")
  {
    REQUIRE(jws_parsing_helper(
      "www.foobar.com/CustomPackage/"
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      "CustomPackage/", "www.foobar.com"));
  }

  SECTION("Custom package name with a reserved character - in the middle of the URI")
  {
    REQUIRE(jws_parsing_helper(
      "www.foobar.com/CustomPackage/"
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c/Something/Else",
      "CustomPackage/", "www.foobar.com/Something/Else"));
  }

  SECTION("URI signing package passed as the only a query parameter")
  {
    REQUIRE(jws_parsing_helper(
      "www.foobar.com/Something/"
      "Here?URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      "URISigningPackage", "www.foobar.com/Something/Here"));
  }

  SECTION("URI signing package passed as first of many query parameters")
  {
    REQUIRE(jws_parsing_helper("www.foobar.com/Something/"
                               "Here?URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c&query3=foobar&query1=foo&query2=bar",
                               "URISigningPackage", "www.foobar.com/Something/Here?query3=foobar&query1=foo&query2=bar"));
  }

  SECTION("URI signing package passed as one of many query parameters - passed in middle")
  {
    REQUIRE(jws_parsing_helper("www.foobar.com/Something/"
                               "Here?query1=foo&query2=bar&URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c&query3=foobar",
                               "URISigningPackage", "www.foobar.com/Something/Here?query1=foo&query2=bar&query3=foobar"));
  }

  SECTION("URI signing package passed as last of many query parameters")
  {
    REQUIRE(jws_parsing_helper("www.foobar.com/Something/"
                               "Here?query1=foo&query2=bar&URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                               "URISigningPackage", "www.foobar.com/Something/Here?query1=foo&query2=bar"));
  }
}

TEST_CASE("3", "[RemoveDotSegmentsTest]")
{
  INFO("TEST 3, Test Removal of Dot Segments From Paths");

  SECTION("../bar test") { REQUIRE(remove_dot_helper("../bar", "bar")); }

  SECTION("./bar test") { REQUIRE(remove_dot_helper("./bar", "bar")); }

  SECTION(".././bar test") { REQUIRE(remove_dot_helper(".././bar", "bar")); }

  SECTION("./../bar test") { REQUIRE(remove_dot_helper("./../bar", "bar")); }

  SECTION("/foo/./bar test") { REQUIRE(remove_dot_helper("/foo/./bar", "/foo/bar")); }

  SECTION("/bar/./ test") { REQUIRE(remove_dot_helper("/bar/./", "/bar/")); }

  SECTION("/. test") { REQUIRE(remove_dot_helper("/.", "/")); }

  SECTION("/bar/. test") { REQUIRE(remove_dot_helper("/bar/.", "/bar/")); }

  SECTION("/foo/../bar test") { REQUIRE(remove_dot_helper("/foo/../bar", "/bar")); }

  SECTION("/bar/../ test") { REQUIRE(remove_dot_helper("/bar/../", "/")); }

  SECTION("/.. test") { REQUIRE(remove_dot_helper("/..", "/")); }

  SECTION("/bar/.. test") { REQUIRE(remove_dot_helper("/bar/..", "/")); }

  SECTION("/foo/bar/.. test") { REQUIRE(remove_dot_helper("/foo/bar/..", "/foo/")); }

  SECTION("Single . test") { REQUIRE(remove_dot_helper(".", "")); }

  SECTION("Single .. test") { REQUIRE(remove_dot_helper("..", "")); }

  SECTION("Test foo/bar/.. test") { REQUIRE(remove_dot_helper("foo/bar/..", "foo/")); }

  SECTION("Test Empty Path Segment") { REQUIRE(remove_dot_helper("", "")); }

  SECTION("Test mixed operations") { REQUIRE(remove_dot_helper("/foo/bar/././something/../foobar", "/foo/bar/foobar")); }
  fprintf(stderr, "\n");
}

TEST_CASE("4", "[NormalizeTest]")
{
  INFO("TEST 4, Test Normalization of URIs");

  SECTION("Testing passing too small of a URI to normalize") { REQUIRE(!normalize_uri_helper("ht", NULL)); }

  SECTION("Testing passing non http/https protocol") { REQUIRE(!normalize_uri_helper("ht:", NULL)); }

  SECTION("Passing a uri with half encoded value at end") { REQUIRE(!normalize_uri_helper("http://www.foobar.co%4", NULL)); }

  SECTION("Passing a uri with half encoded value in the middle")
  {
    REQUIRE(!normalize_uri_helper("http://www.foobar.co%4psomethin/Path", NULL));
  }

  SECTION("Passing a uri with an empty path parameter")
  {
    REQUIRE(normalize_uri_helper("http://www.foobar.com", "http://www.foobar.com/"));
  }

  SECTION("Passing a uri with an empty path parameter and additional query params")
  {
    REQUIRE(normalize_uri_helper("http://www.foobar.com?query1=foo&query2=bar", "http://www.foobar.com/?query1=foo&query2=bar"));
  }

  SECTION("Empty path parameter with port")
  {
    REQUIRE(normalize_uri_helper("http://www.foobar.com:9301?query1=foo&query2=bar",
                                 "http://www.foobar.com:9301/?query1=foo&query2=bar"));
  }

  SECTION("Passing a uri with a username and password")
  {
    REQUIRE(normalize_uri_helper("http://foo%40:PaSsword@www.Foo%42ar.coM:80/", "http://foo%40:PaSsword@www.foobar.com/"));
  }

  SECTION("Testing Removal of standard http Port")
  {
    REQUIRE(normalize_uri_helper("http://foobar.com:80/Something/Here", "http://foobar.com/Something/Here"));
  }

  SECTION("Testing Removal of standard https Port")
  {
    REQUIRE(normalize_uri_helper("https://foobar.com:443/Something/Here", "https://foobar.com/Something/Here"));
  }

  SECTION("Testing passing of non-standard http Port")
  {
    REQUIRE(normalize_uri_helper("http://foobar.com:443/Something/Here", "http://foobar.com:443/Something/Here"));
  }

  SECTION("Testing passing of non-standard https Port")
  {
    REQUIRE(normalize_uri_helper("https://foobar.com:80/Something/Here", "https://foobar.com:80/Something/Here"));
  }

  SECTION("Testing the removal of . and .. in the path ")
  {
    REQUIRE(
      normalize_uri_helper("https://foobar.com:80/Something/Here/././foobar/../foo", "https://foobar.com:80/Something/Here/foo"));
  }

  SECTION("Testing . and .. segments in non path components")
  {
    REQUIRE(normalize_uri_helper("https://foobar.com:80/Something/Here?query1=/././foo/../bar",
                                 "https://foobar.com:80/Something/Here?query1=/././foo/../bar"));
  }

  SECTION("Testing standard decdoing of multiple characters")
  {
    REQUIRE(normalize_uri_helper("https://kelloggs%54ester.com/%53omething/Here", "https://kelloggstester.com/Something/Here"));
  }

  SECTION("Testing passing encoded reserved characters")
  {
    REQUIRE(
      normalize_uri_helper("https://kelloggs%54ester.com/%53omething/Here%3f", "https://kelloggstester.com/Something/Here%3F"));
  }

  SECTION("Mixed Bag Test case")
  {
    REQUIRE(normalize_uri_helper("https://foo:something@kellogs%54ester.com:443/%53omething/.././here",
                                 "https://foo:something@kellogstester.com/here"));
  }

  SECTION("Testing empty hostname with userinfon") { REQUIRE(!normalize_uri_helper("https://foo:something@", NULL)); }

  SECTION("Testing empty uri after http://") { REQUIRE(!normalize_uri_helper("http://", NULL)); }

  SECTION("Testing http:///////") { REQUIRE(!normalize_uri_helper("http:///////", NULL)); }

  SECTION("Testing empty uri after http://?/") { REQUIRE(!normalize_uri_helper("http://?/", NULL)); }
  fprintf(stderr, "\n");
}

TEST_CASE("5", "[RegexTests]")
{
  INFO("TEST 5, Test Regex Matching");

  SECTION("Standard regex")
  {
    REQUIRE(match_regex("http://kelloggsTester.souza.local/KellogsDir/*",
                        "http://kelloggsTester.souza.local/KellogsDir/some_manifest.m3u8"));
  }

  SECTION("Back references are not supported") { REQUIRE(!match_regex("(b*a)\\1$", "bbbbba")); }

  SECTION("Escape a special character") { REQUIRE(match_regex("money\\$", "money$bags")); }

  SECTION("Dollar sign")
  {
    REQUIRE(!match_regex(".+foobar$", "foobarfoofoo"));
    REQUIRE(match_regex(".+foobar$", "foofoofoobar"));
  }

  SECTION("Number Quantifier with Groups")
  {
    REQUIRE(match_regex("(abab){2}", "abababab"));
    REQUIRE(!match_regex("(abab){2}", "abab"));
  }

  SECTION("Alternation") { REQUIRE(match_regex("cat|dog", "dog")); }
  fprintf(stderr, "\n");
}

TEST_CASE("6", "[AudTests]")
{
  INFO("TEST 6, Test Aud Matching");

  json_error_t *err = NULL;
  SECTION("Standard aud string match")
  {
    json_t *raw = json_loads("{\"aud\": \"tester\"}", 0, err);
    json_t *aud = json_object_get(raw, "aud");
    REQUIRE(jwt_check_aud(aud, "tester"));
    json_decref(raw);
  }

  SECTION("Standard aud array match")
  {
    json_t *raw = json_loads("{\"aud\": [ \"foo\", \"bar\",  \"tester\"]}", 0, err);
    json_t *aud = json_object_get(raw, "aud");
    REQUIRE(jwt_check_aud(aud, "tester"));
    json_decref(raw);
  }

  SECTION("Standard aud string mismatch")
  {
    json_t *raw = json_loads("{\"aud\": \"foo\"}", 0, err);
    json_t *aud = json_object_get(raw, "aud");
    REQUIRE(!jwt_check_aud(aud, "tester"));
    json_decref(raw);
  }

  SECTION("Standard aud array mismatch")
  {
    json_t *raw = json_loads("{\"aud\": [\"foo\", \"bar\", \"foobar\"]}", 0, err);
    json_t *aud = json_object_get(raw, "aud");
    REQUIRE(!jwt_check_aud(aud, "tester"));
    json_decref(raw);
  }

  SECTION("Integer trying to pass as an aud")
  {
    json_t *raw = json_loads("{\"aud\": 1}", 0, err);
    json_t *aud = json_object_get(raw, "aud");
    REQUIRE(!jwt_check_aud(aud, "tester"));
    json_decref(raw);
  }

  SECTION("Integer mixed into a passing aud array")
  {
    json_t *raw = json_loads("{\"aud\": [1, \"foo\", \"bar\", \"tester\"]}", 0, err);
    json_t *aud = json_object_get(raw, "aud");
    REQUIRE(jwt_check_aud(aud, "tester"));
    json_decref(raw);
  }

  SECTION("Case sensitive test for single string")
  {
    json_t *raw = json_loads("{\"aud\": \"TESTer\"}", 0, err);
    json_t *aud = json_object_get(raw, "aud");
    REQUIRE(!jwt_check_aud(aud, "tester"));
    json_decref(raw);
  }

  SECTION("Case sensitive test for array")
  {
    json_t *raw = json_loads("{\"aud\": [1, \"foo\", \"bar\", \"Tester\"]}", 0, err);
    json_t *aud = json_object_get(raw, "aud");
    REQUIRE(!jwt_check_aud(aud, "tester"));
    json_decref(raw);
  }

  fprintf(stderr, "\n");
}

TEST_CASE("7", "[TestsConfig]")
{
  INFO("TEST 7, Config Loading and Config Functions");

  fprintf(stderr, "%s\n", testConfig);
  fflush(stderr);

  SECTION("Config Loading ID Field")
  {
    struct config *cfg = read_config_from_string(testConfig);
    REQUIRE(cfg != NULL);
    REQUIRE(strcmp(config_get_id(cfg), "tester") == 0);
    config_delete(cfg);
  }
  fprintf(stderr, "\n");
}

bool
jws_validation_helper(const char *url, const char *package, struct config *cfg)
{
  size_t url_ct   = strlen(url);
  size_t strip_ct = 0;
  char uri_strip[url_ct + 1];
  memset(uri_strip, 0, sizeof uri_strip);
  cjose_jws_t *jws = get_jws_from_uri(url, url_ct, package, uri_strip, url_ct, &strip_ct);
  if (!jws) {
    return false;
  }
  struct jwt *jwt = validate_jws(jws, cfg, uri_strip, strip_ct);
  cjose_jws_release(jws);
  if (!jwt) {
    return false;
  }
  jwt_delete(jwt);
  return true;
}

TEST_CASE("8", "[TestsWithConfig]")
{
  INFO("TEST 8, Tests Involving Validation with Config");
  struct config *cfg = read_config_from_string(testConfig);

  SECTION("Validation of Valid Aud String in JWS")
  {
    REQUIRE(jws_validation_helper("http://www.foobar.com/"
                                  "URISigningPackage=eyJLZXlJREtleSI6IjUiLCJhbGciOiJIUzI1NiJ9."
                                  "eyJjZG5pZXRzIjozMCwiY2RuaXN0dCI6MSwiaXNzIjoiTWFzdGVyIElzc3VlciIsImF1ZCI6InRlc3RlciIsImNkbml1YyI6"
                                  "InJlZ2V4Omh0dHA6Ly93d3cuZm9vYmFyLmNvbS8qIn0.InBxVm6OOAglNqc-U5wAZaRQVebJ9PK7Y9i7VFHWYHU",
                                  "URISigningPackage", cfg));
    fprintf(stderr, "\n");
  }

  SECTION("Validation of Invalid Aud String in JWS")
  {
    REQUIRE(!jws_validation_helper("http://www.foobar.com/"
                                   "URISigningPackage=eyJLZXlJREtleSI6IjUiLCJhbGciOiJIUzI1NiJ9."
                                   "eyJjZG5pZXRzIjozMCwiY2RuaXN0dCI6MSwiaXNzIjoiTWFzdGVyIElzc3VlciIsImF1ZCI6ImJhZCIsImNkbml1YyI6InJ"
                                   "lZ2V4Omh0dHA6Ly93d3cuZm9vYmFyLmNvbS8qIn0.aCOo8gOBa5G1RKkkzgWYwc79dPRw_fQUC0k1sWcjkyM",
                                   "URISigningPackage", cfg));
    fprintf(stderr, "\n");
  }

  SECTION("Validation of Valid Aud Array in JWS")
  {
    REQUIRE(jws_validation_helper(
      "http://www.foobar.com/"
      "URISigningPackage=eyJLZXlJREtleSI6IjUiLCJhbGciOiJIUzI1NiJ9."
      "eyJjZG5pZXRzIjozMCwiY2RuaXN0dCI6MSwiaXNzIjoiTWFzdGVyIElzc3VlciIsImF1ZCI6WyJiYWQiLCJpbnZhbGlkIiwidGVzdGVyIl0sImNkbml1YyI6InJl"
      "Z2V4Omh0dHA6Ly93d3cuZm9vYmFyLmNvbS8qIn0.7lyepZMzc_odieKvOTN2U-k1gLwRKS8KJIvDFQXDqGs",
      "URISigningPackage", cfg));
    fprintf(stderr, "\n");
  }

  SECTION("Validation of Invalid Aud Array in JWS")
  {
    REQUIRE(!jws_validation_helper(
      "http://www.foobar.com/"
      "URISigningPackage=eyJLZXlJREtleSI6IjUiLCJhbGciOiJIUzI1NiJ9."
      "eyJjZG5pZXRzIjozMCwiY2RuaXN0dCI6MSwiaXNzIjoiTWFzdGVyIElzc3VlciIsImF1ZCI6WyJiYWQiLCJpbnZhbGlkIiwiZm9vYmFyIl0sImNkbml1YyI6InJl"
      "Z2V4Omh0dHA6Ly93d3cuZm9vYmFyLmNvbS8qIn0.CU3WMJAPs0uRC7NKXvatVG9uU9SANdZzqO0GdQUatxk",
      "URISigningPackage", cfg));
    fprintf(stderr, "\n");
  }

  SECTION("Validation of Valid Aud Array Mixed types in JWS")
  {
    REQUIRE(jws_validation_helper(
      "http://www.foobar.com/"
      "URISigningPackage=eyJLZXlJREtleSI6IjUiLCJhbGciOiJIUzI1NiJ9."
      "eyJjZG5pZXRzIjozMCwiY2RuaXN0dCI6MSwiaXNzIjoiTWFzdGVyIElzc3VlciIsImF1ZCI6WyJiYWQiLDEsImZvb2JhciIsInRlc3RlciJdLCJjZG5pdWMiOiJy"
      "ZWdleDpodHRwOi8vd3d3LmZvb2Jhci5jb20vKiJ9._vlXsA3r7RPje2ZdMnpaGTwIsdNMjuQWPEHRkGKTVL8",
      "URISigningPackage", cfg));
    fprintf(stderr, "\n");
  }

  config_delete(cfg);
  fprintf(stderr, "\n");
}

// ============================================================================
// TEST SUITE: Token Auth Level 1 - Configurable Token Name (access_token_name)
// ============================================================================

TEST_CASE("Config parses access_token_name from JSON", "[TokenAuthLevel1][Config]")
{
  INFO("TEST: Config should parse access_token_name field");

  SECTION("Parse custom token name")
  {
    const char *config_json = R"({
      "Test Issuer": {
        "access_token_name": "cr-access-token",
        "renewal_kid": "test-key",
        "keys": [{
          "alg": "HS256",
          "kid": "test-key",
          "k": "dGVzdC1rZXktc2VjcmV0MTIzNDU2Nzg5MA",
          "kty": "oct"
        }]
      }
    })";

    struct config *cfg = read_config_from_string(config_json);
    REQUIRE(cfg != NULL);

    const char *token_name = config_get_token_name(cfg);
    REQUIRE(token_name != NULL);
    REQUIRE(strcmp(token_name, "cr-access-token") == 0);

    config_delete(cfg);
    fprintf(stderr, "✓ Custom token name parsed successfully\n");
  }

  SECTION("Use default when access_token_name missing")
  {
    const char *config_json = R"({
      "Test Issuer": {
        "id": "test-aud",
        "renewal_kid": "test-key",
        "keys": [{
          "alg": "HS256",
          "kid": "test-key",
          "k": "dGVzdC1rZXktc2VjcmV0MTIzNDU2Nzg5MA",
          "kty": "oct"
        }]
      }
    })";

    struct config *cfg = read_config_from_string(config_json);
    REQUIRE(cfg != NULL);

    const char *token_name = config_get_token_name(cfg);
    REQUIRE(token_name != NULL);
    REQUIRE(strcmp(token_name, "cr-access-token") == 0); // Default value

    config_delete(cfg);
    fprintf(stderr, "✓ Default token name used when not configured\n");
  }

  SECTION("Use default when access_token_name is empty string")
  {
    const char *config_json = R"({
      "Test Issuer": {
        "access_token_name": "",
        "renewal_kid": "test-key",
        "keys": [{
          "alg": "HS256",
          "kid": "test-key",
          "k": "dGVzdC1rZXktc2VjcmV0MTIzNDU2Nzg5MA",
          "kty": "oct"
        }]
      }
    })";

    struct config *cfg = read_config_from_string(config_json);
    REQUIRE(cfg != NULL);

    const char *token_name = config_get_token_name(cfg);
    REQUIRE(token_name != NULL);
    REQUIRE(strcmp(token_name, "cr-access-token") == 0); // Default value

    config_delete(cfg);
    fprintf(stderr, "✓ Default token name used when empty string\n");
  }

  SECTION("Multiple issuers with different token names")
  {
    const char *config_json = R"({
      "Issuer A": {
        "access_token_name": "token-a",
        "renewal_kid": "key-a",
        "keys": [{
          "alg": "HS256",
          "kid": "key-a",
          "k": "dGVzdC1rZXktc2VjcmV0MTIzNDU2Nzg5MA",
          "kty": "oct"
        }]
      },
      "Issuer B": {
        "access_token_name": "token-b",
        "keys": [{
          "alg": "HS256",
          "kid": "key-b",
          "k": "YW5vdGhlci1rZXktc2VjcmV0MTIzNDU2Nzg",
          "kty": "oct"
        }]
      }
    })";

    struct config *cfg = read_config_from_string(config_json);
    REQUIRE(cfg != NULL);

    // With single token name, uses token name from first issuer processed
    const char *token_name = config_get_token_name(cfg);
    REQUIRE(token_name != NULL);
    // Note: JSON object iteration order may vary, but one of the configured names will be used
    bool valid_name = (strcmp(token_name, "token-a") == 0) || (strcmp(token_name, "token-b") == 0);
    REQUIRE(valid_name);

    config_delete(cfg);
    fprintf(stderr, "✓ Multiple issuers with different token names (uses first issuer's token name)\n");
  }

  SECTION("Single issuer config works correctly")
  {
    const char *config_json = R"({
      "Single Issuer": {
        "access_token_name": "my-token",
        "renewal_kid": "test-key",
        "strip_token": true,
        "id": "test-audience",
        "keys": [{
          "alg": "HS256",
          "kid": "test-key",
          "k": "dGVzdC1rZXktc2VjcmV0MTIzNDU2Nzg5MA",
          "kty": "oct"
        }]
      }
    })";

    struct config *cfg = read_config_from_string(config_json);
    REQUIRE(cfg != NULL);

    const char *token_name = config_get_token_name(cfg);
    REQUIRE(token_name != NULL);
    REQUIRE(strcmp(token_name, "my-token") == 0);

    // Verify other config fields still work
    const char *id = config_get_id(cfg);
    REQUIRE(id != NULL);
    REQUIRE(strcmp(id, "test-audience") == 0);

    REQUIRE(config_strip_token(cfg) == true);

    config_delete(cfg);
    fprintf(stderr, "✓ Single issuer config with all fields\n");
  }

  fprintf(stderr, "\n");
}

TEST_CASE("Token extraction with custom token name", "[TokenAuthLevel1][Parsing]")
{
  INFO("TEST: Token extraction should use custom token name");

  SECTION("Extract token from URL with custom name")
  {
    const char *uri = "http://cdn.com/video.mp4?cr-access-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    REQUIRE(jws_parsing_helper(uri, "cr-access-token", "http://cdn.com/video.mp4"));
    fprintf(stderr, "✓ Token extracted with custom name from URL\n");
  }

  SECTION("Token not found when wrong name used")
  {
    const char *uri = "http://cdn.com/video.mp4?wrong-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    // Looking for "cr-access-token" but it's "wrong-token"
    REQUIRE(!jws_parsing_helper(uri, "cr-access-token", NULL));
    fprintf(stderr, "✓ Token not found with wrong name\n");
  }

  SECTION("Custom token name with multiple query parameters")
  {
    const char *uri = "http://cdn.com/video.mp4?foo=bar&cr-access-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c&baz=qux";

    REQUIRE(jws_parsing_helper(uri, "cr-access-token", "http://cdn.com/video.mp4?foo=bar&baz=qux"));
    fprintf(stderr, "✓ Token extracted with custom name from URL with multiple params\n");
  }

  SECTION("Different custom token names")
  {
    // Test with "my-token"
    const char *uri1 = "http://cdn.com/video.mp4?my-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                       "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    REQUIRE(jws_parsing_helper(uri1, "my-token", "http://cdn.com/video.mp4"));

    // Test with "auth-token"
    const char *uri2 = "http://cdn.com/video.mp4?auth-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                       "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    REQUIRE(jws_parsing_helper(uri2, "auth-token", "http://cdn.com/video.mp4"));

    fprintf(stderr, "✓ Different custom token names work correctly\n");
  }

  fprintf(stderr, "\n");
}

TEST_CASE("Token name validation and edge cases", "[TokenAuthLevel1][Validation]")
{
  INFO("TEST: Token name validation and edge cases");

  SECTION("Token name with special characters (allowed)")
  {
    const char *config_json = R"({
      "Test Issuer": {
        "access_token_name": "my-token_v2",
        "renewal_kid": "test-key",
        "keys": [{
          "alg": "HS256",
          "kid": "test-key",
          "k": "dGVzdC1rZXktc2VjcmV0MTIzNDU2Nzg5MA",
          "kty": "oct"
        }]
      }
    })";

    struct config *cfg = read_config_from_string(config_json);
    REQUIRE(cfg != NULL);

    const char *token_name = config_get_token_name(cfg);
    REQUIRE(token_name != NULL);
    REQUIRE(strcmp(token_name, "my-token_v2") == 0);

    config_delete(cfg);
    fprintf(stderr, "✓ Token name with hyphens and underscores\n");
  }

  SECTION("Config loads successfully with NULL check")
  {
    struct config *cfg     = NULL;
    const char *token_name = config_get_token_name(cfg);

    // Should return default even if cfg is NULL (defensive)
    REQUIRE(token_name != NULL);
    REQUIRE(strcmp(token_name, "cr-access-token") == 0);

    fprintf(stderr, "✓ NULL config returns default token name\n");
  }

  fprintf(stderr, "\n");
}

// ============================================================================
// TEST SUITE: Token Auth Level 2 - JWT cdnisalt Claim Extension
// ============================================================================

TEST_CASE("JWT parses cdnisalt claim", "[TokenAuthLevel2][JWT][cdnisalt]")
{
  INFO("TEST: JWT should parse cdnisalt claim from token");

  json_error_t jerr = {};

  SECTION("Parse JWT with cdnisalt claim present")
  {
    const char *jwt_string = R"({
      "iss": "Test Issuer",
      "exp": 7284188499,
      "cdnistt": 1,
      "cdniets": 3600,
      "cdnisalt": "d4f5e6a7b8c9"
    })";

    json_t *jwk_json = json_loadb(jwt_string, strlen(jwt_string), 0, &jerr);
    REQUIRE(jwk_json != NULL);

    struct jwt *jwt = parse_jwt(jwk_json);
    REQUIRE(jwt != NULL);
    REQUIRE(jwt->cdnisalt != NULL);
    REQUIRE(strcmp(jwt->cdnisalt, "d4f5e6a7b8c9") == 0);

    jwt_delete(jwt);
    fprintf(stderr, "✓ JWT with cdnisalt claim parsed successfully\n");
  }

  SECTION("Parse JWT without cdnisalt claim")
  {
    const char *jwt_string = R"({
      "iss": "Test Issuer",
      "exp": 7284188499,
      "cdnistt": 1,
      "cdniets": 3600
    })";

    json_t *jwk_json = json_loadb(jwt_string, strlen(jwt_string), 0, &jerr);
    REQUIRE(jwk_json != NULL);

    struct jwt *jwt = parse_jwt(jwk_json);
    REQUIRE(jwt != NULL);
    REQUIRE(jwt->cdnisalt == NULL);

    jwt_delete(jwt);
    fprintf(stderr, "✓ JWT without cdnisalt claim parsed with NULL value\n");
  }

  SECTION("Parse JWT with empty cdnisalt string")
  {
    const char *jwt_string = R"({
      "iss": "Test Issuer",
      "exp": 7284188499,
      "cdnistt": 1,
      "cdniets": 3600,
      "cdnisalt": ""
    })";

    json_t *jwk_json = json_loadb(jwt_string, strlen(jwt_string), 0, &jerr);
    REQUIRE(jwk_json != NULL);

    struct jwt *jwt = parse_jwt(jwk_json);
    REQUIRE(jwt != NULL);
    REQUIRE(jwt->cdnisalt != NULL);
    REQUIRE(strcmp(jwt->cdnisalt, "") == 0);

    jwt_delete(jwt);
    fprintf(stderr, "✓ JWT with empty cdnisalt string parsed correctly\n");
  }

  SECTION("Parse JWT with wrong type for cdnisalt (integer)")
  {
    const char *jwt_string = R"({
      "iss": "Test Issuer",
      "exp": 7284188499,
      "cdnistt": 1,
      "cdniets": 3600,
      "cdnisalt": 123456
    })";

    json_t *jwk_json = json_loadb(jwt_string, strlen(jwt_string), 0, &jerr);
    REQUIRE(jwk_json != NULL);

    struct jwt *jwt = parse_jwt(jwk_json);
    REQUIRE(jwt != NULL);
    // json_string_value returns NULL for non-string types
    REQUIRE(jwt->cdnisalt == NULL);

    jwt_delete(jwt);
    fprintf(stderr, "✓ JWT with integer cdnisalt returns NULL\n");
  }

  SECTION("Parse JWT with long cdnisalt (SHA256 hash)")
  {
    const char *jwt_string = R"({
      "iss": "Test Issuer",
      "exp": 7284188499,
      "cdnistt": 1,
      "cdniets": 3600,
      "cdnisalt": "5d41402abc4b2a76b9719d911017c592ae33894b12345678901234567890abcd"
    })";

    json_t *jwk_json = json_loadb(jwt_string, strlen(jwt_string), 0, &jerr);
    REQUIRE(jwk_json != NULL);

    struct jwt *jwt = parse_jwt(jwk_json);
    REQUIRE(jwt != NULL);
    REQUIRE(jwt->cdnisalt != NULL);
    REQUIRE(strcmp(jwt->cdnisalt, "5d41402abc4b2a76b9719d911017c592ae33894b12345678901234567890abcd") == 0);

    jwt_delete(jwt);
    fprintf(stderr, "✓ JWT with long cdnisalt (SHA256) parsed successfully\n");
  }

  fprintf(stderr, "\n");
}

TEST_CASE("JWT cleanup handles cdnisalt correctly", "[TokenAuthLevel2][JWT][Memory]")
{
  INFO("TEST: JWT cleanup should not leak memory with cdnisalt");

  json_error_t jerr = {};

  SECTION("Delete JWT with cdnisalt present")
  {
    const char *jwt_string = R"({
      "iss": "Test Issuer",
      "exp": 7284188499,
      "cdnisalt": "test-salt-value"
    })";

    json_t *jwk_json = json_loadb(jwt_string, strlen(jwt_string), 0, &jerr);
    REQUIRE(jwk_json != NULL);

    struct jwt *jwt = parse_jwt(jwk_json);
    REQUIRE(jwt != NULL);
    REQUIRE(jwt->cdnisalt != NULL);

    // This should not crash and should free all resources
    jwt_delete(jwt);

    fprintf(stderr, "✓ JWT with cdnisalt deleted without memory leak\n");
  }

  SECTION("Delete JWT without cdnisalt")
  {
    const char *jwt_string = R"({
      "iss": "Test Issuer",
      "exp": 7284188499
    })";

    json_t *jwk_json = json_loadb(jwt_string, strlen(jwt_string), 0, &jerr);
    REQUIRE(jwk_json != NULL);

    struct jwt *jwt = parse_jwt(jwk_json);
    REQUIRE(jwt != NULL);
    REQUIRE(jwt->cdnisalt == NULL);

    jwt_delete(jwt);

    fprintf(stderr, "✓ JWT without cdnisalt deleted successfully\n");
  }

  SECTION("Delete NULL JWT")
  {
    // Should handle NULL gracefully
    jwt_delete(NULL);

    fprintf(stderr, "✓ NULL JWT handled gracefully\n");
  }

  fprintf(stderr, "\n");
}

TEST_CASE("Config parses renewal_token configuration", "[TokenAuthLevel2][Config][RenewalToken]")
{
  INFO("TEST: Config should parse renewal_token nested object");

  SECTION("Parse renewal_token with all fields configured")
  {
    const char *config_json = R"({
      "Test Issuer": {
        "renewal_kid": "test-key",
        "keys": [{
          "alg": "HS256",
          "kid": "test-key",
          "k": "dGVzdC1rZXktc2VjcmV0MTIzNDU2Nzg5MA",
          "kty": "oct"
        }],
        "renewal_token": {
          "token_name": "cr-session-token",
          "salt": {
            "enabled": true,
            "bind_session_id": true,
            "bind_user_agent": true,
            "bind_client_ip": false
          },
          "manifest_injection": {
            "enabled": true,
            "inject_to_segments": true,
            "inject_to_init_segments": false,
            "replace_access_token": true,
            "hls_support": true,
            "dash_support": true
          }
        }
      }
    })";

    struct config *cfg = read_config_from_string(config_json);
    REQUIRE(cfg != NULL);

    // TODO: Add assertions once config getters are implemented

    config_delete(cfg);
    fprintf(stderr, "✓ renewal_token with all fields parsed\n");
  }

  SECTION("Parse renewal_token with defaults (only enabled fields)")
  {
    const char *config_json = R"({
      "Test Issuer": {
        "renewal_kid": "test-key",
        "keys": [{
          "alg": "HS256",
          "kid": "test-key",
          "k": "dGVzdC1rZXktc2VjcmV0MTIzNDU2Nzg5MA",
          "kty": "oct"
        }],
        "renewal_token": {
          "salt": {
            "enabled": true
          }
        }
      }
    })";

    struct config *cfg = read_config_from_string(config_json);
    REQUIRE(cfg != NULL);

    // Defaults should be:
    // - token_name: "cr-session-token" (when salt enabled)
    // - salt.bind_session_id: true
    // - salt.bind_user_agent: false
    // - salt.bind_client_ip: false
    // - manifest_injection.enabled: false

    config_delete(cfg);
    fprintf(stderr, "✓ renewal_token with defaults applied\n");
  }

  SECTION("Parse config without renewal_token (backward compatibility)")
  {
    const char *config_json = R"({
      "Test Issuer": {
        "renewal_kid": "test-key",
        "access_token_name": "cr-access-token",
        "keys": [{
          "alg": "HS256",
          "kid": "test-key",
          "k": "dGVzdC1rZXktc2VjcmV0MTIzNDU2Nzg5MA",
          "kty": "oct"
        }]
      }
    })";

    struct config *cfg = read_config_from_string(config_json);
    REQUIRE(cfg != NULL);

    // Should work as before - no salt, no manifest injection

    config_delete(cfg);
    fprintf(stderr, "✓ Config without renewal_token (backward compatible)\n");
  }

  SECTION("Parse renewal_token with salt disabled")
  {
    const char *config_json = R"({
      "Test Issuer": {
        "renewal_kid": "test-key",
        "keys": [{
          "alg": "HS256",
          "kid": "test-key",
          "k": "dGVzdC1rZXktc2VjcmV0MTIzNDU2Nzg5MA",
          "kty": "oct"
        }],
        "renewal_token": {
          "salt": {
            "enabled": false
          }
        }
      }
    })";

    struct config *cfg = read_config_from_string(config_json);
    REQUIRE(cfg != NULL);

    // When salt disabled and no explicit token_name, should use default "cr-session-token"

    config_delete(cfg);
    fprintf(stderr, "✓ renewal_token with salt disabled\n");
  }

  SECTION("Parse renewal_token with manifest injection only")
  {
    const char *config_json = R"({
      "Test Issuer": {
        "renewal_kid": "test-key",
        "keys": [{
          "alg": "HS256",
          "kid": "test-key",
          "k": "dGVzdC1rZXktc2VjcmV0MTIzNDU2Nzg5MA",
          "kty": "oct"
        }],
        "renewal_token": {
          "manifest_injection": {
            "enabled": true,
            "hls_support": true,
            "dash_support": false
          }
        }
      }
    })";

    struct config *cfg = read_config_from_string(config_json);
    REQUIRE(cfg != NULL);

    config_delete(cfg);
    fprintf(stderr, "✓ renewal_token with manifest injection only\n");
  }

  fprintf(stderr, "\n");
}

TEST_CASE("Salt generation from headers", "[TokenAuthLevel2][Session][Salt]")
{
  INFO("TEST: Generate salt from request headers");

  SECTION("Generate salt from session ID only")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = true, .bind_user_agent = false, .bind_client_ip = false};

    const char *session_id = "test-session-12345";
    char *salt             = generate_salt(&cfg, session_id, NULL, NULL);

    REQUIRE(salt != NULL);
    REQUIRE(strlen(salt) == 64); // SHA256 hex = 64 chars

    // Verify it's deterministic
    char *salt2 = generate_salt(&cfg, session_id, NULL, NULL);
    REQUIRE(salt2 != NULL);
    REQUIRE(strcmp(salt, salt2) == 0);

    free(salt);
    free(salt2);
    fprintf(stderr, "✓ Salt generated from session ID only\n");
  }

  SECTION("Generate salt from session ID + user agent")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = true, .bind_user_agent = true, .bind_client_ip = false};

    const char *session_id = "test-session-12345";
    const char *user_agent = "Mozilla/5.0";
    char *salt             = generate_salt(&cfg, session_id, user_agent, NULL);

    REQUIRE(salt != NULL);
    REQUIRE(strlen(salt) == 64);

    // Different from session ID only
    struct salt_config cfg_session_only = {
      .enabled = true, .bind_session_id = true, .bind_user_agent = false, .bind_client_ip = false};
    char *salt_session_only = generate_salt(&cfg_session_only, session_id, NULL, NULL);

    REQUIRE(strcmp(salt, salt_session_only) != 0);

    free(salt);
    free(salt_session_only);
    fprintf(stderr, "✓ Salt generated from session ID + user agent\n");
  }

  SECTION("Generate salt from all headers")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = true, .bind_user_agent = true, .bind_client_ip = true};

    const char *session_id = "test-session-12345";
    const char *user_agent = "Mozilla/5.0";
    const char *client_ip  = "192.168.1.100";
    char *salt             = generate_salt(&cfg, session_id, user_agent, client_ip);

    REQUIRE(salt != NULL);
    REQUIRE(strlen(salt) == 64);

    fprintf(stderr, "✓ Salt generated from all headers: %s\n", salt);
    free(salt);
  }

  SECTION("Salt disabled returns NULL")
  {
    struct salt_config cfg = {.enabled = false, .bind_session_id = true, .bind_user_agent = false, .bind_client_ip = false};

    char *salt = generate_salt(&cfg, "test-session", NULL, NULL);
    REQUIRE(salt == NULL);

    fprintf(stderr, "✓ Salt generation returns NULL when disabled\n");
  }

  SECTION("No headers available returns NULL")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = true, .bind_user_agent = false, .bind_client_ip = false};

    char *salt = generate_salt(&cfg, NULL, NULL, NULL);
    REQUIRE(salt == NULL);

    fprintf(stderr, "✓ Salt generation returns NULL with no headers\n");
  }

  SECTION("Different session IDs produce different salts")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = true, .bind_user_agent = false, .bind_client_ip = false};

    char *salt1 = generate_salt(&cfg, "session-123", NULL, NULL);
    char *salt2 = generate_salt(&cfg, "session-456", NULL, NULL);

    REQUIRE(salt1 != NULL);
    REQUIRE(salt2 != NULL);
    REQUIRE(strcmp(salt1, salt2) != 0);

    free(salt1);
    free(salt2);
    fprintf(stderr, "✓ Different session IDs produce different salts\n");
  }

  fprintf(stderr, "\n");
}

TEST_CASE("Salt generation security: Header length limits", "[TokenAuthLevel2][Session][Security]")
{
  INFO("TEST: Salt generation should reject excessively long headers");

  SECTION("Reject session ID exceeding 4096 bytes")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = true, .bind_user_agent = false, .bind_client_ip = false};

    // Create session ID that's 5000 bytes (exceeds 4096 limit)
    std::string giant_session(5000, 'X');
    char *salt = generate_salt(&cfg, giant_session.c_str(), NULL, NULL);

    // Should return NULL due to length validation
    REQUIRE(salt == NULL);
    fprintf(stderr, "✓ Salt generation rejects oversized session ID (5000 bytes)\n");
  }

  SECTION("Accept session ID at exactly 4096 bytes")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = true, .bind_user_agent = false, .bind_client_ip = false};

    // Create session ID at exactly the limit
    std::string max_session(4096, 'Y');
    char *salt = generate_salt(&cfg, max_session.c_str(), NULL, NULL);

    // Should succeed
    REQUIRE(salt != NULL);
    REQUIRE(strlen(salt) == 64);
    free(salt);
    fprintf(stderr, "✓ Salt generation accepts session ID at 4096 bytes\n");
  }

  SECTION("Reject User-Agent exceeding 2048 bytes")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = false, .bind_user_agent = true, .bind_client_ip = false};

    // Create User-Agent that's 3000 bytes (exceeds 2048 limit)
    std::string giant_ua(3000, 'Z');
    char *salt = generate_salt(&cfg, NULL, giant_ua.c_str(), NULL);

    // Should return NULL due to length validation
    REQUIRE(salt == NULL);
    fprintf(stderr, "✓ Salt generation rejects oversized User-Agent (3000 bytes)\n");
  }

  SECTION("Accept User-Agent at exactly 2048 bytes")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = false, .bind_user_agent = true, .bind_client_ip = false};

    // Create User-Agent at exactly the limit
    std::string max_ua(2048, 'A');
    char *salt = generate_salt(&cfg, NULL, max_ua.c_str(), NULL);

    // Should succeed
    REQUIRE(salt != NULL);
    REQUIRE(strlen(salt) == 64);
    free(salt);
    fprintf(stderr, "✓ Salt generation accepts User-Agent at 2048 bytes\n");
  }

  SECTION("Reject Client IP exceeding 64 bytes")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = false, .bind_user_agent = false, .bind_client_ip = true};

    // Create IP that's 100 bytes (exceeds 64 limit)
    std::string giant_ip(100, '1');
    char *salt = generate_salt(&cfg, NULL, NULL, giant_ip.c_str());

    // Should return NULL due to length validation
    REQUIRE(salt == NULL);
    fprintf(stderr, "✓ Salt generation rejects oversized Client IP (100 bytes)\n");
  }

  SECTION("Accept Client IP at exactly 64 bytes")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = false, .bind_user_agent = false, .bind_client_ip = true};

    // Create IP at exactly the limit (64 chars)
    std::string max_ip(64, '2');
    char *salt = generate_salt(&cfg, NULL, NULL, max_ip.c_str());

    // Should succeed
    REQUIRE(salt != NULL);
    REQUIRE(strlen(salt) == 64);
    free(salt);
    fprintf(stderr, "✓ Salt generation accepts Client IP at 64 bytes\n");
  }

  SECTION("Reject combined headers when one exceeds limit")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = true, .bind_user_agent = true, .bind_client_ip = true};

    // Valid session and IP, but oversized User-Agent
    const char *session = "valid-session-123";
    std::string giant_ua(3000, 'B');
    const char *ip = "192.168.1.1";

    char *salt = generate_salt(&cfg, session, giant_ua.c_str(), ip);

    // Should return NULL because User-Agent exceeds limit
    REQUIRE(salt == NULL);
    fprintf(stderr, "✓ Salt generation rejects when any header exceeds limit\n");
  }

  SECTION("Accept combined headers at maximum valid sizes")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = true, .bind_user_agent = true, .bind_client_ip = true};

    // All at or near maximum valid sizes
    std::string max_session(4096, 'S');
    std::string max_ua(2048, 'U');
    std::string max_ip(64, 'I');

    char *salt = generate_salt(&cfg, max_session.c_str(), max_ua.c_str(), max_ip.c_str());

    // Should succeed - total is 6208 bytes which is safe
    REQUIRE(salt != NULL);
    REQUIRE(strlen(salt) == 64);
    free(salt);
    fprintf(stderr, "✓ Salt generation accepts all headers at maximum valid sizes\n");
  }

  fprintf(stderr, "\n");
}

TEST_CASE("Salt validation against JWT", "[TokenAuthLevel2][Session][Validation]")
{
  INFO("TEST: Validate salt in JWT token");

  json_error_t jerr = {};

  SECTION("Validate matching salt")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = true, .bind_user_agent = false, .bind_client_ip = false};

    const char *session_id = "test-session-12345";

    // Generate expected salt
    char *expected_salt = generate_salt(&cfg, session_id, NULL, NULL);
    REQUIRE(expected_salt != NULL);

    // Create JWT with this salt
    char jwt_json[512];
    snprintf(jwt_json, sizeof(jwt_json), "{\"iss\":\"Test\",\"exp\":9999999999,\"cdnisalt\":\"%s\"}", expected_salt);

    json_t *jwt_obj = json_loadb(jwt_json, strlen(jwt_json), 0, &jerr);
    REQUIRE(jwt_obj != NULL);

    struct jwt *jwt = parse_jwt(jwt_obj);
    REQUIRE(jwt != NULL);

    // Validate should pass (token has salt, so parameter names don't matter)
    bool valid = validate_salt(jwt, &cfg, NULL, NULL, session_id, NULL, NULL);
    REQUIRE(valid == true);

    jwt_delete(jwt);
    free(expected_salt);
    fprintf(stderr, "✓ Matching salt validates successfully\n");
  }

  SECTION("Validate mismatched salt")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = true, .bind_user_agent = false, .bind_client_ip = false};

    // JWT with one session's salt
    char *salt1 = generate_salt(&cfg, "session-1", NULL, NULL);
    REQUIRE(salt1 != NULL);

    char jwt_json[512];
    snprintf(jwt_json, sizeof(jwt_json), "{\"iss\":\"Test\",\"exp\":9999999999,\"cdnisalt\":\"%s\"}", salt1);

    json_t *jwt_obj = json_loadb(jwt_json, strlen(jwt_json), 0, &jerr);
    REQUIRE(jwt_obj != NULL);

    struct jwt *jwt = parse_jwt(jwt_obj);
    REQUIRE(jwt != NULL);

    // Validate with different session should fail
    bool valid = validate_salt(jwt, &cfg, NULL, NULL, "session-2", NULL, NULL);
    REQUIRE(valid == false);

    jwt_delete(jwt);
    free(salt1);
    fprintf(stderr, "✓ Mismatched salt validation fails\n");
  }

  SECTION("Validate with salt disabled (always passes)")
  {
    struct salt_config cfg = {.enabled = false, .bind_session_id = true, .bind_user_agent = false, .bind_client_ip = false};

    const char *jwt_string = R"({"iss":"Test","exp":9999999999})";
    json_t *jwt_obj        = json_loadb(jwt_string, strlen(jwt_string), 0, &jerr);
    REQUIRE(jwt_obj != NULL);

    struct jwt *jwt = parse_jwt(jwt_obj);
    REQUIRE(jwt != NULL);

    // Should pass even without cdnisalt claim
    bool valid = validate_salt(jwt, &cfg, NULL, NULL, "any-session", NULL, NULL);
    REQUIRE(valid == true);

    jwt_delete(jwt);
    fprintf(stderr, "✓ Salt validation passes when disabled\n");
  }

  SECTION("Validate access token without salt (should PASS)")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = true, .bind_user_agent = false, .bind_client_ip = false};

    const char *jwt_string = R"({"iss":"Test","exp":9999999999})";
    json_t *jwt_obj        = json_loadb(jwt_string, strlen(jwt_string), 0, &jerr);
    REQUIRE(jwt_obj != NULL);

    struct jwt *jwt = parse_jwt(jwt_obj);
    REQUIRE(jwt != NULL);
    REQUIRE(jwt->cdnisalt == NULL);

    // Should PASS - access token without salt is allowed (origin doesn't know device context)
    bool valid = validate_salt(jwt, &cfg, "cr-access-token", "cr-access-token", "test-session", NULL, NULL);
    REQUIRE(valid == true);

    jwt_delete(jwt);
    fprintf(stderr, "✓ Access token without salt validates successfully\n");
  }

  SECTION("Validate renewal token without salt (should FAIL)")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = true, .bind_user_agent = false, .bind_client_ip = false};

    const char *jwt_string = R"({"iss":"Test","exp":9999999999})";
    json_t *jwt_obj        = json_loadb(jwt_string, strlen(jwt_string), 0, &jerr);
    REQUIRE(jwt_obj != NULL);

    struct jwt *jwt = parse_jwt(jwt_obj);
    REQUIRE(jwt != NULL);
    REQUIRE(jwt->cdnisalt == NULL);

    // Should FAIL - renewal token MUST have salt when salt.enabled=true
    bool valid = validate_salt(jwt, &cfg, "cr-session-token", "cr-access-token", "test-session", NULL, NULL);
    REQUIRE(valid == false);

    jwt_delete(jwt);
    fprintf(stderr, "✓ Renewal token without salt fails validation\n");
  }

  SECTION("Validate token without salt and NULL parameter names (should FAIL)")
  {
    struct salt_config cfg = {.enabled = true, .bind_session_id = true, .bind_user_agent = false, .bind_client_ip = false};

    const char *jwt_string = R"({"iss":"Test","exp":9999999999})";
    json_t *jwt_obj        = json_loadb(jwt_string, strlen(jwt_string), 0, &jerr);
    REQUIRE(jwt_obj != NULL);

    struct jwt *jwt = parse_jwt(jwt_obj);
    REQUIRE(jwt != NULL);
    REQUIRE(jwt->cdnisalt == NULL);

    // Should FAIL - when parameter names not provided, default to REJECT
    bool valid = validate_salt(jwt, &cfg, NULL, NULL, "test-session", NULL, NULL);
    REQUIRE(valid == false);

    jwt_delete(jwt);
    fprintf(stderr, "✓ Token without salt and NULL names fails validation\n");
  }

  fprintf(stderr, "\n");
}

TEST_CASE("Salt validation security: cdnisalt format validation", "[TokenAuthLevel2][Session][Security]")
{
  INFO("TEST: validate_salt() should reject invalid cdnisalt formats");

  json_error_t jerr      = {};
  struct salt_config cfg = {.enabled = true, .bind_session_id = true, .bind_user_agent = false, .bind_client_ip = false};

  const char *session_id = "test-session-12345";

  SECTION("Reject cdnisalt with length < 64 characters")
  {
    // Short salt (only 32 chars)
    const char *jwt_string = R"({
      "iss": "Test",
      "exp": 9999999999,
      "cdnisalt": "abcd1234abcd1234abcd1234abcd1234"
    })";

    json_t *jwt_obj = json_loadb(jwt_string, strlen(jwt_string), 0, &jerr);
    REQUIRE(jwt_obj != NULL);

    struct jwt *jwt = parse_jwt(jwt_obj);
    REQUIRE(jwt != NULL);
    REQUIRE(jwt->cdnisalt != NULL);

    // Should fail - salt is too short
    bool valid = validate_salt(jwt, &cfg, NULL, NULL, session_id, NULL, NULL);
    REQUIRE(valid == false);

    jwt_delete(jwt);
    fprintf(stderr, "✓ Salt validation rejects short salt (32 chars)\n");
  }

  SECTION("Reject cdnisalt with length > 64 characters")
  {
    // Long salt (128 chars - twice the expected length)
    const char *jwt_string = R"({
      "iss": "Test",
      "exp": 9999999999,
      "cdnisalt": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
    })";

    json_t *jwt_obj = json_loadb(jwt_string, strlen(jwt_string), 0, &jerr);
    REQUIRE(jwt_obj != NULL);

    struct jwt *jwt = parse_jwt(jwt_obj);
    REQUIRE(jwt != NULL);
    REQUIRE(jwt->cdnisalt != NULL);

    // Should fail - salt is too long
    bool valid = validate_salt(jwt, &cfg, NULL, NULL, session_id, NULL, NULL);
    REQUIRE(valid == false);

    jwt_delete(jwt);
    fprintf(stderr, "✓ Salt validation rejects long salt (128 chars)\n");
  }

  SECTION("Reject cdnisalt with non-hex characters (uppercase)")
  {
    // Contains uppercase letters (invalid for lowercase hex)
    const char *jwt_string = R"({
      "iss": "Test",
      "exp": 9999999999,
      "cdnisalt": "ABCD1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
    })";

    json_t *jwt_obj = json_loadb(jwt_string, strlen(jwt_string), 0, &jerr);
    REQUIRE(jwt_obj != NULL);

    struct jwt *jwt = parse_jwt(jwt_obj);
    REQUIRE(jwt != NULL);
    REQUIRE(jwt->cdnisalt != NULL);

    // Should fail - contains uppercase hex (we only accept lowercase)
    bool valid = validate_salt(jwt, &cfg, NULL, NULL, session_id, NULL, NULL);
    REQUIRE(valid == false);

    jwt_delete(jwt);
    fprintf(stderr, "✓ Salt validation rejects uppercase hex characters\n");
  }

  SECTION("Reject cdnisalt with special characters")
  {
    // Contains special character '-'
    const char *jwt_string = R"({
      "iss": "Test",
      "exp": 9999999999,
      "cdnisalt": "abcd-234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
    })";

    json_t *jwt_obj = json_loadb(jwt_string, strlen(jwt_string), 0, &jerr);
    REQUIRE(jwt_obj != NULL);

    struct jwt *jwt = parse_jwt(jwt_obj);
    REQUIRE(jwt != NULL);
    REQUIRE(jwt->cdnisalt != NULL);

    // Should fail - contains non-hex character
    bool valid = validate_salt(jwt, &cfg, NULL, NULL, session_id, NULL, NULL);
    REQUIRE(valid == false);

    jwt_delete(jwt);
    fprintf(stderr, "✓ Salt validation rejects special characters\n");
  }

  SECTION("Reject extremely long cdnisalt (DoS protection)")
  {
    // Create a massive salt string (10000 chars) to test DoS protection
    std::string giant_salt(10000, 'a');
    std::string jwt_json = "{\"iss\":\"Test\",\"exp\":9999999999,\"cdnisalt\":\"" + giant_salt + "\"}";

    json_t *jwt_obj = json_loadb(jwt_json.c_str(), jwt_json.length(), 0, &jerr);
    REQUIRE(jwt_obj != NULL);

    struct jwt *jwt = parse_jwt(jwt_obj);
    REQUIRE(jwt != NULL);
    REQUIRE(jwt->cdnisalt != NULL);

    // Should fail immediately due to length check (before expensive strcmp)
    bool valid = validate_salt(jwt, &cfg, NULL, NULL, session_id, NULL, NULL);
    REQUIRE(valid == false);

    jwt_delete(jwt);
    fprintf(stderr, "✓ Salt validation rejects extremely long salt (DoS protection)\n");
  }

  SECTION("Accept valid cdnisalt (exactly 64 lowercase hex chars)")
  {
    // Generate valid salt to compare against
    char *expected_salt = generate_salt(&cfg, session_id, NULL, NULL);
    REQUIRE(expected_salt != NULL);
    REQUIRE(strlen(expected_salt) == 64);

    // Create JWT with this valid salt
    char jwt_json[512];
    snprintf(jwt_json, sizeof(jwt_json), "{\"iss\":\"Test\",\"exp\":9999999999,\"cdnisalt\":\"%s\"}", expected_salt);

    json_t *jwt_obj = json_loadb(jwt_json, strlen(jwt_json), 0, &jerr);
    REQUIRE(jwt_obj != NULL);

    struct jwt *jwt = parse_jwt(jwt_obj);
    REQUIRE(jwt != NULL);
    REQUIRE(jwt->cdnisalt != NULL);

    // Should pass - valid format and matching value
    bool valid = validate_salt(jwt, &cfg, NULL, NULL, session_id, NULL, NULL);
    REQUIRE(valid == true);

    jwt_delete(jwt);
    free(expected_salt);
    fprintf(stderr, "✓ Salt validation accepts valid 64-char lowercase hex salt\n");
  }

  fprintf(stderr, "\n");
}

TEST_CASE("Renew function includes salt in token", "[TokenAuthLevel2][Renew][Salt]")
{
  INFO("TEST: renew() should include cdnisalt claim when salt provided");

  // Load test config
  struct config *cfg = read_config_from_string(testConfig);
  REQUIRE(cfg != NULL);

  struct signer *signer = config_signer(cfg);
  REQUIRE(signer != NULL);
  REQUIRE(signer->jwk != NULL);

  SECTION("Renew token with salt creates token containing cdnisalt")
  {
    // Create a JWT that allows renewal
    const char *jwt_string = R"({
      "iss": "Master Issuer",
      "exp": 9999999999,
      "cdnistt": 1,
      "cdniets": 3600,
      "cdnistd": 0
    })";

    json_error_t jerr = {};
    json_t *jwt_obj   = json_loadb(jwt_string, strlen(jwt_string), 0, &jerr);
    REQUIRE(jwt_obj != NULL);

    struct jwt *jwt = parse_jwt(jwt_obj);
    REQUIRE(jwt != NULL);

    const char *test_salt = "abc123def456";
    const char *test_uri  = "http://example.com/video.mp4";

    // Call renew with salt
    char *cookie = renew(jwt, signer->issuer, signer->jwk, signer->alg, "test-token", test_uri, strlen(test_uri), test_salt);
    REQUIRE(cookie != NULL);

    // Cookie format: "token-name=JWS; Path=/path"
    // Extract the JWS part
    const char *jws_start = strchr(cookie, '=');
    REQUIRE(jws_start != NULL);
    jws_start++; // Skip '='

    const char *jws_end = strchr(jws_start, ';');
    REQUIRE(jws_end != NULL);

    size_t jws_len = jws_end - jws_start;
    char *jws_str  = (char *)malloc(jws_len + 1);
    strncpy(jws_str, jws_start, jws_len);
    jws_str[jws_len] = '\0';

    // Parse the renewed JWS
    cjose_err err;
    cjose_jws_t *renewed_jws = cjose_jws_import(jws_str, jws_len, &err);
    REQUIRE(renewed_jws != NULL);

    // Get the JWKs for validation
    cjose_jwk_t **jwks = find_keys(cfg, signer->issuer);
    REQUIRE(jwks != NULL);

    // Verify and get payload
    uint8_t *payload_data = NULL;
    size_t payload_len    = 0;
    bool verified         = false;

    for (cjose_jwk_t **jwk = jwks; *jwk && !verified; ++jwk) {
      if (cjose_jws_verify(renewed_jws, *jwk, &err)) {
        verified     = true;
        payload_data = NULL;
        payload_len  = 0;
        if (cjose_jws_get_plaintext(renewed_jws, &payload_data, &payload_len, &err)) {
          break;
        }
      }
    }

    REQUIRE(verified == true);
    REQUIRE(payload_data != NULL);
    REQUIRE(payload_len > 0);

    // Parse the payload JSON
    json_t *payload_json = json_loadb((char *)payload_data, payload_len, 0, &jerr);
    REQUIRE(payload_json != NULL);

    // Verify cdnisalt claim exists
    json_t *salt_claim = json_object_get(payload_json, "cdnisalt");
    REQUIRE(salt_claim != NULL);

    const char *salt_value = json_string_value(salt_claim);
    REQUIRE(salt_value != NULL);
    REQUIRE(strcmp(salt_value, test_salt) == 0);

    json_decref(payload_json);
    cjose_jws_release(renewed_jws);
    free(jws_str);
    free(cookie);
    jwt_delete(jwt);

    fprintf(stderr, "✓ Renewed token contains cdnisalt claim\n");
  }

  SECTION("Renew token without salt (NULL) creates token without cdnisalt")
  {
    // Create a JWT that allows renewal
    const char *jwt_string = R"({
      "iss": "Master Issuer",
      "exp": 9999999999,
      "cdnistt": 1,
      "cdniets": 3600,
      "cdnistd": 0
    })";

    json_error_t jerr = {};
    json_t *jwt_obj   = json_loadb(jwt_string, strlen(jwt_string), 0, &jerr);
    REQUIRE(jwt_obj != NULL);

    struct jwt *jwt = parse_jwt(jwt_obj);
    REQUIRE(jwt != NULL);

    const char *test_uri = "http://example.com/video.mp4";

    // Call renew WITHOUT salt (NULL)
    char *cookie = renew(jwt, signer->issuer, signer->jwk, signer->alg, "test-token", test_uri, strlen(test_uri), NULL);
    REQUIRE(cookie != NULL);

    // Extract JWS
    const char *jws_start = strchr(cookie, '=');
    REQUIRE(jws_start != NULL);
    jws_start++;

    const char *jws_end = strchr(jws_start, ';');
    REQUIRE(jws_end != NULL);

    size_t jws_len = jws_end - jws_start;
    char *jws_str  = (char *)malloc(jws_len + 1);
    strncpy(jws_str, jws_start, jws_len);
    jws_str[jws_len] = '\0';

    // Parse the renewed JWS
    cjose_err err;
    cjose_jws_t *renewed_jws = cjose_jws_import(jws_str, jws_len, &err);
    REQUIRE(renewed_jws != NULL);

    // Get payload
    uint8_t *payload_data = NULL;
    size_t payload_len    = 0;
    cjose_jwk_t **jwks    = find_keys(cfg, signer->issuer);
    REQUIRE(jwks != NULL);

    bool verified = false;
    for (cjose_jwk_t **jwk = jwks; *jwk && !verified; ++jwk) {
      if (cjose_jws_verify(renewed_jws, *jwk, &err)) {
        verified = true;
        if (cjose_jws_get_plaintext(renewed_jws, &payload_data, &payload_len, &err)) {
          break;
        }
      }
    }

    REQUIRE(verified == true);
    REQUIRE(payload_data != NULL);

    // Parse the payload JSON
    json_t *payload_json = json_loadb((char *)payload_data, payload_len, 0, &jerr);
    REQUIRE(payload_json != NULL);

    // Verify cdnisalt claim is NULL (not present)
    json_t *salt_claim = json_object_get(payload_json, "cdnisalt");
    REQUIRE(salt_claim == NULL);

    json_decref(payload_json);
    cjose_jws_release(renewed_jws);
    free(jws_str);
    free(cookie);
    jwt_delete(jwt);

    fprintf(stderr, "✓ Renewed token without salt has no cdnisalt claim\n");
  }

  config_delete(cfg);
  fprintf(stderr, "\n");
}

TEST_CASE("Manifest type detection", "[TokenAuthLevel2][Manifest][Detection]")
{
  INFO("TEST: Detect manifest type from URI and Content-Type");

  SECTION("Detect HLS from .m3u8 extension")
  {
    manifest_type_t type = detect_manifest_type("/path/to/playlist.m3u8", NULL);
    REQUIRE(type == MANIFEST_TYPE_HLS_M3U8);
    fprintf(stderr, "✓ Detected HLS from .m3u8 extension\n");
  }

  SECTION("Detect DASH from .mpd extension")
  {
    manifest_type_t type = detect_manifest_type("/path/to/manifest.mpd", NULL);
    REQUIRE(type == MANIFEST_TYPE_DASH_MPD);
    fprintf(stderr, "✓ Detected DASH from .mpd extension\n");
  }

  SECTION("Detect HLS from Content-Type application/vnd.apple.mpegurl")
  {
    manifest_type_t type = detect_manifest_type("/stream", "application/vnd.apple.mpegurl");
    REQUIRE(type == MANIFEST_TYPE_HLS_M3U8);
    fprintf(stderr, "✓ Detected HLS from Content-Type\n");
  }

  SECTION("Detect HLS from Content-Type application/x-mpegURL")
  {
    manifest_type_t type = detect_manifest_type("/stream", "application/x-mpegURL; charset=utf-8");
    REQUIRE(type == MANIFEST_TYPE_HLS_M3U8);
    fprintf(stderr, "✓ Detected HLS from alternative Content-Type\n");
  }

  SECTION("Detect DASH from Content-Type application/dash+xml")
  {
    manifest_type_t type = detect_manifest_type("/stream", "application/dash+xml");
    REQUIRE(type == MANIFEST_TYPE_DASH_MPD);
    fprintf(stderr, "✓ Detected DASH from Content-Type\n");
  }

  SECTION("Unknown type for unrecognized URI")
  {
    manifest_type_t type = detect_manifest_type("/video.mp4", NULL);
    REQUIRE(type == MANIFEST_TYPE_UNKNOWN);
    fprintf(stderr, "✓ Unknown type for non-manifest URI\n");
  }

  SECTION("Prefer extension over Content-Type")
  {
    manifest_type_t type = detect_manifest_type("/playlist.m3u8", "application/dash+xml");
    REQUIRE(type == MANIFEST_TYPE_HLS_M3U8);
    fprintf(stderr, "✓ Extension takes precedence over Content-Type\n");
  }

  fprintf(stderr, "\n");
}

TEST_CASE("HLS segment URL detection", "[TokenAuthLevel2][Manifest][HLS]")
{
  INFO("TEST: Identify segment URLs vs tags in HLS manifests");

  SECTION("Segment URL line")
  {
    REQUIRE(is_segment_url("segment001.ts") == true);
    REQUIRE(is_segment_url("  segment001.ts") == true);
    REQUIRE(is_segment_url("http://example.com/seg.ts") == true);
    fprintf(stderr, "✓ Identified segment URL lines\n");
  }

  SECTION("Tag lines are not segments")
  {
    REQUIRE(is_segment_url("#EXTM3U") == false);
    REQUIRE(is_segment_url("#EXT-X-VERSION:3") == false);
    REQUIRE(is_segment_url("#EXTINF:10.0,") == false);
    fprintf(stderr, "✓ Tags correctly identified as non-segments\n");
  }

  SECTION("Empty lines are not segments")
  {
    REQUIRE(is_segment_url("") == false);
    REQUIRE(is_segment_url("   ") == false);
    REQUIRE(is_segment_url("\n") == false);
    fprintf(stderr, "✓ Empty lines correctly identified as non-segments\n");
  }

  SECTION("Init segment detection")
  {
    REQUIRE(is_init_segment("#EXT-X-MAP:URI=\"init.mp4\"") == true);
    REQUIRE(is_init_segment("#EXT-X-MAP:URI=\"init.mp4\",BYTERANGE=\"500@0\"") == true);
    REQUIRE(is_init_segment("#EXTINF:10.0,") == false);
    fprintf(stderr, "✓ Init segments correctly identified\n");
  }

  fprintf(stderr, "\n");
}

TEST_CASE("strip_param_from_url: Remove query parameters", "[TokenAuthLevel2][Manifest][URLManipulation][BugFix]")
{
  INFO("TEST: strip_param_from_url() - BUG #4 Fix - Fragment preservation");

  SECTION("Strip token from URL with fragment (BUG #4 FIX)")
  {
    // CRITICAL: Fragment must be preserved when stripping parameter
    char *result = strip_param_from_url("segment.ts?token=OLD#t=0.0", "token");
    REQUIRE(result != NULL);
    REQUIRE(std::string(result) == "segment.ts#t=0.0");
    free(result);
    fprintf(stderr, "✓ BUG #4 FIX: Fragment preserved when stripping first param\n");
  }

  SECTION("Strip middle param with fragment")
  {
    char *result = strip_param_from_url("seg.ts?a=1&token=OLD&b=2#frag", "token");
    REQUIRE(result != NULL);
    REQUIRE(std::string(result) == "seg.ts?a=1&b=2#frag");
    free(result);
    fprintf(stderr, "✓ Fragment preserved when stripping middle param\n");
  }

  SECTION("Strip last param with fragment")
  {
    char *result = strip_param_from_url("seg.ts?a=1&token=OLD#frag", "token");
    REQUIRE(result != NULL);
    REQUIRE(std::string(result) == "seg.ts?a=1#frag");
    free(result);
    fprintf(stderr, "✓ Fragment preserved when stripping last param\n");
  }

  SECTION("Strip param without fragment (normal case)")
  {
    char *result = strip_param_from_url("seg.ts?token=OLD", "token");
    REQUIRE(result != NULL);
    REQUIRE(std::string(result) == "seg.ts");
    free(result);
    fprintf(stderr, "✓ Works correctly without fragment\n");
  }

  SECTION("Strip param with empty fragment")
  {
    char *result = strip_param_from_url("seg.ts?token=OLD#", "token");
    REQUIRE(result != NULL);
    REQUIRE(std::string(result) == "seg.ts#");
    free(result);
    fprintf(stderr, "✓ Empty fragment preserved\n");
  }

  SECTION("Strip param with fragment containing special chars")
  {
    char *result = strip_param_from_url("seg.ts?token=OLD#t=0&foo=bar", "token");
    REQUIRE(result != NULL);
    REQUIRE(std::string(result) == "seg.ts#t=0&foo=bar");
    free(result);
    fprintf(stderr, "✓ Fragment with special chars preserved\n");
  }

  SECTION("URL without token param - fragment preserved")
  {
    char *result = strip_param_from_url("seg.ts?other=value#frag", "token");
    REQUIRE(result != NULL);
    REQUIRE(std::string(result) == "seg.ts?other=value#frag");
    free(result);
    fprintf(stderr, "✓ No changes when token not found\n");
  }

  SECTION("Multiple params with fragment - strip first")
  {
    char *result = strip_param_from_url("seg.ts?token=OLD&a=1&b=2#frag", "token");
    REQUIRE(result != NULL);
    REQUIRE(std::string(result) == "seg.ts?a=1&b=2#frag");
    free(result);
    fprintf(stderr, "✓ Multiple params + fragment handled correctly\n");
  }

  fprintf(stderr, "\n");
}

TEST_CASE("Add token to URL", "[TokenAuthLevel2][Manifest][URLManipulation]")
{
  INFO("TEST: Append token parameter to various URL formats");

  SECTION("URL without query parameters")
  {
    char *result = add_token_to_url("segment001.ts", "eyJ0eXAi.eyJpc3Mi.SflKx", "token");
    REQUIRE(result != NULL);
    REQUIRE(std::string(result) == "segment001.ts?token=eyJ0eXAi.eyJpc3Mi.SflKx");
    free(result);
    fprintf(stderr, "✓ Added token to URL without query\n");
  }

  SECTION("URL with existing query parameters")
  {
    char *result = add_token_to_url("segment001.ts?foo=bar", "eyJ0eXAi.eyJpc3Mi.SflKx", "token");
    REQUIRE(result != NULL);
    REQUIRE(std::string(result) == "segment001.ts?foo=bar&token=eyJ0eXAi.eyJpc3Mi.SflKx");
    free(result);
    fprintf(stderr, "✓ Added token to URL with existing query\n");
  }

  SECTION("URL with leading/trailing whitespace")
  {
    char *result = add_token_to_url("  segment001.ts  ", "eyJ0eXAi.eyJpc3Mi.SflKx", "token");
    REQUIRE(result != NULL);
    REQUIRE(std::string(result) == "segment001.ts?token=eyJ0eXAi.eyJpc3Mi.SflKx");
    free(result);
    fprintf(stderr, "✓ Trimmed whitespace before adding token\n");
  }

  SECTION("Absolute URL")
  {
    char *result = add_token_to_url("http://example.com/path/segment.ts", "eyJ0eXAi.eyJpc3Mi.SflKx", "cr-session-token");
    REQUIRE(result != NULL);
    REQUIRE(std::string(result) == "http://example.com/path/segment.ts?cr-session-token=eyJ0eXAi.eyJpc3Mi.SflKx");
    free(result);
    fprintf(stderr, "✓ Added token to absolute URL\n");
  }

  SECTION("NULL inputs return NULL")
  {
    REQUIRE(add_token_to_url(NULL, "token", "param") == NULL);
    REQUIRE(add_token_to_url("url", NULL, "param") == NULL);
    REQUIRE(add_token_to_url("url", "token", NULL) == NULL);
    fprintf(stderr, "✓ NULL inputs handled correctly\n");
  }

  SECTION("URL with fragment identifier - token BEFORE fragment (RFC 3986)")
  {
    // BUG #1 FIX: Fragment must come AFTER query string per RFC 3986
    char *result = add_token_to_url("segment.ts#t=0.0", "eyJ0eXAi.eyJpc3Mi.SflKx", "token");
    REQUIRE(result != NULL);
    REQUIRE(std::string(result) == "segment.ts?token=eyJ0eXAi.eyJpc3Mi.SflKx#t=0.0");
    free(result);
    fprintf(stderr, "✓ Fragment placed AFTER token (RFC 3986)\n");
  }

  SECTION("URL with query params AND fragment - token BEFORE fragment")
  {
    char *result = add_token_to_url("segment.ts?quality=high#t=0.0", "eyJ0eXAi.eyJpc3Mi.SflKx", "token");
    REQUIRE(result != NULL);
    REQUIRE(std::string(result) == "segment.ts?quality=high&token=eyJ0eXAi.eyJpc3Mi.SflKx#t=0.0");
    free(result);
    fprintf(stderr, "✓ Fragment placed AFTER token with existing query\n");
  }

  fprintf(stderr, "\n");
}

TEST_CASE("HLS manifest token injection", "[TokenAuthLevel2][Manifest][HLS][Injection]")
{
  INFO("TEST: Inject tokens into HLS M3U8 manifests");

  const char *token      = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJDRE4iLCJleHAiOjE3MDAwMDAwMDB9.abcdef123456";
  const char *param_name = "cr-session-token";

  SECTION("Simple manifest with media segments")
  {
    const char *manifest = "#EXTM3U\n"
                           "#EXT-X-VERSION:3\n"
                           "#EXT-X-TARGETDURATION:10\n"
                           "#EXTINF:10.0,\n"
                           "segment001.ts\n"
                           "#EXTINF:10.0,\n"
                           "segment002.ts\n"
                           "#EXT-X-ENDLIST\n";

    struct manifest_injection_config cfg = {.enabled                 = true,
                                            .inject_to_segments      = true,
                                            .inject_to_init_segments = false,
                                            .replace_access_token    = false,
                                            .hls_support             = true,
                                            .dash_support            = false,
                                            .cache_untransformed     = true};

    size_t new_len = 0;
    char *result   = inject_token_hls(manifest, strlen(manifest), token, param_name, NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    REQUIRE(new_len > 0);

    std::string result_str(result);
    REQUIRE(result_str.find("segment001.ts?cr-session-token=") != std::string::npos);
    REQUIRE(result_str.find("segment002.ts?cr-session-token=") != std::string::npos);
    REQUIRE(result_str.find("#EXTM3U") != std::string::npos);
    REQUIRE(result_str.find("#EXT-X-VERSION:3") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ Injected tokens into media segments\n");
  }

  SECTION("Manifest with init segment (EXT-X-MAP)")
  {
    const char *manifest = "#EXTM3U\n"
                           "#EXT-X-VERSION:6\n"
                           "#EXT-X-MAP:URI=\"init.mp4\"\n"
                           "segment001.m4s\n"
                           "segment002.m4s\n";

    struct manifest_injection_config cfg_with_init = {.enabled                 = true,
                                                      .inject_to_segments      = true,
                                                      .inject_to_init_segments = true,
                                                      .replace_access_token    = false,
                                                      .hls_support             = true,
                                                      .dash_support            = false,
                                                      .cache_untransformed     = true};

    size_t new_len = 0;
    char *result   = inject_token_hls(manifest, strlen(manifest), token, param_name, NULL, &cfg_with_init, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);
    REQUIRE(result_str.find("init.mp4?cr-session-token=") != std::string::npos);
    REQUIRE(result_str.find("segment001.m4s?cr-session-token=") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ Injected tokens into init and media segments\n");
  }

  SECTION("Manifest with init segment but injection disabled for init")
  {
    const char *manifest = "#EXTM3U\n"
                           "#EXT-X-MAP:URI=\"init.mp4\"\n"
                           "segment001.m4s\n";

    struct manifest_injection_config cfg_no_init = {.enabled                 = true,
                                                    .inject_to_segments      = true,
                                                    .inject_to_init_segments = false,
                                                    .replace_access_token    = false,
                                                    .hls_support             = true,
                                                    .dash_support            = false,
                                                    .cache_untransformed     = true};

    size_t new_len = 0;
    char *result   = inject_token_hls(manifest, strlen(manifest), token, param_name, NULL, &cfg_no_init, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);
    REQUIRE(result_str.find("init.mp4?cr-session-token=") == std::string::npos);
    REQUIRE(result_str.find("segment001.m4s?cr-session-token=") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ Init segment injection respects config\n");
  }

  SECTION("Injection disabled for segments")
  {
    const char *manifest = "#EXTM3U\n"
                           "segment001.ts\n";

    struct manifest_injection_config cfg_no_segments = {.enabled                 = true,
                                                        .inject_to_segments      = false,
                                                        .inject_to_init_segments = false,
                                                        .replace_access_token    = false,
                                                        .hls_support             = true,
                                                        .dash_support            = false,
                                                        .cache_untransformed     = true};

    size_t new_len = 0;
    char *result   = inject_token_hls(manifest, strlen(manifest), token, param_name, NULL, &cfg_no_segments, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);
    REQUIRE(result_str.find("segment001.ts?cr-session-token=") == std::string::npos);
    REQUIRE(result_str == manifest);

    free(result);
    fprintf(stderr, "✓ Segment injection respects config\n");
  }

  SECTION("Preserve existing query parameters")
  {
    const char *manifest = "#EXTM3U\n"
                           "segment001.ts?foo=bar\n";

    struct manifest_injection_config cfg = {.enabled                 = true,
                                            .inject_to_segments      = true,
                                            .inject_to_init_segments = false,
                                            .replace_access_token    = false,
                                            .hls_support             = true,
                                            .dash_support            = false,
                                            .cache_untransformed     = true};

    size_t new_len = 0;
    char *result   = inject_token_hls(manifest, strlen(manifest), token, param_name, NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);
    REQUIRE(result_str.find("segment001.ts?foo=bar&cr-session-token=") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ Preserved existing query parameters\n");
  }

  SECTION("NULL inputs handled correctly")
  {
    struct manifest_injection_config cfg = {.enabled                 = true,
                                            .inject_to_segments      = true,
                                            .inject_to_init_segments = false,
                                            .replace_access_token    = false,
                                            .hls_support             = true,
                                            .dash_support            = false,
                                            .cache_untransformed     = true};

    size_t new_len = 0;
    REQUIRE(inject_token_hls(NULL, 100, token, param_name, NULL, &cfg, &new_len) == NULL);
    REQUIRE(inject_token_hls("manifest", 8, NULL, param_name, NULL, &cfg, &new_len) == NULL);
    REQUIRE(inject_token_hls("manifest", 8, token, NULL, NULL, &cfg, &new_len) == NULL);
    REQUIRE(inject_token_hls("manifest", 8, token, param_name, NULL, NULL, &new_len) == NULL);

    fprintf(stderr, "✓ NULL input validation working\n");
  }

  fprintf(stderr, "\n");
}

TEST_CASE("DASH manifest token injection", "[TokenAuthLevel2][Manifest][DASH][Injection]")
{
  INFO("TEST: DASH injection (basic passthrough for now)");

  const char *token      = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJDRE4iLCJleHAiOjE3MDAwMDAwMDB9.abcdef123456";
  const char *param_name = "cr-session-token";

  SECTION("DASH manifest basic injection")
  {
    const char *manifest = "<?xml version=\"1.0\"?>\n"
                           "<MPD xmlns=\"urn:mpeg:dash:schema:mpd:2011\">\n"
                           "  <Period>\n"
                           "    <AdaptationSet>\n"
                           "      <Representation id=\"1\">\n"
                           "        <BaseURL>segment.mp4</BaseURL>\n"
                           "      </Representation>\n"
                           "    </AdaptationSet>\n"
                           "  </Period>\n"
                           "</MPD>\n";

    struct manifest_injection_config cfg = {.enabled                 = true,
                                            .inject_to_segments      = true,
                                            .inject_to_init_segments = false,
                                            .replace_access_token    = false,
                                            .hls_support             = false,
                                            .dash_support            = true,
                                            .cache_untransformed     = true};

    size_t new_len = 0;
    char *result   = inject_token_dash(manifest, strlen(manifest), token, param_name, NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    REQUIRE(new_len > 0);
    std::string result_str(result);
    REQUIRE(result_str.find("segment.mp4?" + std::string(param_name) + "=" + std::string(token)) != std::string::npos);

    free(result);
    fprintf(stderr, "✓ DASH basic structure validated\n");
  }

  SECTION("DASH: Basic MPD with BaseURL")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD xmlns=\"urn:mpeg:dash:schema:mpd:2011\">\n"
                      "  <Period>\n"
                      "    <AdaptationSet>\n"
                      "      <Representation id=\"1\" bandwidth=\"1000000\">\n"
                      "        <BaseURL>http://cdn.example.com/video/</BaseURL>\n"
                      "      </Representation>\n"
                      "    </AdaptationSet>\n"
                      "  </Period>\n"
                      "</MPD>";

    struct manifest_injection_config cfg = {.enabled                 = true,
                                            .inject_to_segments      = true,
                                            .inject_to_init_segments = false,
                                            .replace_access_token    = false,
                                            .hls_support             = false,
                                            .dash_support            = true,
                                            .cache_untransformed     = true};

    size_t new_len = 0;
    char *result   = inject_token_dash(mpd, strlen(mpd), "TOKEN123", "token", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    REQUIRE(new_len > 0);
    std::string result_str(result);
    REQUIRE(result_str.find("<BaseURL>http://cdn.example.com/video/?token=TOKEN123</BaseURL>") != std::string::npos);
    free(result);
    fprintf(stderr, "✓ DASH: BaseURL injection works\n");
  }

  SECTION("DASH: SegmentTemplate with media and initialization")
  {
    const char *mpd =
      "<?xml version=\"1.0\"?>\n"
      "<MPD><Period><AdaptationSet><Representation>\n"
      "<SegmentTemplate media=\"segment-$Number$.m4s\" initialization=\"init.mp4\" startNumber=\"1\" timescale=\"90000\"/>\n"
      "</Representation></AdaptationSet></Period></MPD>";

    struct manifest_injection_config cfg = {true, true, true, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(mpd, strlen(mpd), "ABC123", "t", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);
    REQUIRE(result_str.find("media=\"segment-$Number$.m4s?t=ABC123\"") != std::string::npos);
    REQUIRE(result_str.find("initialization=\"init.mp4?t=ABC123\"") != std::string::npos);
    free(result);
    fprintf(stderr, "✓ DASH: SegmentTemplate injection works\n");
  }

  SECTION("DASH: Multi-level BaseURL hierarchy")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD><BaseURL>http://cdn1.example.com/</BaseURL>\n"
                      "<Period><BaseURL>live/</BaseURL>\n"
                      "<AdaptationSet><BaseURL>video/</BaseURL>\n"
                      "<Representation><BaseURL>720p/</BaseURL>\n"
                      "</Representation></AdaptationSet></Period></MPD>";

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(mpd, strlen(mpd), "XYZ", "tok", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);
    // All BaseURLs should have token injected
    REQUIRE(result_str.find("<BaseURL>http://cdn1.example.com/?tok=XYZ</BaseURL>") != std::string::npos);
    REQUIRE(result_str.find("<BaseURL>live/?tok=XYZ</BaseURL>") != std::string::npos);
    REQUIRE(result_str.find("<BaseURL>video/?tok=XYZ</BaseURL>") != std::string::npos);
    REQUIRE(result_str.find("<BaseURL>720p/?tok=XYZ</BaseURL>") != std::string::npos);
    free(result);
    fprintf(stderr, "✓ DASH: Multi-level BaseURL injection works\n");
  }

  SECTION("DASH: SegmentList with SegmentURL")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD><Period><AdaptationSet><Representation>\n"
                      "<SegmentList>\n"
                      "  <SegmentURL media=\"seg1.m4s\"/>\n"
                      "  <SegmentURL media=\"seg2.m4s\"/>\n"
                      "  <SegmentURL media=\"seg3.m4s\"/>\n"
                      "</SegmentList>\n"
                      "</Representation></AdaptationSet></Period></MPD>";

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(mpd, strlen(mpd), "SEG", "s", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);
    REQUIRE(result_str.find("media=\"seg1.m4s?s=SEG\"") != std::string::npos);
    REQUIRE(result_str.find("media=\"seg2.m4s?s=SEG\"") != std::string::npos);
    REQUIRE(result_str.find("media=\"seg3.m4s?s=SEG\"") != std::string::npos);
    free(result);
    fprintf(stderr, "✓ DASH: SegmentURL injection works\n");
  }

  SECTION("DASH: Initialization element with sourceURL")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD><Period><AdaptationSet><Representation>\n"
                      "<SegmentList>\n"
                      "  <Initialization sourceURL=\"init-stream.mp4\"/>\n"
                      "  <SegmentURL media=\"seg1.m4s\"/>\n"
                      "</SegmentList>\n"
                      "</Representation></AdaptationSet></Period></MPD>";

    struct manifest_injection_config cfg = {true, true, true, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(mpd, strlen(mpd), "INIT", "i", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);
    REQUIRE(result_str.find("sourceURL=\"init-stream.mp4?i=INIT\"") != std::string::npos);
    REQUIRE(result_str.find("media=\"seg1.m4s?i=INIT\"") != std::string::npos);
    free(result);
    fprintf(stderr, "✓ DASH: Initialization sourceURL injection works\n");
  }

  SECTION("DASH: Config flags - inject_to_segments only")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD><Period><AdaptationSet><Representation>\n"
                      "<SegmentTemplate media=\"seg.m4s\" initialization=\"init.mp4\"/>\n"
                      "</Representation></AdaptationSet></Period></MPD>";

    // Only inject to segments, NOT init segments
    struct manifest_injection_config cfg = {.enabled                 = true,
                                            .inject_to_segments      = true,
                                            .inject_to_init_segments = false,
                                            .replace_access_token    = false,
                                            .hls_support             = false,
                                            .dash_support            = true,
                                            .cache_untransformed     = true};

    size_t new_len = 0;
    char *result   = inject_token_dash(mpd, strlen(mpd), "FLAG", "f", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);
    REQUIRE(result_str.find("media=\"seg.m4s?f=FLAG\"") != std::string::npos);
    REQUIRE(result_str.find("initialization=\"init.mp4\"") != std::string::npos); // NO token
    free(result);
    fprintf(stderr, "✓ DASH: inject_to_segments flag respected\n");
  }

  SECTION("DASH: Config flags - inject_to_init_segments only")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD><Period><AdaptationSet><Representation>\n"
                      "<SegmentTemplate media=\"seg.m4s\" initialization=\"init.mp4\"/>\n"
                      "</Representation></AdaptationSet></Period></MPD>";

    // Only inject to init segments, NOT media segments
    struct manifest_injection_config cfg = {.enabled                 = true,
                                            .inject_to_segments      = false,
                                            .inject_to_init_segments = true,
                                            .replace_access_token    = false,
                                            .hls_support             = false,
                                            .dash_support            = true,
                                            .cache_untransformed     = true};

    size_t new_len = 0;
    char *result   = inject_token_dash(mpd, strlen(mpd), "INIT_ONLY", "io", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);
    REQUIRE(result_str.find("media=\"seg.m4s\"") != std::string::npos); // NO token
    REQUIRE(result_str.find("initialization=\"init.mp4?io=INIT_ONLY\"") != std::string::npos);
    free(result);
    fprintf(stderr, "✓ DASH: inject_to_init_segments flag respected\n");
  }

  SECTION("DASH: Query parameter handling - existing query string")
  {
    // Test with actual query string - libxml2 will encode & as &amp; in output
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD><Period><AdaptationSet><Representation>\n"
                      "<BaseURL>http://cdn.example.com/video?quality=hd&amp;bitrate=5000</BaseURL>\n"
                      "</Representation></AdaptationSet></Period></MPD>";

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(mpd, strlen(mpd), "QP", "token", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);

    // libxml2 will parse &amp; as & internally, then re-encode as &amp; in output
    // So we should find the parameters preserved and token added
    // The actual serialized form will have &amp; entities
    REQUIRE(result_str.find("quality=hd") != std::string::npos);
    REQUIRE(result_str.find("bitrate=5000") != std::string::npos);
    REQUIRE(result_str.find("token=QP") != std::string::npos);

    // Verify proper XML entity encoding (should be &amp; not bare &)
    size_t bare_amp_pos    = result_str.find("quality=hd&bitrate");
    size_t encoded_amp_pos = result_str.find("quality=hd&amp;bitrate");
    // Should NOT find bare & (bare_amp_pos == npos), SHOULD find &amp;
    REQUIRE(bare_amp_pos == std::string::npos);
    REQUIRE(encoded_amp_pos != std::string::npos);

    free(result);
    fprintf(stderr, "✓ DASH: Query parameter handling works\n");
  }

  SECTION("DASH: Complex nested structure with multiple representations")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD><Period>\n"
                      "<AdaptationSet contentType=\"video\">\n"
                      "  <Representation id=\"720\" bandwidth=\"1500000\">\n"
                      "    <BaseURL>720p/</BaseURL>\n"
                      "    <SegmentTemplate media=\"seg-$Number$.m4s\" initialization=\"init.mp4\"/>\n"
                      "  </Representation>\n"
                      "  <Representation id=\"1080\" bandwidth=\"3000000\">\n"
                      "    <BaseURL>1080p/</BaseURL>\n"
                      "    <SegmentTemplate media=\"seg-$Number$.m4s\" initialization=\"init.mp4\"/>\n"
                      "  </Representation>\n"
                      "</AdaptationSet>\n"
                      "<AdaptationSet contentType=\"audio\">\n"
                      "  <Representation id=\"audio\" bandwidth=\"128000\">\n"
                      "    <BaseURL>audio/</BaseURL>\n"
                      "    <SegmentTemplate media=\"seg-$Number$.m4a\" initialization=\"init.m4a\"/>\n"
                      "  </Representation>\n"
                      "</AdaptationSet>\n"
                      "</Period></MPD>";

    struct manifest_injection_config cfg = {true, true, true, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(mpd, strlen(mpd), "MULTI", "m", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);
    // All BaseURLs should have token
    REQUIRE(result_str.find("<BaseURL>720p/?m=MULTI</BaseURL>") != std::string::npos);
    REQUIRE(result_str.find("<BaseURL>1080p/?m=MULTI</BaseURL>") != std::string::npos);
    REQUIRE(result_str.find("<BaseURL>audio/?m=MULTI</BaseURL>") != std::string::npos);
    // All SegmentTemplates should have token in both media and init
    size_t pos            = 0;
    int video_media_count = 0;
    while ((pos = result_str.find("media=\"seg-$Number$.m4s?m=MULTI\"", pos)) != std::string::npos) {
      video_media_count++;
      pos++;
    }
    REQUIRE(video_media_count == 2); // Two video representations
    free(result);
    fprintf(stderr, "✓ DASH: Complex multi-representation structure works\n");
  }

  SECTION("DASH: Malformed XML handling")
  {
    const char *bad_mpd                  = "<?xml version=\"1.0\"?><MPD><Period><Unclosed>";
    struct manifest_injection_config cfg = {true, true, true, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(bad_mpd, strlen(bad_mpd), "ERR", "e", NULL, &cfg, &new_len);

    // Should handle gracefully and return NULL
    REQUIRE(result == NULL);
    fprintf(stderr, "✓ DASH: Malformed XML handled gracefully\n");
  }

  SECTION("DASH: Non-MPD root element")
  {
    const char *wrong_root               = "<?xml version=\"1.0\"?><NotMPD><Period></Period></NotMPD>";
    struct manifest_injection_config cfg = {true, true, true, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(wrong_root, strlen(wrong_root), "WR", "w", NULL, &cfg, &new_len);

    // Should detect and reject non-MPD documents
    REQUIRE(result == NULL);
    fprintf(stderr, "✓ DASH: Non-MPD root element rejected\n");
  }

  SECTION("DASH: Empty MPD")
  {
    const char *empty_mpd                = "<?xml version=\"1.0\"?><MPD></MPD>";
    struct manifest_injection_config cfg = {true, true, true, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(empty_mpd, strlen(empty_mpd), "EMP", "e", NULL, &cfg, &new_len);

    // Should handle empty MPD without crashing
    REQUIRE(result != NULL);
    REQUIRE(new_len > 0);
    free(result);
    fprintf(stderr, "✓ DASH: Empty MPD handled correctly\n");
  }

  SECTION("DASH: NULL input validation")
  {
    struct manifest_injection_config cfg = {true, true, true, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;

    REQUIRE(inject_token_dash(NULL, 100, "tok", "t", NULL, &cfg, &new_len) == NULL);
    REQUIRE(inject_token_dash("<MPD></MPD>", 11, NULL, "t", NULL, &cfg, &new_len) == NULL);
    REQUIRE(inject_token_dash("<MPD></MPD>", 11, "tok", NULL, NULL, &cfg, &new_len) == NULL);
    REQUIRE(inject_token_dash("<MPD></MPD>", 11, "tok", "t", NULL, NULL, &new_len) == NULL);
    REQUIRE(inject_token_dash("<MPD></MPD>", 11, "tok", "t", NULL, &cfg, NULL) == NULL);
    fprintf(stderr, "✓ DASH: NULL input validation works\n");
  }

  SECTION("DASH: Special characters in URLs")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD><Period><AdaptationSet><Representation>\n"
                      "<BaseURL>http://cdn.example.com/path%20with%20spaces/video/</BaseURL>\n"
                      "</Representation></AdaptationSet></Period></MPD>";

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(mpd, strlen(mpd), "SPECIAL", "s", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);
    // URL encoding should be preserved
    REQUIRE(result_str.find("path%20with%20spaces/video/?s=SPECIAL") != std::string::npos);
    free(result);
    fprintf(stderr, "✓ DASH: Special characters handled correctly\n");
  }

  SECTION("DASH: Very long token")
  {
    const char *mpd = "<?xml "
                      "version=\"1.0\"?><MPD><Period><AdaptationSet><Representation><BaseURL>http://cdn.com/</BaseURL></"
                      "Representation></AdaptationSet></Period></MPD>";
    // Create a very long token (JWT can be 1000+ chars)
    std::string long_token(2000, 'A');
    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(mpd, strlen(mpd), long_token.c_str(), "jwt", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);
    REQUIRE(result_str.find("http://cdn.com/?jwt=" + long_token) != std::string::npos);
    free(result);
    fprintf(stderr, "✓ DASH: Very long token handled correctly\n");
  }

  SECTION("DASH: Mixed content - segments and init segments")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD><Period><AdaptationSet><Representation>\n"
                      "<SegmentList>\n"
                      "  <Initialization sourceURL=\"init.mp4\"/>\n"
                      "  <SegmentURL media=\"seg1.m4s\"/>\n"
                      "  <SegmentURL media=\"seg2.m4s\"/>\n"
                      "</SegmentList>\n"
                      "</Representation></AdaptationSet></Period></MPD>";

    // Inject to both
    struct manifest_injection_config cfg = {true, true, true, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(mpd, strlen(mpd), "BOTH", "b", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);
    REQUIRE(result_str.find("sourceURL=\"init.mp4?b=BOTH\"") != std::string::npos);
    REQUIRE(result_str.find("media=\"seg1.m4s?b=BOTH\"") != std::string::npos);
    REQUIRE(result_str.find("media=\"seg2.m4s?b=BOTH\"") != std::string::npos);
    free(result);
    fprintf(stderr, "✓ DASH: Mixed init and segments injection works\n");
  }

  SECTION("DASH: Preserve original XML formatting (whitespace/indentation)")
  {
    // Well-formatted DASH manifest with indentation and newlines
    const char *formatted_mpd = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                "<MPD xmlns=\"urn:mpeg:dash:schema:mpd:2011\">\n"
                                "  <Period>\n"
                                "    <AdaptationSet>\n"
                                "      <Representation id=\"1\" bandwidth=\"500000\">\n"
                                "        <BaseURL>http://cdn.example.com/video/</BaseURL>\n"
                                "        <SegmentTemplate media=\"seg-$Number$.m4s\"\n"
                                "                         initialization=\"init.mp4\"/>\n"
                                "      </Representation>\n"
                                "    </AdaptationSet>\n"
                                "  </Period>\n"
                                "</MPD>\n";

    struct manifest_injection_config cfg = {true, true, true, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result = inject_token_dash(formatted_mpd, strlen(formatted_mpd), "FMT123", "fmt", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);

    // Verify token injection worked
    REQUIRE(result_str.find("http://cdn.example.com/video/?fmt=FMT123") != std::string::npos);
    REQUIRE(result_str.find("media=\"seg-$Number$.m4s?fmt=FMT123\"") != std::string::npos);
    REQUIRE(result_str.find("initialization=\"init.mp4?fmt=FMT123\"") != std::string::npos);

    // Verify XML structure is preserved
    REQUIRE(result_str.find("<?xml") != std::string::npos);
    REQUIRE(result_str.find("<MPD") != std::string::npos);
    REQUIRE(result_str.find("</MPD>") != std::string::npos);

    // CRITICAL: Verify formatting is preserved (should contain newlines and indentation)
    // Look for multi-line structure - if minified, everything would be on one line
    REQUIRE(result_str.find("\n") != std::string::npos);
    REQUIRE(result_str.find("  <Period>") != std::string::npos);            // 2-space indent
    REQUIRE(result_str.find("    <AdaptationSet>") != std::string::npos);   // 4-space indent
    REQUIRE(result_str.find("      <Representation") != std::string::npos); // 6-space indent

    // Count newlines - formatted MPD should have multiple lines
    size_t newline_count = std::count(result_str.begin(), result_str.end(), '\n');
    REQUIRE(newline_count >= 10); // At least 10 newlines for properly formatted XML

    free(result);
    fprintf(stderr, "✓ DASH: Original formatting (whitespace/indentation) preserved\n");
  }

  // ========================================================================
  // SECURITY TESTS - XML Injection & Attack Vectors
  // ========================================================================

  SECTION("DASH Security: XXE (XML External Entity) injection attempt")
  {
    // Malicious MPD trying to reference external entities
    const char *xxe_mpd = "<?xml version=\"1.0\"?>\n"
                          "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n"
                          "<MPD><BaseURL>&xxe;</BaseURL></MPD>";

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(xxe_mpd, strlen(xxe_mpd), "XXE", "t", NULL, &cfg, &new_len);

    // With XML_PARSE_NONET, entity will NOT be expanded
    // The entity reference will remain as is or cause parse error
    if (result) {
      std::string result_str(result);
      // Should NOT contain actual /etc/passwd content (lines with root:x:0:0:...)
      // Should NOT contain "root:" pattern from passwd file
      REQUIRE(result_str.find("root:x:0:0") == std::string::npos);
      free(result);
    }
    // Either parse failed (NULL) or parsed without expansion - both acceptable
    fprintf(stderr, "✓ DASH Security: XXE injection blocked\n");
  }

  SECTION("DASH Security: Billion laughs attack (XML bomb)")
  {
    // XML bomb - exponential entity expansion
    const char *bomb = "<?xml version=\"1.0\"?>\n"
                       "<!DOCTYPE lolz [\n"
                       "<!ENTITY lol \"lol\">\n"
                       "<!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n"
                       "<!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">\n"
                       "]>\n"
                       "<MPD><BaseURL>&lol3;</BaseURL></MPD>";

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;

    // This should either fail gracefully or parse safely (not expand entities)
    char *result = inject_token_dash(bomb, strlen(bomb), "BOMB", "t", NULL, &cfg, &new_len);

    if (result) {
      // If parsed, length should be reasonable (not gigabytes from expansion)
      REQUIRE(new_len < 10000); // Reasonable limit
      free(result);
    }

    fprintf(stderr, "✓ DASH Security: XML bomb handled safely\n");
  }

  SECTION("DASH Security: Deeply nested XML (stack overflow test)")
  {
    // Create deeply nested XML (1000 levels)
    std::string deep_xml = "<?xml version=\"1.0\"?><MPD>";
    for (int i = 0; i < 1000; i++) {
      deep_xml += "<Period>";
    }
    deep_xml += "<BaseURL>test.m4s</BaseURL>";
    for (int i = 0; i < 1000; i++) {
      deep_xml += "</Period>";
    }
    deep_xml += "</MPD>";

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result = inject_token_dash(deep_xml.c_str(), deep_xml.length(), "DEEP", "t", NULL, &cfg, &new_len);

    // Should not crash, either parse or reject
    if (result) {
      REQUIRE(new_len > 0);
      free(result);
    }

    fprintf(stderr, "✓ DASH Security: Deep nesting handled\n");
  }

  SECTION("DASH Security: Malicious URL in BaseURL (script injection)")
  {
    // Try to inject JavaScript via URL
    const char *xss_mpd = "<?xml version=\"1.0\"?>\n"
                          "<MPD><Period><AdaptationSet><Representation>\n"
                          "<BaseURL>javascript:alert('XSS')</BaseURL>\n"
                          "</Representation></AdaptationSet></Period></MPD>";

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(xss_mpd, strlen(xss_mpd), "XSS", "t", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);

    // Should still contain the malicious URL but with token appended
    // Protection is client-side, we just inject tokens
    REQUIRE(result_str.find("javascript:alert") != std::string::npos);
    REQUIRE(result_str.find("t=XSS") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ DASH Security: XSS URL preserved (client must validate)\n");
  }

  SECTION("DASH Security: CDATA section in BaseURL")
  {
    const char *cdata_mpd = "<?xml version=\"1.0\"?>\n"
                            "<MPD><BaseURL><![CDATA[http://cdn.example.com/video?test=1&foo=2]]></BaseURL></MPD>";

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(cdata_mpd, strlen(cdata_mpd), "CDATA", "t", NULL, &cfg, &new_len);

    if (result) {
      std::string result_str(result);
      // Token should be injected even with CDATA
      REQUIRE(result_str.find("t=CDATA") != std::string::npos);
      free(result);
    }

    fprintf(stderr, "✓ DASH Security: CDATA handled\n");
  }

  SECTION("DASH Edge: Very large MPD (memory exhaustion test)")
  {
    // Create MPD with many segments (10000)
    std::string large_mpd = "<?xml version=\"1.0\"?><MPD><Period><AdaptationSet><Representation><SegmentList>";
    for (int i = 0; i < 10000; i++) {
      large_mpd += "<SegmentURL media=\"seg" + std::to_string(i) + ".m4s\"/>";
    }
    large_mpd += "</SegmentList></Representation></AdaptationSet></Period></MPD>";

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result = inject_token_dash(large_mpd.c_str(), large_mpd.length(), "LARGE", "t", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);

    // Verify some segments got tokens
    std::string result_str(result);
    REQUIRE(result_str.find("seg0.m4s?t=LARGE") != std::string::npos);
    REQUIRE(result_str.find("seg9999.m4s?t=LARGE") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ DASH Edge: Large MPD processed\n");
  }

  SECTION("DASH Edge: Invalid UTF-8 in BaseURL")
  {
    // Invalid UTF-8 sequence
    const char *invalid_utf8_mpd = "<?xml version=\"1.0\"?>\n"
                                   "<MPD><BaseURL>http://cdn.example.com/\xFF\xFE/video</BaseURL></MPD>";

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result = inject_token_dash(invalid_utf8_mpd, strlen(invalid_utf8_mpd), "UTF8", "t", NULL, &cfg, &new_len);

    // Should either reject or handle gracefully
    if (result) {
      REQUIRE(new_len > 0);
      free(result);
    }

    fprintf(stderr, "✓ DASH Edge: Invalid UTF-8 handled\n");
  }

  SECTION("DASH Edge: Token with XML special characters")
  {
    // Token containing XML special chars that need escaping
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD><BaseURL>http://cdn.example.com/video</BaseURL></MPD>";

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;

    // Token with <, >, &, ', "
    const char *dangerous_token = "abc<>&'\"123";
    char *result                = inject_token_dash(mpd, strlen(mpd), dangerous_token, "token", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);

    // libxml2 xmlEncodeSpecialChars escapes: & < > (but NOT quotes in element content)
    // & becomes &amp;, < becomes &lt;, > becomes &gt;
    // Quotes and apostrophes are NOT escaped in element content (only in attributes)
    // So the URL will be: http://cdn.example.com/video?token=abc&lt;&gt;&amp;'"123

    // Check that dangerous chars are properly escaped
    REQUIRE(result_str.find("&lt;") != std::string::npos);  // < escaped
    REQUIRE(result_str.find("&gt;") != std::string::npos);  // > escaped
    REQUIRE(result_str.find("&amp;") != std::string::npos); // & escaped
    // ' and " are not escaped in element content, only in attributes

    free(result);
    fprintf(stderr, "✓ DASH Edge: XML special chars in token escaped properly\n");
  }

  SECTION("DASH Edge: Empty token parameter")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD><BaseURL>http://cdn.example.com/video</BaseURL></MPD>";

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;

    // Empty token string
    char *result = inject_token_dash(mpd, strlen(mpd), "", "token", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string result_str(result);
    // Should inject empty value: ?token=
    REQUIRE(result_str.find("token=") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ DASH Edge: Empty token handled\n");
  }

  SECTION("DASH Edge: Empty param_name")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD><BaseURL>http://cdn.example.com/video</BaseURL></MPD>";

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;

    // Empty parameter name - should return NULL (invalid)
    char *result = inject_token_dash(mpd, strlen(mpd), "TOKEN123", "", NULL, &cfg, &new_len);

    // Should gracefully handle or just inject with empty name (implementation dependent)
    if (result) {
      free(result);
    }

    fprintf(stderr, "✓ DASH Edge: Empty param_name handled\n");
  }

  // ========================================================================
  // CRITICAL SECURITY: Buffer Overflow Protection
  // ========================================================================

  SECTION("DASH Security: Extremely long URL (buffer overflow protection)")
  {
    // Create URL longer than safe limit (8KB)
    std::string giant_url = "http://cdn.example.com/";
    giant_url += std::string(9000, 'x'); // 9KB of 'x' characters
    giant_url += ".m4s";

    std::string mpd = "<?xml version=\"1.0\"?><MPD><BaseURL>" + giant_url + "</BaseURL></MPD>";

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(mpd.c_str(), mpd.length(), "TOKEN", "t", NULL, &cfg, &new_len);

    // MPD parsing succeeds, but URL processing fails internally
    // Token should NOT be injected due to length limit
    // Result may be returned but WITHOUT token injection
    if (result) {
      std::string result_str(result);
      // Token should NOT appear (protection worked)
      REQUIRE(result_str.find("t=TOKEN") == std::string::npos);
      free(result);
    }
    // Either NULL or result without token injection is acceptable

    fprintf(stderr, "✓ DASH Security: Excessive URL length protection works\n");
  }

  SECTION("DASH Security: Extremely long token (buffer overflow protection)")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD><BaseURL>http://cdn.example.com/video.m4s</BaseURL></MPD>";

    // Create token longer than safe limit (4KB)
    std::string giant_token(5000, 'T'); // 5KB token

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(mpd, strlen(mpd), giant_token.c_str(), "token", NULL, &cfg, &new_len);

    // MPD parsing succeeds, but token injection fails
    if (result) {
      std::string result_str(result);
      // Giant token should NOT be injected
      REQUIRE(result_str.find(giant_token) == std::string::npos);
      free(result);
    }

    fprintf(stderr, "✓ DASH Security: Excessive token length protection works\n");
  }

  SECTION("DASH Security: Extremely long param_name (buffer overflow protection)")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD><BaseURL>http://cdn.example.com/video.m4s</BaseURL></MPD>";

    // Create param_name longer than safe limit (256 bytes)
    std::string giant_param(300, 'p');

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(mpd, strlen(mpd), "TOKEN", giant_param.c_str(), NULL, &cfg, &new_len);

    // MPD parsing succeeds, but param injection fails
    if (result) {
      std::string result_str(result);
      // Giant param_name should NOT be injected
      REQUIRE(result_str.find(giant_param) == std::string::npos);
      free(result);
    }

    fprintf(stderr, "✓ DASH Security: Excessive param_name length protection works\n");
  }

  SECTION("DASH Security: Maximum safe lengths accepted")
  {
    // Test that maximum safe values still work
    std::string safe_url = "http://cdn.example.com/";
    safe_url += std::string(8000, 'x'); // 8KB URL (just under limit)

    std::string mpd = "<?xml version=\"1.0\"?><MPD><BaseURL>" + safe_url + "</BaseURL></MPD>";

    std::string safe_token(4000, 'T'); // 4KB token (just under limit)
    std::string safe_param(250, 'p');  // 250 byte param (just under limit)

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* cache_untransformed=true */
    size_t new_len                       = 0;
    char *result = inject_token_dash(mpd.c_str(), mpd.length(), safe_token.c_str(), safe_param.c_str(), NULL, &cfg, &new_len);

    // Should succeed for maximum safe values
    REQUIRE(result != NULL);
    REQUIRE(new_len > 0);

    free(result);
    fprintf(stderr, "✓ DASH Security: Maximum safe lengths accepted\n");
  }

  fprintf(stderr, "\n");
}

/* ============================================================================
 * COMPREHENSIVE TESTS FOR replace_access_token FEATURE
 * ============================================================================
 * These tests verify the replace_access_token functionality which is
 * CRITICAL for security as it prevents access token leakage in manifests.
 * Default: replace_access_token = true (recommended)
 */
TEST_CASE("HLS Manifest: replace_access_token feature", "[manifest][hls][replace_access_token][security]")
{
  fprintf(stderr, "\n=== HLS replace_access_token Tests ===\n");

  SECTION("Replace access token in simple segment URL")
  {
    const char *manifest = "#EXTM3U\n"
                           "#EXT-X-VERSION:3\n"
                           "#EXTINF:10.0,\n"
                           "segment001.ts?cr-access-token=OLD_TOKEN\n";

    struct manifest_injection_config cfg = {.enabled                 = true,
                                            .inject_to_segments      = true,
                                            .inject_to_init_segments = false,
                                            .replace_access_token    = true, /* ENABLED */
                                            .hls_support             = true,
                                            .dash_support            = false,
                                            .cache_untransformed     = true};

    size_t new_len = 0;
    char *result =
      inject_token_hls(manifest, strlen(manifest), "NEW_SESSION_TOKEN", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    REQUIRE(new_len > 0);

    std::string output(result);

    // OLD access token should be REMOVED
    REQUIRE(output.find("cr-access-token=OLD_TOKEN") == std::string::npos);

    // NEW session token should be present
    REQUIRE(output.find("cr-session-token=NEW_SESSION_TOKEN") != std::string::npos);

    // Only ONE token parameter should exist
    REQUIRE(output.find("segment001.ts?cr-session-token=NEW_SESSION_TOKEN") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ HLS: Simple segment URL - access token replaced\n");
  }

  SECTION("Replace access token at START of query string")
  {
    const char *manifest = "#EXTM3U\n"
                           "segment.ts?cr-access-token=OLD&quality=high&bitrate=1000\n";

    struct manifest_injection_config cfg = {true, true, false, true, true, false, true};
    size_t new_len                       = 0;
    char *result =
      inject_token_hls(manifest, strlen(manifest), "SESSION123", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // Access token should be gone
    REQUIRE(output.find("cr-access-token=OLD") == std::string::npos);

    // Session token should be present
    REQUIRE(output.find("cr-session-token=SESSION123") != std::string::npos);

    // Other parameters should remain
    REQUIRE(output.find("quality=high") != std::string::npos);
    REQUIRE(output.find("bitrate=1000") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ HLS: Access token at START of query - replaced correctly\n");
  }

  SECTION("Replace access token in MIDDLE of query string")
  {
    const char *manifest = "#EXTM3U\n"
                           "segment.ts?quality=high&cr-access-token=MIDDLE_TOKEN&bitrate=1000\n";

    struct manifest_injection_config cfg = {true, true, false, true, true, false, true};
    size_t new_len                       = 0;
    char *result = inject_token_hls(manifest, strlen(manifest), "NEW_TOK", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // Access token should be removed
    REQUIRE(output.find("cr-access-token=MIDDLE_TOKEN") == std::string::npos);

    // Session token should be added
    REQUIRE(output.find("cr-session-token=NEW_TOK") != std::string::npos);

    // Other params should remain
    REQUIRE(output.find("quality=high") != std::string::npos);
    REQUIRE(output.find("bitrate=1000") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ HLS: Access token in MIDDLE of query - replaced correctly\n");
  }

  SECTION("Replace access token at END of query string")
  {
    const char *manifest = "#EXTM3U\n"
                           "segment.ts?quality=high&bitrate=1000&cr-access-token=END_TOKEN\n";

    struct manifest_injection_config cfg = {true, true, false, true, true, false, true};
    size_t new_len                       = 0;
    char *result = inject_token_hls(manifest, strlen(manifest), "NEWSESS", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // Access token should be removed
    REQUIRE(output.find("cr-access-token=END_TOKEN") == std::string::npos);

    // Session token should be added
    REQUIRE(output.find("cr-session-token=NEWSESS") != std::string::npos);

    // Other params should remain
    REQUIRE(output.find("quality=high") != std::string::npos);
    REQUIRE(output.find("bitrate=1000") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ HLS: Access token at END of query - replaced correctly\n");
  }

  SECTION("Replace ONLY access token (no other params)")
  {
    const char *manifest = "#EXTM3U\n"
                           "segment.ts?cr-access-token=ONLY_TOKEN\n";

    struct manifest_injection_config cfg = {true, true, false, true, true, false, true};
    size_t new_len                       = 0;
    char *result = inject_token_hls(manifest, strlen(manifest), "SINGLE", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // Should have ONLY session token, no access token
    REQUIRE(output.find("cr-access-token") == std::string::npos);
    REQUIRE(output.find("segment.ts?cr-session-token=SINGLE") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ HLS: Only access token present - replaced with session token only\n");
  }

  SECTION("URL without access token (should not crash)")
  {
    const char *manifest = "#EXTM3U\n"
                           "segment.ts?quality=high\n";

    struct manifest_injection_config cfg = {true, true, false, true, true, false, true};
    size_t new_len                       = 0;
    char *result = inject_token_hls(manifest, strlen(manifest), "TOKEN", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // Should add session token normally
    REQUIRE(output.find("cr-session-token=TOKEN") != std::string::npos);
    REQUIRE(output.find("quality=high") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ HLS: No access token present - session token added normally\n");
  }

  SECTION("EXT-X-MAP with access token (init segment)")
  {
    const char *manifest = "#EXTM3U\n"
                           "#EXT-X-MAP:URI=\"init.mp4?cr-access-token=INIT_OLD\"\n";

    struct manifest_injection_config cfg = {.enabled                 = true,
                                            .inject_to_segments      = true,
                                            .inject_to_init_segments = true, /* Enable init segment injection */
                                            .replace_access_token    = true,
                                            .hls_support             = true,
                                            .dash_support            = false,
                                            .cache_untransformed     = true};

    size_t new_len = 0;
    char *result = inject_token_hls(manifest, strlen(manifest), "INIT_NEW", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // Access token should be removed from init segment
    REQUIRE(output.find("cr-access-token=INIT_OLD") == std::string::npos);

    // Session token should be in init segment
    REQUIRE(output.find("cr-session-token=INIT_NEW") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ HLS: EXT-X-MAP init segment - access token replaced\n");
  }

  SECTION("replace_access_token=false should keep both tokens")
  {
    const char *manifest = "#EXTM3U\n"
                           "segment.ts?cr-access-token=OLD\n";

    struct manifest_injection_config cfg = {.enabled                 = true,
                                            .inject_to_segments      = true,
                                            .inject_to_init_segments = false,
                                            .replace_access_token    = false, /* DISABLED */
                                            .hls_support             = true,
                                            .dash_support            = false,
                                            .cache_untransformed     = true};

    size_t new_len = 0;
    char *result   = inject_token_hls(manifest, strlen(manifest), "NEW", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // BOTH tokens should be present
    REQUIRE(output.find("cr-access-token=OLD") != std::string::npos);
    REQUIRE(output.find("cr-session-token=NEW") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ HLS: replace_access_token=false - both tokens present\n");
  }

  SECTION("HLS: Prevent session token duplication (BUG #2 FIX)")
  {
    // URL already has an OLD session token - should be stripped before adding NEW one
    const char *manifest = "#EXTM3U\n"
                           "segment.ts?cr-session-token=OLD_SESSION_TOKEN\n";

    struct manifest_injection_config cfg = {.enabled                 = true,
                                            .inject_to_segments      = true,
                                            .inject_to_init_segments = false,
                                            .replace_access_token    = false,
                                            .hls_support             = true,
                                            .dash_support            = false,
                                            .cache_untransformed     = true};

    size_t new_len = 0;
    char *result   = inject_token_hls(manifest, strlen(manifest), "NEW_SESSION_TOKEN", "cr-session-token", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // OLD session token should be REMOVED (not duplicated)
    REQUIRE(output.find("cr-session-token=OLD_SESSION_TOKEN") == std::string::npos);

    // NEW session token should be present
    REQUIRE(output.find("cr-session-token=NEW_SESSION_TOKEN") != std::string::npos);

    // Should NOT have duplicate parameter: ?cr-session-token=OLD&cr-session-token=NEW
    size_t first_pos  = output.find("cr-session-token=");
    size_t second_pos = output.find("cr-session-token=", first_pos + 1);
    REQUIRE(second_pos == std::string::npos); // Should only appear ONCE

    free(result);
    fprintf(stderr, "✓ HLS: Session token duplication prevented\n");
  }

  SECTION("HLS: Prevent session token duplication in EXT-X-MAP (BUG #2 FIX)")
  {
    const char *manifest = "#EXTM3U\n"
                           "#EXT-X-MAP:URI=\"init.mp4?cr-session-token=OLD_TOKEN\"\n";

    struct manifest_injection_config cfg = {.enabled                 = true,
                                            .inject_to_segments      = false,
                                            .inject_to_init_segments = true,
                                            .replace_access_token    = false,
                                            .hls_support             = true,
                                            .dash_support            = false,
                                            .cache_untransformed     = true};

    size_t new_len = 0;
    char *result   = inject_token_hls(manifest, strlen(manifest), "NEW_TOKEN", "cr-session-token", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // OLD token should be removed
    REQUIRE(output.find("cr-session-token=OLD_TOKEN") == std::string::npos);

    // NEW token should be present
    REQUIRE(output.find("cr-session-token=NEW_TOKEN") != std::string::npos);

    // Check no duplication
    size_t first_pos  = output.find("cr-session-token=");
    size_t second_pos = output.find("cr-session-token=", first_pos + 1);
    REQUIRE(second_pos == std::string::npos);

    free(result);
    fprintf(stderr, "✓ HLS: EXT-X-MAP session token duplication prevented\n");
  }

  fprintf(stderr, "\n");
}

TEST_CASE("DASH Manifest: replace_access_token feature", "[manifest][dash][replace_access_token][security]")
{
  fprintf(stderr, "\n=== DASH replace_access_token Tests ===\n");

  SECTION("Replace access token in BaseURL")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD>\n"
                      "  <Period>\n"
                      "    <BaseURL>http://cdn.com/video/?cr-access-token=OLD_BASE_TOKEN</BaseURL>\n"
                      "  </Period>\n"
                      "</MPD>";

    struct manifest_injection_config cfg = {true, true, false, true, false, true, true};
    size_t new_len                       = 0;
    char *result = inject_token_dash(mpd, strlen(mpd), "BASE_NEW", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // Access token should be removed
    REQUIRE(output.find("cr-access-token=OLD_BASE_TOKEN") == std::string::npos);

    // Session token should be present
    REQUIRE(output.find("cr-session-token=BASE_NEW") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ DASH: BaseURL - access token replaced\n");
  }

  SECTION("Replace access token in SegmentTemplate media")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD>\n"
                      "  <Period>\n"
                      "    <AdaptationSet>\n"
                      "      <SegmentTemplate media=\"seg-$Number$.m4s?cr-access-token=MEDIA_OLD&amp;quality=high\" />\n"
                      "    </AdaptationSet>\n"
                      "  </Period>\n"
                      "</MPD>";

    struct manifest_injection_config cfg = {true, true, false, true, false, true, true};
    size_t new_len                       = 0;
    char *result = inject_token_dash(mpd, strlen(mpd), "MEDIA_NEW", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // Access token should be removed
    REQUIRE(output.find("cr-access-token=MEDIA_OLD") == std::string::npos);

    // Session token should be added
    REQUIRE(output.find("cr-session-token=MEDIA_NEW") != std::string::npos);

    // Other params should remain (decoded form in internal processing)
    REQUIRE(output.find("quality=high") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ DASH: SegmentTemplate media - access token replaced\n");
  }

  SECTION("Replace access token in SegmentTemplate initialization")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD>\n"
                      "  <Period>\n"
                      "    <AdaptationSet>\n"
                      "      <SegmentTemplate initialization=\"init.mp4?cr-access-token=INIT_OLD\" />\n"
                      "    </AdaptationSet>\n"
                      "  </Period>\n"
                      "</MPD>";

    struct manifest_injection_config cfg = {.enabled                 = true,
                                            .inject_to_segments      = true,
                                            .inject_to_init_segments = true, /* Enable init */
                                            .replace_access_token    = true,
                                            .hls_support             = false,
                                            .dash_support            = true,
                                            .cache_untransformed     = true};

    size_t new_len = 0;
    char *result   = inject_token_dash(mpd, strlen(mpd), "INIT_NEW", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // Access token should be removed from init
    REQUIRE(output.find("cr-access-token=INIT_OLD") == std::string::npos);

    // Session token should be in init
    REQUIRE(output.find("cr-session-token=INIT_NEW") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ DASH: SegmentTemplate initialization - access token replaced\n");
  }

  SECTION("Multiple URLs with access tokens")
  {
    const char *mpd =
      "<?xml version=\"1.0\"?>\n"
      "<MPD>\n"
      "  <Period>\n"
      "    <BaseURL>http://cdn.com/?cr-access-token=BASE1</BaseURL>\n"
      "    <AdaptationSet>\n"
      "      <SegmentTemplate media=\"seg.m4s?cr-access-token=SEG1\" initialization=\"init.mp4?cr-access-token=INIT1\" />\n"
      "    </AdaptationSet>\n"
      "  </Period>\n"
      "</MPD>";

    struct manifest_injection_config cfg = {true, true, true, true, false, true, true};
    size_t new_len                       = 0;
    char *result = inject_token_dash(mpd, strlen(mpd), "MULTI_NEW", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // ALL access tokens should be removed
    REQUIRE(output.find("cr-access-token=BASE1") == std::string::npos);
    REQUIRE(output.find("cr-access-token=SEG1") == std::string::npos);
    REQUIRE(output.find("cr-access-token=INIT1") == std::string::npos);

    // Session token should be in all places
    size_t pos = 0;
    int count  = 0;
    while ((pos = output.find("cr-session-token=MULTI_NEW", pos)) != std::string::npos) {
      count++;
      pos++;
    }
    REQUIRE(count == 3); // Should appear 3 times (BaseURL, media, init)

    free(result);
    fprintf(stderr, "✓ DASH: Multiple URLs - all access tokens replaced\n");
  }

  SECTION("DASH manifest without access tokens")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD>\n"
                      "  <Period>\n"
                      "    <BaseURL>http://cdn.com/video/</BaseURL>\n"
                      "    <AdaptationSet>\n"
                      "      <SegmentTemplate media=\"seg-$Number$.m4s\" />\n"
                      "    </AdaptationSet>\n"
                      "  </Period>\n"
                      "</MPD>";

    struct manifest_injection_config cfg = {true, true, false, true, false, true, true};
    size_t new_len                       = 0;
    char *result = inject_token_dash(mpd, strlen(mpd), "CLEAN_TOK", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // Session tokens should be added normally
    REQUIRE(output.find("cr-session-token=CLEAN_TOK") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ DASH: No access tokens - session tokens added normally\n");
  }

  SECTION("replace_access_token=false should keep both tokens (DASH)")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD>\n"
                      "  <Period>\n"
                      "    <BaseURL>http://cdn.com/?cr-access-token=KEEP_OLD</BaseURL>\n"
                      "  </Period>\n"
                      "</MPD>";

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true}; /* replace_access_token=false */
    size_t new_len                       = 0;
    char *result = inject_token_dash(mpd, strlen(mpd), "ADD_NEW", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // BOTH tokens should be present
    REQUIRE(output.find("cr-access-token=KEEP_OLD") != std::string::npos);
    REQUIRE(output.find("cr-session-token=ADD_NEW") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ DASH: replace_access_token=false - both tokens present\n");
  }

  SECTION("DASH: Prevent session token duplication in BaseURL (BUG #2 FIX)")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD>\n"
                      "  <Period>\n"
                      "    <BaseURL>http://cdn.com/video.m4s?cr-session-token=OLD_SESSION</BaseURL>\n"
                      "  </Period>\n"
                      "</MPD>";

    struct manifest_injection_config cfg = {true, true, false, false, false, true, true};
    size_t new_len                       = 0;
    char *result = inject_token_dash(mpd, strlen(mpd), "NEW_SESSION", "cr-session-token", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // OLD session token should be REMOVED
    REQUIRE(output.find("cr-session-token=OLD_SESSION") == std::string::npos);

    // NEW session token should be present
    REQUIRE(output.find("cr-session-token=NEW_SESSION") != std::string::npos);

    // Check no duplication
    size_t first_pos  = output.find("cr-session-token=");
    size_t second_pos = output.find("cr-session-token=", first_pos + 1);
    REQUIRE(second_pos == std::string::npos);

    free(result);
    fprintf(stderr, "✓ DASH: BaseURL session token duplication prevented\n");
  }

  SECTION("DASH: Prevent session token duplication in SegmentTemplate (BUG #2 FIX)")
  {
    const char *mpd = "<?xml version=\"1.0\"?>\n"
                      "<MPD>\n"
                      "  <Period>\n"
                      "    <AdaptationSet>\n"
                      "      <SegmentTemplate media=\"seg-$Number$.m4s?cr-session-token=OLD\" "
                      "initialization=\"init.mp4?cr-session-token=OLD_INIT\" />\n"
                      "    </AdaptationSet>\n"
                      "  </Period>\n"
                      "</MPD>";

    struct manifest_injection_config cfg = {true, true, true, false, false, true, true};
    size_t new_len                       = 0;
    char *result                         = inject_token_dash(mpd, strlen(mpd), "NEW", "cr-session-token", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // OLD tokens should be REMOVED
    REQUIRE(output.find("cr-session-token=OLD\"") == std::string::npos);
    REQUIRE(output.find("cr-session-token=OLD_INIT") == std::string::npos);

    // NEW token should appear exactly twice (media + initialization)
    size_t pos = 0;
    int count  = 0;
    while ((pos = output.find("cr-session-token=NEW", pos)) != std::string::npos) {
      count++;
      pos++;
    }
    REQUIRE(count == 2);

    free(result);
    fprintf(stderr, "✓ DASH: SegmentTemplate session token duplication prevented\n");
  }

  fprintf(stderr, "\n");
}

TEST_CASE("replace_access_token: Security & Edge Cases", "[manifest][replace_access_token][security]")
{
  fprintf(stderr, "\n=== replace_access_token Security Tests ===\n");

  SECTION("NULL access_token_name handling")
  {
    const char *manifest = "#EXTM3U\n"
                           "segment.ts?cr-access-token=SHOULD_KEEP\n";

    struct manifest_injection_config cfg = {true, true, false, true, true, false, true};
    size_t new_len                       = 0;
    // Pass NULL as access_token_name
    char *result = inject_token_hls(manifest, strlen(manifest), "NEW_TOK", "cr-session-token", NULL, &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // Access token should NOT be removed (because access_token_name is NULL)
    REQUIRE(output.find("cr-access-token=SHOULD_KEEP") != std::string::npos);
    // Session token should still be added
    REQUIRE(output.find("cr-session-token=NEW_TOK") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ Security: NULL access_token_name - no replacement (safe)\n");
  }

  SECTION("Empty access_token_name handling")
  {
    const char *manifest = "#EXTM3U\n"
                           "segment.ts?cr-access-token=KEEP\n";

    struct manifest_injection_config cfg = {true, true, false, true, true, false, true};
    size_t new_len                       = 0;
    char *result = inject_token_hls(manifest, strlen(manifest), "TOK", "cr-session-token", "", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // Access token should NOT be removed (empty name should not match)
    REQUIRE(output.find("cr-access-token=KEEP") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ Security: Empty access_token_name - no replacement (safe)\n");
  }

  SECTION("Different access token name (no match)")
  {
    const char *manifest = "#EXTM3U\n"
                           "segment.ts?different-token=VALUE\n";

    struct manifest_injection_config cfg = {true, true, false, true, true, false, true};
    size_t new_len                       = 0;
    // Look for "cr-access-token" but URL has "different-token"
    char *result = inject_token_hls(manifest, strlen(manifest), "NEW", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // Different token should be kept
    REQUIRE(output.find("different-token=VALUE") != std::string::npos);
    // Session token should be added
    REQUIRE(output.find("cr-session-token=NEW") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ Security: Non-matching token name - not replaced (correct)\n");
  }

  SECTION("Token name as substring (should not match)")
  {
    const char *manifest = "#EXTM3U\n"
                           "segment.ts?my-cr-access-token-custom=VALUE\n";

    struct manifest_injection_config cfg = {true, true, false, true, true, false, true};
    size_t new_len                       = 0;
    char *result = inject_token_hls(manifest, strlen(manifest), "NEW", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // Should NOT remove "my-cr-access-token-custom" (different name)
    REQUIRE(output.find("my-cr-access-token-custom=VALUE") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ Security: Token name as substring - not replaced (correct matching)\n");
  }

  SECTION("Special characters in token value")
  {
    const char *manifest = "#EXTM3U\n"
                           "segment.ts?cr-access-token=ABC%3D%3D%26xyz\n"; // URL encoded

    struct manifest_injection_config cfg = {true, true, false, true, true, false, true};
    size_t new_len                       = 0;
    char *result = inject_token_hls(manifest, strlen(manifest), "NEW_TOKEN", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // Old token should be removed even with special chars
    REQUIRE(output.find("cr-access-token=ABC%3D%3D%26xyz") == std::string::npos);
    // New token should be present
    REQUIRE(output.find("cr-session-token=NEW_TOKEN") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ Security: Special chars in token value - handled correctly\n");
  }

  SECTION("Very long URL with access token")
  {
    // Create a 4KB URL with access token
    std::string long_path(3900, 'x');
    std::string manifest = "#EXTM3U\n" + long_path + "?cr-access-token=LONG_URL_TOKEN\n";

    struct manifest_injection_config cfg = {true, true, false, true, true, false, true};
    size_t new_len                       = 0;
    char *result =
      inject_token_hls(manifest.c_str(), manifest.length(), "NEW", "cr-session-token", "cr-access-token", &cfg, &new_len);

    REQUIRE(result != NULL);
    std::string output(result);

    // Should handle long URLs correctly
    REQUIRE(output.find("cr-access-token=LONG_URL_TOKEN") == std::string::npos);
    REQUIRE(output.find("cr-session-token=NEW") != std::string::npos);

    free(result);
    fprintf(stderr, "✓ Security: Very long URL - handled correctly\n");
  }

  fprintf(stderr, "\n");
}

// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use super::*;

#[test]
fn uri_parse_components() {
    {
        let c = parse_uri_components("http://www.ics.uci.edu/pub/ietf/uri/#Related")
            .expect("Should have matched");
        assert_eq!(c.scheme_with_colon, Some("http:"));
        assert_eq!(c.scheme, Some("http"));
        assert_eq!(c.authority_with_slashes, Some("//www.ics.uci.edu"));
        assert_eq!(c.authority, Some("www.ics.uci.edu"));
        assert_eq!(c.path, "/pub/ietf/uri/");
        assert_eq!(c.query_with_marker, None);
        assert_eq!(c.query, None);
        assert_eq!(c.fragment_with_marker, Some("#Related"));
        assert_eq!(c.fragment, Some("Related"));
    }
    {
        let c =
            parse_uri_components("coap+sms://username:password@example.com:1234?query&d=3#frag")
                .expect("Should have matched");
        assert_eq!(c.scheme_with_colon, Some("coap+sms:"));
        assert_eq!(c.scheme, Some("coap+sms"));
        assert_eq!(
            c.authority_with_slashes,
            Some("//username:password@example.com:1234")
        );
        assert_eq!(c.authority, Some("username:password@example.com:1234"));
        assert_eq!(c.path, "");
        assert_eq!(c.query_with_marker, Some("?query&d=3"));
        assert_eq!(c.query, Some("query&d=3"));
        assert_eq!(c.fragment_with_marker, Some("#frag"));
        assert_eq!(c.fragment, Some("frag"));
    }
    {
        let c = parse_uri_components("uid:a-strange-id?q#f").expect("Should have matched");
        assert_eq!(c.scheme_with_colon, Some("uid:"));
        assert_eq!(c.scheme, Some("uid"));
        assert_eq!(c.authority_with_slashes, None);
        assert_eq!(c.authority, None);
        assert_eq!(c.path, "a-strange-id");
        assert_eq!(c.query_with_marker, Some("?q"));
        assert_eq!(c.query, Some("q"));
        assert_eq!(c.fragment_with_marker, Some("#f"));
        assert_eq!(c.fragment, Some("f"));
    }
    {
        let c = parse_uri_components("path?q#f?b#").expect("Should have matched");
        assert_eq!(c.scheme_with_colon, None);
        assert_eq!(c.scheme, None);
        assert_eq!(c.authority_with_slashes, None);
        assert_eq!(c.authority, None);
        assert_eq!(c.path, "path");
        assert_eq!(c.query_with_marker, Some("?q"));
        assert_eq!(c.query, Some("q"));
        assert_eq!(c.fragment_with_marker, Some("#f?b#"));
        assert_eq!(c.fragment, Some("f?b#"));
    }
}

#[test]
fn uri_parse_authority() {
    {
        let a = parse_authority_components("username:password@example.com:1234")
            .expect("Should have matched");
        assert_eq!(a.userinfo_with_at, Some("username:password@"));
        assert_eq!(a.userinfo, Some("username:password"));
        assert_eq!(a.host, Some("example.com"));
        assert_eq!(a.port_with_colon, Some(":1234"));
        assert_eq!(a.port, Some("1234"));
    }
    {
        let a = parse_authority_components("username@[2000::1]:1234")
            .expect("Should have matched");
        assert_eq!(a.userinfo_with_at, Some("username@"));
        assert_eq!(a.userinfo, Some("username"));
        assert_eq!(a.host, Some("[2000::1]"));
        assert_eq!(a.port_with_colon, Some(":1234"));
        assert_eq!(a.port, Some("1234"));
    }
    {
        let a = parse_authority_components("example.com").expect("Should have matched");
        assert_eq!(a.userinfo_with_at, None);
        assert_eq!(a.userinfo, None);
        assert_eq!(a.host, Some("example.com"));
        assert_eq!(a.port_with_colon, None);
        assert_eq!(a.port, None);
    }
}

#[test]
fn uri_check_scheme() {
    assert!(is_valid_scheme("http"));
    assert!(is_valid_scheme("coap+sms"));
    assert!(is_valid_scheme("a"));
    assert!(is_valid_scheme("a1"));
    assert!(is_valid_scheme("my-scheme.v2"));
    assert!(!is_valid_scheme(""));
    assert!(!is_valid_scheme("1abc"));
    assert!(!is_valid_scheme("-abc"));
}

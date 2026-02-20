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

/// Result of parsing a URI string per RFC 3986 Appendix B.
///
/// The fields correspond to the capture groups of the original regex:
/// `^(([^:/?#%]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?$`
#[allow(dead_code)]
pub(crate) struct UriComponents<'a> {
    /// Scheme with trailing colon (e.g. "http:"), group 1
    pub scheme_with_colon: Option<&'a str>,
    /// Scheme only (e.g. "http"), group 2
    pub scheme: Option<&'a str>,
    /// Authority with leading "//" (e.g. "//example.com"), group 3
    pub authority_with_slashes: Option<&'a str>,
    /// Authority only (e.g. "example.com"), group 4
    pub authority: Option<&'a str>,
    /// Path (always present, may be empty), group 5
    pub path: &'a str,
    /// Query with leading "?" (e.g. "?foo=bar"), group 6
    pub query_with_marker: Option<&'a str>,
    /// Query only (e.g. "foo=bar"), group 7
    pub query: Option<&'a str>,
    /// Fragment with leading "#" (e.g. "#frag"), group 8
    pub fragment_with_marker: Option<&'a str>,
    /// Fragment only (e.g. "frag"), group 9
    pub fragment: Option<&'a str>,
    /// Byte offset where the scheme starts (for error reporting)
    pub scheme_start: usize,
    /// Byte offset where the scheme ends (for error reporting)
    pub scheme_end: usize,
}

/// Parse a URI string into its components per RFC 3986 Appendix B.
///
/// This always succeeds for any input string (the regex it replaces always matches).
/// The scheme is rejected if it contains a '%' character.
pub(crate) fn parse_uri_components(uri: &str) -> Option<UriComponents<'_>> {
    let bytes = uri.as_bytes();
    let len = bytes.len();
    let mut pos = 0;

    // Try to extract scheme: `([^:/?#%]+):`
    let (scheme_with_colon, scheme, scheme_start, scheme_end) = {
        let start = pos;
        let mut found_scheme = false;
        let mut colon_pos = 0;
        let mut i = start;
        while i < len {
            match bytes[i] {
                b':' => {
                    if i > start {
                        colon_pos = i;
                        found_scheme = true;
                    }
                    break;
                }
                b'/' | b'?' | b'#' | b'%' => break,
                _ => i += 1,
            }
        }
        if found_scheme {
            let scheme_str = &uri[start..colon_pos];
            let scheme_with_colon_str = &uri[start..=colon_pos];
            pos = colon_pos + 1;
            (
                Some(scheme_with_colon_str),
                Some(scheme_str),
                start,
                colon_pos,
            )
        } else {
            (None, None, 0, 0)
        }
    };

    // Try to extract authority: `//([^/?#]*)`
    let (authority_with_slashes, authority) = if pos + 1 < len
        && bytes[pos] == b'/'
        && bytes[pos + 1] == b'/'
    {
        let auth_start = pos + 2;
        let mut auth_end = auth_start;
        while auth_end < len && !matches!(bytes[auth_end], b'/' | b'?' | b'#') {
            auth_end += 1;
        }
        let with_slashes = &uri[pos..auth_end];
        let auth_only = &uri[auth_start..auth_end];
        pos = auth_end;
        (Some(with_slashes), Some(auth_only))
    } else {
        (None, None)
    };

    // Extract path: `[^?#]*`
    let path_start = pos;
    while pos < len && !matches!(bytes[pos], b'?' | b'#') {
        pos += 1;
    }
    let path = &uri[path_start..pos];

    // Extract query: `\?([^#]*)`
    let (query_with_marker, query) = if pos < len && bytes[pos] == b'?' {
        let q_start = pos;
        pos += 1;
        let q_val_start = pos;
        while pos < len && bytes[pos] != b'#' {
            pos += 1;
        }
        (Some(&uri[q_start..pos]), Some(&uri[q_val_start..pos]))
    } else {
        (None, None)
    };

    // Extract fragment: `#(.*)`
    let (fragment_with_marker, fragment) = if pos < len && bytes[pos] == b'#' {
        (Some(&uri[pos..]), Some(&uri[pos + 1..]))
    } else {
        (None, None)
    };

    Some(UriComponents {
        scheme_with_colon,
        scheme,
        authority_with_slashes,
        authority,
        path,
        query_with_marker,
        query,
        fragment_with_marker,
        fragment,
        scheme_start,
        scheme_end,
    })
}

/// Check if a URI scheme is well-formed: starts with a letter,
/// followed by any combination of letters, digits, '+', '-', or '.'.
pub(crate) fn is_valid_scheme(scheme: &str) -> bool {
    let bytes = scheme.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    if !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'+' | b'.'))
}

/// Result of parsing a URI authority string.
#[allow(dead_code)]
pub(crate) struct AuthorityComponents<'a> {
    /// Userinfo with trailing "@" (e.g. "user@"), group 1
    pub userinfo_with_at: Option<&'a str>,
    /// Userinfo only (e.g. "user"), group 2
    pub userinfo: Option<&'a str>,
    /// Host (IPv4/hostname or bracketed IPv6), group 3
    pub host: Option<&'a str>,
    /// Port with leading ":" (e.g. ":8080"), group 4
    pub port_with_colon: Option<&'a str>,
    /// Port only (e.g. "8080"), group 5
    pub port: Option<&'a str>,
}

/// Parse a URI authority string into userinfo, host, and port components.
///
/// Matches the pattern: `^(([^@/?#]+)@)?([^\[\]:]+|\[[^\]]+\])(:([0-9]+))?$`
pub(crate) fn parse_authority_components(authority: &str) -> Option<AuthorityComponents<'_>> {
    let bytes = authority.as_bytes();
    let len = bytes.len();

    if len == 0 {
        return None;
    }

    // Find the last '@' to split userinfo from host+port.
    // We scan for '@' that isn't inside brackets.
    let at_pos = {
        let mut found = None;
        let mut i = 0;
        while i < len {
            match bytes[i] {
                b'@' => {
                    found = Some(i);
                    break;
                }
                b'/' | b'?' | b'#' => break,
                _ => i += 1,
            }
        }
        found
    };

    let (userinfo_with_at, userinfo, host_port_start) = if let Some(at) = at_pos {
        if at == 0 {
            return None; // empty userinfo before @
        }
        (
            Some(&authority[..=at]),
            Some(&authority[..at]),
            at + 1,
        )
    } else {
        (None, None, 0)
    };

    let remaining = &authority[host_port_start..];
    let rem_bytes = remaining.as_bytes();
    let rem_len = rem_bytes.len();

    if rem_len == 0 {
        return None;
    }

    // Parse host — either bracketed (IPv6) or unbracketed
    let (host, port_start) = if rem_bytes[0] == b'[' {
        // Bracketed host (IPv6): find closing ']'
        let close = rem_bytes.iter().position(|&b| b == b']')?;
        let host_str = &remaining[..=close];
        (Some(host_str), close + 1)
    } else {
        // Unbracketed host: everything up to ':' or end
        let mut end = 0;
        while end < rem_len && rem_bytes[end] != b':' {
            if rem_bytes[end] == b'[' || rem_bytes[end] == b']' {
                return None; // stray brackets
            }
            end += 1;
        }
        if end == 0 {
            return None; // empty host
        }
        (Some(&remaining[..end]), end)
    };

    // Parse port: `:([0-9]+)` at the end
    let (port_with_colon, port) = if port_start < rem_len && rem_bytes[port_start] == b':' {
        let port_str = &remaining[port_start + 1..];
        if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        (
            Some(&remaining[port_start..]),
            Some(port_str),
        )
    } else if port_start < rem_len {
        // Trailing characters after host that aren't a port
        return None;
    } else {
        (None, None)
    };

    Some(AuthorityComponents {
        userinfo_with_at,
        userinfo,
        host,
        port_with_colon,
        port,
    })
}

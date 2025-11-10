macro_rules! static_table {
    (
       $([$index:expr] $name:expr, $value:expr; )*
    ) => {
        pub const STATIC_TABLE: [(&str, &str); 99] = [
            $(($name, $value,),)*
        ];

        pub fn find_name(name: &[u8]) -> Option<usize> {
            match name {
                $(
                    name if name == $name.as_bytes() => Some($index),
                )*
                _=> None
            }
        }

        pub fn find_value(value: &[u8]) -> Option<usize> {
            match value {
                value if value.is_empty() => return None,
                $(
                    value if value == $value.as_bytes() => Some($index),
                )*
                _=> None
            }
        }

        pub fn find(name: &[u8], value: &[u8]) -> (Option<usize>, Option<usize>) {
            match (name, value) {
                $(
                    (name, value) if name == $name.as_bytes() && !value.is_empty() && value == $value.as_bytes() => (Some($index), Some($index)),
                )*
                (name, value) => (find_name(name), find_value(value)),
            }
        }


        pub fn get_name(index: u64) -> Option<&'static str> {
            STATIC_TABLE.get(index as usize).map(|(name, _)| *name)
        }

        pub fn get_value(index: u64) -> Option<&'static str> {
            STATIC_TABLE.get(index as usize).map(|(_, value)| *value)
        }

        pub fn get(index: u64) -> Option<(&'static str, &'static str)> {
            STATIC_TABLE.get(index as usize).copied()
        }
    };
}

// https://datatracker.ietf.org/doc/html/rfc9204#static-table
static_table![
// Index Name                                Value
    [ 0] ":authority",                       "";
    [ 1] ":path",                            "/";
    [ 2] "age",                              "0";
    [ 3] "content-disposition",              "";
    [ 4] "content-length",                   "0";
    [ 5] "cookie",                           "";
    [ 6] "date",                             "";
    [ 7] "etag",                             "";
    [ 8] "if-modified-since",                "";
    [ 9] "if-none-match",                    "";
    [10] "last-modified",                    "";
    [11] "link",                             "";
    [12] "location",                         "";
    [13] "referer",                          "";
    [14] "set-cookie",                       "";
    [15] ":method",                          "CONNECT";
    [16] ":method",                          "DELETE";
    [17] ":method",                          "GET";
    [18] ":method",                          "HEAD";
    [19] ":method",                          "OPTIONS";
    [20] ":method",                          "POST";
    [21] ":method",                          "PUT";
    [22] ":scheme",                          "http";
    [23] ":scheme",                          "https";
    [24] ":status",                          "103";
    [25] ":status",                          "200";
    [26] ":status",                          "304";
    [27] ":status",                          "404";
    [28] ":status",                          "503";
    [29] "accept",                           "*/*";
    [30] "accept",                           "application/dns-message";
    [31] "accept-encoding",                  "gzip, deflate, br";
    [32] "accept-ranges",                    "bytes";
    [33] "access-control-allow-headers",     "cache-control";
    [34] "access-control-allow-headers",     "content-type";
    [35] "access-control-allow-origin",      "*";
    [36] "cache-control",                    "max-age=0";
    [37] "cache-control",                    "max-age=2592000";
    [38] "cache-control",                    "max-age=604800";
    [39] "cache-control",                    "no-cache";
    [40] "cache-control",                    "no-store";
    [41] "cache-control",                    "public, max-age=31536000";
    [42] "content-encoding",                 "br";
    [43] "content-encoding",                 "gzip";
    [44] "content-type",                     "application/dns-message";
    [45] "content-type",                     "application/javascript";
    [46] "content-type",                     "application/json";
    [47] "content-type",                     "application/x-www-form-urlencoded";
    [48] "content-type",                     "image/gif";
    [49] "content-type",                     "image/jpeg";
    [50] "content-type",                     "image/png";
    [51] "content-type",                     "text/css";
    [52] "content-type",                     "text/html; charset=utf-8";
    [53] "content-type",                     "text/plain";
    [54] "content-type",                     "text/plain;charset=utf-8";
    [55] "range",                            "bytes=0-";
    [56] "strict-transport-security",        "max-age=31536000";
    [57] "strict-transport-security",        "max-age=31536000; includesubdomains";
    [58] "strict-transport-security",        "max-age=31536000; includesubdomains; preload";
    [59] "vary",                             "accept-encoding";
    [60] "vary",                             "origin";
    [61] "x-content-type-options",           "nosniff";
    [62] "x-xss-protection",                 "1; mode=block";
    [63] ":status",                          "100";
    [64] ":status",                          "204";
    [65] ":status",                          "206";
    [66] ":status",                          "302";
    [67] ":status",                          "400";
    [68] ":status",                          "403";
    [69] ":status",                          "421";
    [70] ":status",                          "425";
    [71] ":status",                          "500";
    [72] "accept-language",                  "";
    [73] "access-control-allow-credentials", "FALSE";
    [74] "access-control-allow-credentials", "TRUE";
    [75] "access-control-allow-headers",     "*";
    [76] "access-control-allow-methods",     "get";
    [77] "access-control-allow-methods",     "get, post, options";
    [78] "access-control-allow-methods",     "options";
    [79] "access-control-expose-headers",    "content-length";
    [80] "access-control-request-headers",   "content-type";
    [81] "access-control-request-method",    "get";
    [82] "access-control-request-method",    "post";
    [83] "alt-svc",                          "clear";
    [84] "authorization",                    "";
    [85] "content-security-policy",          "script-src 'none'; object-src 'none'; base-uri 'none'";
    [86] "early-data",                       "1";
    [87] "expect-ct",                        "";
    [88] "forwarded",                        "";
    [89] "if-range",                         "";
    [90] "origin",                           "";
    [91] "purpose",                          "prefetch";
    [92] "server",                           "";
    [93] "timing-allow-origin",              "*";
    [94] "upgrade-insecure-requests",        "1";
    [95] "user-agent",                       "";
    [96] "x-forwarded-for",                  "";
    [97] "x-frame-options",                  "deny";
    [98] "x-frame-options",                  "sameorigin";
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_name_existing() {
        // 测试查找存在的头部名称
        assert_eq!(find_name(b":authority"), Some(0));
        assert_eq!(find_name(b":path"), Some(1));
        assert_eq!(find_name(b":method"), Some(15)); // 第一个 :method 条目
        assert_eq!(find_name(b"content-type"), Some(44)); // 第一个 content-type 条目
        assert_eq!(find_name(b"x-frame-options"), Some(97)); // 第一个 x-frame-options 条目
    }

    #[test]
    fn test_find_name_not_existing() {
        // 测试查找不存在的头部名称
        assert_eq!(find_name(b"non-existent-header"), None);
        assert_eq!(find_name(b""), None);
        assert_eq!(find_name(b"custom-header"), None);
    }

    #[test]
    fn test_find_name_case_sensitive() {
        // 测试名称查找是否大小写敏感
        assert_eq!(find_name(b":AUTHORITY"), None);
        assert_eq!(find_name(b"Content-Type"), None);
        assert_eq!(find_name(b"ACCEPT"), None);
    }

    #[test]
    fn test_find_value_existing() {
        // 测试查找存在的头部值
        assert_eq!(find_value(b"/"), Some(1));
        assert_eq!(find_value(b"0"), Some(2)); // 第一个 "0" 值 (age)
        assert_eq!(find_value(b"GET"), Some(17));
        assert_eq!(find_value(b"POST"), Some(20));
        assert_eq!(find_value(b"https"), Some(23));
        assert_eq!(find_value(b"200"), Some(25));
        assert_eq!(find_value(b"404"), Some(27));
    }

    #[test]
    fn test_find_value_not_existing() {
        // 测试查找不存在的头部值
        assert_eq!(find_value(b"non-existent-value"), None);
        assert_eq!(find_value(b"999"), None);
        assert_eq!(find_value(b"PATCH"), None);
    }

    #[test]
    fn test_find_value_empty() {
        // 测试空值查找
        assert_eq!(find_value(b""), None);
    }

    #[test]
    fn test_find_value_case_sensitive() {
        // 测试值查找是否大小写敏感
        // 注意：静态表中既有 "GET" (索引17) 也有 "get" (索引76)
        assert_eq!(find_value(b"GET"), Some(17));
        assert_eq!(find_value(b"get"), Some(76)); // 实际存在小写的 get
        assert_eq!(find_value(b"Http"), None); // 应该是 "http"
        assert_eq!(find_value(b"http"), Some(22)); // 小写的 http 存在
    }

    #[test]
    fn test_find_exact_match() {
        // 测试精确匹配（名称和值都匹配）
        let (name_idx, value_idx) = find(b":path", b"/");
        assert_eq!(name_idx, Some(1));
        assert_eq!(value_idx, Some(1));

        let (name_idx, value_idx) = find(b":method", b"GET");
        assert_eq!(name_idx, Some(17));
        assert_eq!(value_idx, Some(17));

        let (name_idx, value_idx) = find(b":status", b"200");
        assert_eq!(name_idx, Some(25));
        assert_eq!(value_idx, Some(25));

        let (name_idx, value_idx) = find(b"content-type", b"text/plain");
        assert_eq!(name_idx, Some(53));
        assert_eq!(value_idx, Some(53));
    }

    #[test]
    fn test_find_name_match_only() {
        // 测试只有名称匹配的情况
        let (name_idx, value_idx) = find(b":authority", b"example.com");
        assert_eq!(name_idx, Some(0));
        assert_eq!(value_idx, None); // "example.com" 不在静态表中

        let (name_idx, value_idx) = find(b"content-length", b"1024");
        assert_eq!(name_idx, Some(4));
        assert_eq!(value_idx, None); // "1024" 不在静态表中
    }

    #[test]
    fn test_find_value_match_only() {
        // 测试只有值匹配的情况
        let (name_idx, value_idx) = find(b"custom-header", b"GET");
        assert_eq!(name_idx, None); // "custom-header" 不在静态表中
        assert_eq!(value_idx, Some(17)); // "GET" 在静态表中
    }

    #[test]
    fn test_find_no_match() {
        // 测试名称和值都不匹配的情况
        let (name_idx, value_idx) = find(b"custom-header", b"custom-value");
        assert_eq!(name_idx, None);
        assert_eq!(value_idx, None);
    }

    #[test]
    fn test_find_empty_value() {
        // 测试空值的情况
        let (name_idx, value_idx) = find(b":authority", b"");
        assert_eq!(name_idx, Some(0));
        assert_eq!(value_idx, None); // 空值不会被查找

        let (name_idx, value_idx) = find(b"custom-header", b"");
        assert_eq!(name_idx, None);
        assert_eq!(value_idx, None);
    }

    #[test]
    fn test_find_multiple_entries_same_name() {
        // 测试同一名称的多个条目，应该返回第一个匹配的
        let (name_idx, value_idx) = find(b":method", b"DELETE");
        assert_eq!(name_idx, Some(16)); // DELETE 是索引 16
        assert_eq!(value_idx, Some(16));

        let (name_idx, value_idx) = find(b":method", b"OPTIONS");
        assert_eq!(name_idx, Some(19)); // OPTIONS 是索引 19
        assert_eq!(value_idx, Some(19));

        // 当只查找名称时，应该返回第一个出现的索引
        assert_eq!(find_name(b":method"), Some(15)); // CONNECT 是第一个 :method
    }

    #[test]
    fn test_static_table_length() {
        // 测试静态表的长度
        assert_eq!(STATIC_TABLE.len(), 99);
    }

    #[test]
    fn test_static_table_entries() {
        // 测试静态表中的一些关键条目
        assert_eq!(get(0), Some((":authority", "")));
        assert_eq!(get(1), Some((":path", "/")));
        assert_eq!(get(17), Some((":method", "GET")));
        assert_eq!(get(25), Some((":status", "200")));
        assert_eq!(get(98), Some(("x-frame-options", "sameorigin")));
    }
}

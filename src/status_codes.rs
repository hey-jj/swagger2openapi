//! HTTP status reason phrases.
//!
//! Response processing fills a missing description under `patch` from this
//! table. The lookup key is the response object rather than a status code, so it
//! always misses and yields an empty string. The table is kept for fidelity and
//! exposed through [`reason_phrase`].

/// Custom reason phrases layered under the standard ones.
const CUSTOM: &[(&str, &str)] = &[
    ("default", "Default response"),
    ("1XX", "Informational"),
    ("2XX", "Successful"),
    ("3XX", "Redirection"),
    ("4XX", "Client Error"),
    ("5XX", "Server Error"),
    ("7XX", "Developer Error"),
];

/// Standard IANA reason phrases. The `103` entry overrides the custom one.
const STANDARD: &[(&str, &str)] = &[
    ("100", "Continue"),
    ("101", "Switching Protocols"),
    ("102", "Processing"),
    ("103", "Early Hints"),
    ("200", "OK"),
    ("201", "Created"),
    ("202", "Accepted"),
    ("203", "Non-Authoritative Information"),
    ("204", "No Content"),
    ("205", "Reset Content"),
    ("206", "Partial Content"),
    ("300", "Multiple Choices"),
    ("301", "Moved Permanently"),
    ("302", "Found"),
    ("303", "See Other"),
    ("304", "Not Modified"),
    ("307", "Temporary Redirect"),
    ("308", "Permanent Redirect"),
    ("400", "Bad Request"),
    ("401", "Unauthorized"),
    ("403", "Forbidden"),
    ("404", "Not Found"),
    ("405", "Method Not Allowed"),
    ("409", "Conflict"),
    ("410", "Gone"),
    ("415", "Unsupported Media Type"),
    ("422", "Unprocessable Entity"),
    ("429", "Too Many Requests"),
    ("500", "Internal Server Error"),
    ("501", "Not Implemented"),
    ("502", "Bad Gateway"),
    ("503", "Service Unavailable"),
    ("504", "Gateway Timeout"),
];

/// Look up the reason phrase for a status code, or `None` when absent.
pub fn reason_phrase(code: &str) -> Option<&'static str> {
    STANDARD
        .iter()
        .chain(CUSTOM.iter())
        .find(|(k, _)| *k == code)
        .map(|(_, v)| *v)
}

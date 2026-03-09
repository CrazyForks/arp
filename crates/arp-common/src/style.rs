//! ANSI terminal style constants shared across ARP binaries.

/// Reset all terminal attributes.
pub const RESET: &str = "\x1b[0m";
/// Bold text.
pub const BOLD: &str = "\x1b[1m";
/// Dim (faint) text.
pub const DIM: &str = "\x1b[2m";
/// Green foreground.
pub const GREEN: &str = "\x1b[32m";
/// Red foreground.
pub const RED: &str = "\x1b[31m";
/// Yellow foreground.
pub const YELLOW: &str = "\x1b[33m";
/// Cyan foreground.
pub const CYAN: &str = "\x1b[36m";

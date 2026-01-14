//! Protocol constants and conditional compilation macros
//!
//! In debug builds: strings are plain, logging is enabled
//! In release builds: strings are obfuscated, logging is disabled

/// Macro for protocol byte strings - obfuscated in release, plain in debug
#[cfg(debug_assertions)]
#[macro_export]
macro_rules! proto_bytes {
    ($s:expr) => { $s };
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! proto_bytes {
    ($s:expr) => { obfstr::obfbytes!($s) };
}

/// Macro for protocol strings - obfuscated in release, plain in debug
#[cfg(debug_assertions)]
#[macro_export]
macro_rules! proto_str {
    ($s:expr) => { $s };
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! proto_str {
    ($s:expr) => { obfstr::obfstr!($s) };
}

// === Conditional Logging Macros ===
// These compile to nothing in release builds

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => { tracing::info!($($arg)*) };
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => { };
}

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => { tracing::debug!($($arg)*) };
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => { };
}

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)*) => { tracing::trace!($($arg)*) };
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)*) => { };
}

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => { tracing::warn!($($arg)*) };
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => { };
}

/// Convert obfuscated string to 'static str (leaks memory, fine for CLI args)
#[cfg(debug_assertions)]
#[macro_export]
macro_rules! static_str {
    ($s:expr) => { $s };
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! static_str {
    ($s:expr) => {{
        let s: &'static str = Box::leak(obfstr::obfstr!($s).to_string().into_boxed_str());
        s
    }};
}

// Error logging - also disabled in release for stealth
#[cfg(debug_assertions)]
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => { tracing::error!($($arg)*) };
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => { };
}

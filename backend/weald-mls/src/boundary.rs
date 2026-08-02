// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The panic guard, and the rules for reading what a caller passed in.
//!
//! `specs/backend/relay/mls-binding.md`: "No panics cross the boundary. Every entry point
//! is wrapped in `catch_unwind` and returns a typed error. A panic that unwinds into
//! Swift is undefined behaviour, and it would happen first in the least tested path."
//!
//! So every `#[no_mangle]` function in this crate is one call to ``guard`` around a
//! closure that returns ``Result``. There is no second spelling and no exception: an
//! entry point that forgot the wrapper would be the one that unwinds, and a grep for
//! `no_mangle` next to a grep for `guard` is how that is checked.

use core::panic::AssertUnwindSafe;

use crate::status::{Error, Result, Status};

/// Run `body`, turning both its error and any panic into a ``Status``.
///
/// The panic message is not returned to the caller. It goes to stderr through the
/// process's own hook, where a crash reporter can collect it; handing it out would be a
/// string allocation to free and a place for key material to end up in a log.
pub fn guard<T>(on_ok: impl FnOnce(T), body: impl FnOnce() -> Result<T>) -> Status {
    // `AssertUnwindSafe` because the closure borrows a handle whose state may be
    // observed after a panic. That is exactly the situation `Status::Panicked`
    // describes: the caller is told the handle is unusable and must free it, which is
    // the only honest thing to say about MLS state that a panic interrupted.
    match std::panic::catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(value)) => {
            on_ok(value);
            Status::Ok
        }
        Ok(Err(error)) => {
            log_error(&error);
            error.status()
        }
        Err(_) => Status::Panicked,
    }
}

/// Where an error goes when it is not handed to the caller.
///
/// Deliberately stderr and deliberately unstructured: this crate has no logging
/// dependency and should not grow one. The relay's structured logging is
/// `wealdrelay::logging`; this is a library linked into a desktop app, and its errors
/// belong in the app's own log through the code the caller receives.
fn log_error(error: &Error) {
    // A single line, prefixed so it is greppable in a crash report.
    eprintln!("weald_mls: {error}");
}

/// A read-only view of bytes a caller passed in.
///
/// Every input is a pointer and a length, and every one of them is checked here rather
/// than at each call site: null with a non-zero length is a caller bug, and a null with
/// a zero length is the ordinary way to pass "nothing".
///
/// # Safety
/// `bytes` must be null or point to `len` readable bytes that stay valid and unmodified
/// for the duration of the call.
pub unsafe fn slice<'a>(bytes: *const u8, len: usize, what: &str) -> Result<&'a [u8]> {
    if bytes.is_null() {
        if len == 0 {
            return Ok(&[]);
        }
        return Err(Error::InvalidArgument(format!(
            "{what} is null with len {len}"
        )));
    }
    // Safety: the caller's contract above.
    Ok(unsafe { core::slice::from_raw_parts(bytes, len) })
}

/// The same, refusing empty input.
///
/// Most inputs on this boundary cannot be empty and mean anything: a zero-length MLS
/// message is not a message, and a zero-length group id is not a group. Saying so here
/// keeps the check out of every function.
///
/// # Safety
/// As ``slice``.
pub unsafe fn required_slice<'a>(bytes: *const u8, len: usize, what: &str) -> Result<&'a [u8]> {
    // Safety: forwarded.
    let found = unsafe { slice(bytes, len, what)? };
    if found.is_empty() {
        return Err(Error::InvalidArgument(format!("{what} is empty")));
    }
    Ok(found)
}

/// A NUL-terminated string a caller passed in, as UTF-8.
///
/// # Safety
/// `text` must be null or point to a NUL-terminated string that stays valid for the
/// duration of the call.
pub unsafe fn text<'a>(text: *const core::ffi::c_char, what: &str) -> Result<&'a str> {
    if text.is_null() {
        return Err(Error::InvalidArgument(format!("{what} is null")));
    }
    // Safety: the caller's contract above.
    let raw = unsafe { core::ffi::CStr::from_ptr(text) };
    raw.to_str()
        .map_err(|_| Error::InvalidArgument(format!("{what} is not utf-8")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The out-parameter every case below hands to ``guard``.
    ///
    /// One helper rather than a closure written out at each call site, and the reason is
    /// the assertion itself. "A failed call must not write an out-parameter" is only worth
    /// anything if the sink it did not call is the same sink that works: a second closure,
    /// written only for the failure case, would never run anywhere, so nothing would tell
    /// us whether it could have. Here the body below is one piece of code, proven to write
    /// by the success case and proven not to have been reached by the failure, panic and
    /// non-string-panic cases, which is the property `guard` actually claims.
    fn sink(seen: &mut Option<i32>) -> impl FnOnce(i32) + '_ {
        move |value| *seen = Some(value)
    }

    /// Serialises the two cases below that install a panic hook.
    ///
    /// The process has one panic hook and the test harness runs these two cases on two
    /// threads, so without this each one could install its hook, have the other overwrite
    /// it, and then panic into a hook it did not set. That is not a hypothetical: it is
    /// what was happening, and the visible symptom was that one of the two silencing
    /// hooks below never ran at all, which meant the case that was supposed to be quiet
    /// was quiet only by luck and the other case's panic message was being printed twice.
    /// Taking one lock for the whole set-panic-restore span makes each case's hook the one
    /// its own panic reaches. Nothing here is asserted more weakly for it.
    static PANIC_HOOK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn a_value_is_handed_to_the_success_arm_and_reported_ok() {
        let mut seen = None;
        let status = guard(sink(&mut seen), || Ok(41 + 1));
        assert_eq!(status, Status::Ok);
        assert_eq!(seen, Some(42));
    }

    #[test]
    fn an_error_becomes_its_status_and_touches_no_out_parameter() {
        let mut seen: Option<i32> = None;
        let status = guard(sink(&mut seen), || {
            Err(Error::Protocol("wrong epoch".into()))
        });
        assert_eq!(status, Status::Protocol);
        assert_eq!(seen, None, "a failed call must not write an out-parameter");
    }

    #[test]
    fn a_panic_is_caught_and_named_rather_than_unwinding() {
        // The rule this whole file exists for. Without the guard this test would abort
        // the process the moment the unwind reached the `extern "C"` frame.
        let _serialised = PANIC_HOOK.lock().expect("the hook lock");
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut seen: Option<i32> = None;
        let status = guard(sink(&mut seen), || panic!("inside the boundary"));
        std::panic::set_hook(previous);
        assert_eq!(status, Status::Panicked);
        assert_eq!(seen, None);
    }

    #[test]
    fn a_panic_carrying_a_non_string_payload_is_caught_too() {
        // `panic_any` with a payload that is not a `&str` or `String`, because a
        // `catch_unwind` that only handled the string cases would let this one through.
        let _serialised = PANIC_HOOK.lock().expect("the hook lock");
        let previous = std::panic::take_hook();
        // Silenced here, and this closure has to be the one that runs: it is what proves
        // the hook installed by this case is the hook this case's own panic reaches.
        std::panic::set_hook(Box::new(|_| {}));
        let mut seen: Option<i32> = None;
        let status = guard(sink(&mut seen), || std::panic::panic_any(7_u8));
        std::panic::set_hook(previous);
        assert_eq!(status, Status::Panicked);
        assert_eq!(seen, None);
    }

    #[test]
    fn bytes_in_are_read_when_they_are_there_and_refused_when_they_are_not() {
        let input = [1_u8, 2, 3];
        // Safety: `input` outlives the borrow.
        let seen = unsafe { slice(input.as_ptr(), input.len(), "message") }.expect("a slice");
        assert_eq!(seen, &[1, 2, 3]);

        // Null and empty is "nothing", which several MLS inputs legitimately are.
        let nothing = unsafe { slice(core::ptr::null(), 0, "message") }.expect("empty");
        assert!(nothing.is_empty());

        // Null with a length is a caller that computed a pointer wrongly.
        let error = unsafe { slice(core::ptr::null(), 8, "message") }.expect_err("refused");
        assert_eq!(error.status(), Status::InvalidArgument);
        assert!(error.to_string().contains("message"));
    }

    #[test]
    fn an_input_that_cannot_be_empty_says_so_by_name() {
        let error =
            unsafe { required_slice(core::ptr::null(), 0, "group_id") }.expect_err("refused");
        assert_eq!(error.status(), Status::InvalidArgument);
        assert!(error.to_string().contains("group_id is empty"));

        let empty: [u8; 0] = [];
        let error = unsafe { required_slice(empty.as_ptr(), 0, "group_id") }.expect_err("refused");
        assert!(error.to_string().contains("empty"));

        let input = [9_u8];
        let seen = unsafe { required_slice(input.as_ptr(), 1, "group_id") }.expect("a slice");
        assert_eq!(seen, &[9]);
    }

    #[test]
    fn a_string_in_is_utf8_or_it_is_refused() {
        let valid = std::ffi::CString::new("/tmp/weald.sqlite").expect("no interior nul");
        let seen = unsafe { text(valid.as_ptr(), "path") }.expect("utf-8");
        assert_eq!(seen, "/tmp/weald.sqlite");

        let error = unsafe { text(core::ptr::null(), "path") }.expect_err("refused");
        assert_eq!(error.status(), Status::InvalidArgument);
        assert!(error.to_string().contains("path is null"));

        // A lone continuation byte: valid C, not valid UTF-8, and a path this library
        // must refuse rather than lossily convert.
        let invalid = [0x80_u8, 0x00];
        let error = unsafe { text(invalid.as_ptr().cast(), "path") }.expect_err("refused");
        assert!(error.to_string().contains("not utf-8"));
    }
}

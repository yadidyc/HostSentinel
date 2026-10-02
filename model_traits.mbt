///|
/// Keep derived trait methods explicit for newer MoonBit toolchains.
pub extend DomainError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend DomainError with Eq::{not_equal, equal}

///|
pub extend HostId with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend HostId with Eq::{not_equal, equal}

///|
pub extend HostPlatform with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend HostPlatform with Eq::{not_equal, equal}

///|
pub extend HostState with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend HostState with Eq::{not_equal, equal}

///|
pub extend Host with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend Host with Eq::{not_equal, equal}

///|
pub extend EventId with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend EventId with Eq::{not_equal, equal}

///|
pub extend ObservedAt with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend ObservedAt with Eq::{not_equal, equal}

///|
pub extend EventKind with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend EventKind with Eq::{not_equal, equal}

///|
pub extend EventSource with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend EventSource with Eq::{not_equal, equal}

///|
pub extend Severity with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend Severity with Eq::{not_equal, equal}

///|
pub extend SecurityEvent with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SecurityEvent with Eq::{not_equal, equal}

///|
pub extend NormalizationError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend NormalizationError with Eq::{not_equal, equal}

///|
pub extend NormalizedEvent with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend NormalizedEvent with Eq::{not_equal, equal}

///|
pub extend IocKind with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend IocKind with Eq::{not_equal, equal}

///|
pub extend IocError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend IocError with Eq::{not_equal, equal}

///|
pub extend Indicator with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend Indicator with Eq::{not_equal, equal}

///|
pub extend IocMatch with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend IocMatch with Eq::{not_equal, equal}

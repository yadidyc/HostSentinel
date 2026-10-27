///|
/// A caller-classified event. `event_key` identifies one source record across
/// roles; `group_key` is the caller's exact correlation scope.
pub(all) struct Hit {
  event_key : String
  role : String
  source : String
  time_ms : Int64
  group_key : String
  value : String?
} derive(Debug, Eq)

///|
pub extend Hit with Eq::{equal, not_equal}

///|
pub extend Hit with @debug.Debug::{to_repr}

///|
pub(all) enum Kind {
  EventCount
  ValueCount
  Temporal
  TemporalOrdered
} derive(Debug, Eq)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with @debug.Debug::{to_repr}

///|
pub(all) enum CountOperator {
  Gt
  Gte
  Lt
  Lte
  Eq
  Neq
} derive(Debug, Eq)

///|
pub extend CountOperator with Eq::{equal, not_equal}

///|
pub extend CountOperator with @debug.Debug::{to_repr}

///|
/// A reusable window/aggregation program; event classification and field
/// extraction are intentionally owned by the caller, not by this package.
pub(all) struct Rule {
  id : String
  kind : Kind
  roles : Array[String]
  window_ms : Int64
  operator : CountOperator?
  threshold : Int32?
} derive(Debug, Eq)

///|
pub extend Rule with Eq::{equal, not_equal}

///|
pub extend Rule with @debug.Debug::{to_repr}

///|
pub(all) suberror CorrelationError {
  Invalid(String)
} derive(Debug, Eq)

///|
pub extend CorrelationError with Eq::{equal, not_equal}

///|
pub extend CorrelationError with @debug.Debug::{to_repr}

///|
/// Indices refer to the input `Hit` array; one event may have multiple roles.
pub struct Candidate {
  group_key : String
  hit_indices : Array[Int32]
  event_keys : Array[String]
  roles : Array[String]
  sources : Array[String]
  started_ms : Int64
  ended_ms : Int64
  observed_count : Int32
}

///|
pub fn Candidate::group_key(self : Candidate) -> String {
  self.group_key
}

///|
pub fn Candidate::hit_indices(self : Candidate) -> Array[Int32] {
  self.hit_indices.copy()
}

///|
pub fn Candidate::event_keys(self : Candidate) -> Array[String] {
  self.event_keys.copy()
}

///|
pub fn Candidate::roles(self : Candidate) -> Array[String] {
  self.roles.copy()
}

///|
pub fn Candidate::sources(self : Candidate) -> Array[String] {
  self.sources.copy()
}

///|
pub fn Candidate::started_ms(self : Candidate) -> Int64 {
  self.started_ms
}

///|
pub fn Candidate::ended_ms(self : Candidate) -> Int64 {
  self.ended_ms
}

///|
pub fn Candidate::observed_count(self : Candidate) -> Int32 {
  self.observed_count
}

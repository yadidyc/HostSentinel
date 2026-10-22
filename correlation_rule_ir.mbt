///|
/// The supported Sigma correlation subset. Aggregation variants are rejected.
pub(all) enum CorrelationRuleKind {
  EventCount
  ValueCount
  Temporal
  TemporalOrdered
} derive(Debug, Eq)

///|
pub extend CorrelationRuleKind with Eq::{equal, not_equal}

///|
pub extend CorrelationRuleKind with @debug.Debug::{to_repr}

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
/// A rule-file error with a path into the input document.
pub(all) suberror CorrelationRuleError {
  Invalid(path~ : String, detail~ : String)
} derive(Debug, Eq)

///|
pub extend CorrelationRuleError with Eq::{equal, not_equal}

///|
pub extend CorrelationRuleError with @debug.Debug::{to_repr}

///|
pub(all) struct BaseFieldPredicate {
  field : String
  value : String
}

///|
pub(all) struct BaseEventRule {
  id : String
  version : Int32
  predicates : Array[BaseFieldPredicate]
}

///|
pub(all) struct FieldAlias {
  name : String
  mappings : Map[String, String]
}

///|
/// Validated, source-independent correlation program. Construct with
/// `compile_correlation_rules_json` or `compile_correlation_rules_yaml`.
pub struct CompiledCorrelationRule {
  id : String
  version : Int32
  kind : CorrelationRuleKind
  rule_ids : Array[String]
  base_rules : Array[BaseEventRule]
  group_by : Array[String]
  aliases : Array[FieldAlias]
  window_ms : Int64
  operator : CountOperator?
  threshold : Int32?
  value_field : String?
}

///|
pub fn CompiledCorrelationRule::id(self : CompiledCorrelationRule) -> String {
  self.id
}

///|
pub fn CompiledCorrelationRule::version(
  self : CompiledCorrelationRule,
) -> Int32 {
  self.version
}

///|
pub fn CompiledCorrelationRule::kind(
  self : CompiledCorrelationRule,
) -> CorrelationRuleKind {
  self.kind
}

///|
pub fn CompiledCorrelationRule::rule_ids(
  self : CompiledCorrelationRule,
) -> Array[String] {
  self.rule_ids.copy()
}

///|
pub fn CompiledCorrelationRule::window_ms(
  self : CompiledCorrelationRule,
) -> Int64 {
  self.window_ms
}

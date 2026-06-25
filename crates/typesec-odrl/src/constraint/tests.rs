use super::*;
use crate::model::{ConstraintOperand, ConstraintOperator, OdrlConstraint};

fn make_constraint(left: &str, op: ConstraintOperator, right: &str) -> OdrlConstraint {
    OdrlConstraint {
        left_operand: ConstraintOperand::parse(left),
        operator: op,
        right_operand: right.into(),
    }
}

#[test]
fn purpose_eq_passes() {
    let c = make_constraint("purpose", ConstraintOperator::Eq, "analytics");
    let ctx = ConstraintContext::default().with_purpose("analytics");
    assert!(evaluate(&c, &ctx));
}

#[test]
fn purpose_eq_fails_wrong_value() {
    let c = make_constraint("purpose", ConstraintOperator::Eq, "analytics");
    let ctx = ConstraintContext::default().with_purpose("billing");
    assert!(!evaluate(&c, &ctx));
}

#[test]
fn purpose_is_part_of() {
    let c = make_constraint(
        "purpose",
        ConstraintOperator::IsPartOf,
        "analytics, audit, reporting",
    );
    let ctx = ConstraintContext::default().with_purpose("audit");
    assert!(evaluate(&c, &ctx));
}

#[test]
fn datetime_lt_passes_when_before() {
    let future = "2099-01-01T00:00:00Z";
    let c = make_constraint("dateTime", ConstraintOperator::Lt, future);
    let ctx = ConstraintContext::default();
    assert!(evaluate(&c, &ctx));
}

#[test]
fn datetime_lt_fails_when_past() {
    let past = "2000-01-01T00:00:00Z";
    let c = make_constraint("dateTime", ConstraintOperator::Lt, past);
    let ctx = ConstraintContext::default();
    assert!(!evaluate(&c, &ctx));
}

#[test]
fn count_operand_reads_custom_context() {
    let c = make_constraint("count", ConstraintOperator::Lteq, "5");
    let ctx = ConstraintContext::default().with("count", "3");
    assert!(evaluate(&c, &ctx));
}

#[test]
fn count_ordering_is_numeric_not_lexicographic() {
    // "10" <= "5" is true lexicographically but false numerically.
    let c = make_constraint("count", ConstraintOperator::Lteq, "5");
    let ctx = ConstraintContext::default().with("count", "10");
    assert!(!evaluate(&c, &ctx), "count 10 must not satisfy `lteq 5`");

    // And the genuinely-satisfied numeric case still passes.
    let c = make_constraint("count", ConstraintOperator::Gt, "5");
    let ctx = ConstraintContext::default().with("count", "10");
    assert!(evaluate(&c, &ctx), "count 10 must satisfy `gt 5`");
}

#[test]
fn non_numeric_ordering_falls_back_to_lexicographic() {
    let c = make_constraint("tier", ConstraintOperator::Lt, "gold");
    let ctx = ConstraintContext::default().with("tier", "bronze");
    assert!(
        evaluate(&c, &ctx),
        "\"bronze\" < \"gold\" lexicographically"
    );
}

#[test]
fn custom_operand_reads_custom_context() {
    let c = make_constraint("region", ConstraintOperator::Eq, "eu");
    let ctx = ConstraintContext::default().with("region", "eu");
    assert!(evaluate(&c, &ctx));
}

#[test]
fn unknown_custom_operand_fails_closed() {
    let c = make_constraint("region", ConstraintOperator::Eq, "eu");
    let ctx = ConstraintContext::default();
    assert!(!evaluate(&c, &ctx));
}

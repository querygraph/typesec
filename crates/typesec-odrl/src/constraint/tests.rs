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

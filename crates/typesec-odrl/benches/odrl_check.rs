use criterion::{Criterion, black_box, criterion_group, criterion_main};
use typesec_odrl::OdrlEngine;
use typesec_odrl::constraint::ConstraintContext;

fn odrl_policy() -> String {
    let mut yaml = String::from("policies:\n");
    for idx in 0..10 {
        yaml.push_str(&format!(
            r#"  - uid: "policy-{idx}"
    type: Set
    rules:
      - type: permission
        assignee: "agent:bench"
        action: read
        target: "reports/{idx}/*"
        constraints:
          - leftOperand: purpose
            operator: eq
            rightOperand: analytics
"#
        ));
    }
    yaml
}

fn bench_odrl_check_with_constraints(c: &mut Criterion) {
    let yaml = odrl_policy();
    let engine = OdrlEngine::from_yaml(&yaml).expect("policy");
    let context = ConstraintContext::default().with_purpose("analytics");

    c.bench_function("bench_odrl_check_with_constraints", |b| {
        b.iter(|| {
            for _ in 0..1_000 {
                let _ = black_box(engine.check_with_context(
                    black_box("agent:bench"),
                    black_box("read"),
                    black_box("reports/7/q1"),
                    black_box(&context),
                ));
            }
        })
    });
}

criterion_group!(benches, bench_odrl_check_with_constraints);
criterion_main!(benches);

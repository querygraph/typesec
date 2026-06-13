use criterion::{Criterion, black_box, criterion_group, criterion_main};
use typesec_core::PolicyEngine;
use typesec_rbac::RbacEngine;

const HIT_POLICY: &str = r#"
roles:
  - name: analyst
    permissions: [read]
    resources: ["reports/*"]
assignments:
  - subject: "agent:bench"
    roles: [analyst]
"#;

fn miss_policy() -> String {
    let mut yaml = String::from("roles:\n");
    for idx in 0..50 {
        yaml.push_str(&format!(
            "  - name: role_{idx}\n    permissions: [read]\n    resources: [\"reports/{idx}/*\"]\n"
        ));
    }
    yaml.push_str("assignments:\n");
    yaml.push_str("  - subject: \"agent:other\"\n    roles: [role_0]\n");
    yaml
}

fn bench_rbac_check_hit(c: &mut Criterion) {
    let engine = RbacEngine::from_yaml(HIT_POLICY).expect("policy");

    c.bench_function("bench_rbac_check_hit", |b| {
        b.iter(|| {
            for _ in 0..1_000 {
                let _ = black_box(engine.check(
                    black_box("agent:bench"),
                    black_box("read"),
                    black_box("reports/q1"),
                ));
            }
        })
    });
}

fn bench_rbac_check_miss(c: &mut Criterion) {
    let yaml = miss_policy();
    let engine = RbacEngine::from_yaml(&yaml).expect("policy");

    c.bench_function("bench_rbac_check_miss", |b| {
        b.iter(|| {
            for _ in 0..1_000 {
                let _ = black_box(engine.check(
                    black_box("agent:bench"),
                    black_box("write"),
                    black_box("reports/q1"),
                ));
            }
        })
    });
}

criterion_group!(benches, bench_rbac_check_hit, bench_rbac_check_miss);
criterion_main!(benches);

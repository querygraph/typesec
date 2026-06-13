use std::sync::Arc;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use typesec_core::{
    CanRead, CanWrite, Capability, CombineStrategy, ComposedEngine, LatticeEngine, Permission,
    PolicyEngine, PolicyResult, Resource, policy::mint_capability, resource::GenericResource,
};

struct AllowAll;

impl PolicyEngine for AllowAll {
    fn check(&self, _: &str, _: &str, _: &str) -> PolicyResult {
        PolicyResult::Allow
    }
}

struct WriteOnly;

impl PolicyEngine for WriteOnly {
    fn check(&self, _: &str, action: &str, _: &str) -> PolicyResult {
        if action == "write" {
            PolicyResult::Allow
        } else {
            PolicyResult::Deny("direct grant missing".to_owned())
        }
    }
}

struct DenyAll;

impl PolicyEngine for DenyAll {
    fn check(&self, _: &str, _: &str, _: &str) -> PolicyResult {
        PolicyResult::Deny("denied".to_owned())
    }
}

fn bench_mint_capability_allow(c: &mut Criterion) {
    let engine = AllowAll;
    let resource = GenericResource::new("reports/q1", "report");

    c.bench_function("bench_mint_capability_allow", |b| {
        b.iter(|| {
            for _ in 0..1_000 {
                let cap: Capability<CanRead, GenericResource> =
                    mint_capability(&engine, black_box("agent:bench"), black_box(&resource))
                        .expect("allow");
                black_box(cap);
            }
        })
    });
}

fn bench_lattice_promotion(c: &mut Criterion) {
    let engine = LatticeEngine::new(Arc::new(WriteOnly));
    let resource = GenericResource::new("reports/q1", "report");

    c.bench_function("bench_lattice_promotion", |b| {
        b.iter(|| {
            for _ in 0..1_000 {
                let _ = black_box(engine.check(
                    black_box("agent:bench"),
                    black_box(CanRead::name()),
                    black_box(resource.resource_id()),
                ));
            }
        })
    });
}

fn bench_composed_engine_deny_overrides(c: &mut Criterion) {
    let engine = ComposedEngine::new(
        vec![Arc::new(AllowAll), Arc::new(DenyAll)],
        CombineStrategy::DenyOverrides,
    );
    let resource = GenericResource::new("reports/q1", "report");

    c.bench_function("bench_composed_engine_deny_overrides", |b| {
        b.iter(|| {
            for _ in 0..1_000 {
                let _ = black_box(engine.check(
                    black_box("agent:bench"),
                    black_box(CanWrite::name()),
                    black_box(resource.resource_id()),
                ));
            }
        })
    });
}

criterion_group!(
    benches,
    bench_mint_capability_allow,
    bench_lattice_promotion,
    bench_composed_engine_deny_overrides
);
criterion_main!(benches);

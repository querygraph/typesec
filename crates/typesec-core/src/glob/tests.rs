use super::*;

#[test]
fn literal_star_matches_everything_including_separators() {
    let any = GlobPattern::compile("*", "resource").expect("compile");
    assert!(any.matches("reports/2024/q1"));
    assert!(any.matches(""));
    assert!(any.matches("anything"));
}

#[test]
fn single_star_does_not_cross_separators() {
    let pat = GlobPattern::compile("reports/*", "resource").expect("compile");
    assert!(pat.matches("reports/q1"));
    assert!(!pat.matches("reports/2024/q1"));
}

#[test]
fn double_star_crosses_separators() {
    let pat = GlobPattern::compile("reports/**", "resource").expect("compile");
    assert!(pat.matches("reports/q1"));
    assert!(pat.matches("reports/2024/q1"));
}

#[test]
fn char_classes_and_question_mark_match() {
    let class = GlobPattern::compile("report-[ab].csv", "resource").expect("compile");
    assert!(class.matches("report-a.csv"));
    assert!(class.matches("report-b.csv"));
    assert!(!class.matches("report-c.csv"));

    let single = GlobPattern::compile("report-?.csv", "resource").expect("compile");
    assert!(single.matches("report-1.csv"));
    assert!(!single.matches("report-12.csv"));
}

#[test]
fn invalid_pattern_is_rejected_with_kind_in_message() {
    let err = GlobPattern::compile("report-[ab.csv", "target").expect_err("should fail");
    assert!(err.contains("target"));
    assert!(err.contains("report-[ab.csv"));
}

#[test]
fn is_glob_pattern_detects_metacharacters() {
    assert!(is_glob_pattern("a*"));
    assert!(is_glob_pattern("a?"));
    assert!(is_glob_pattern("a[bc]"));
    assert!(!is_glob_pattern("plain/literal"));
}

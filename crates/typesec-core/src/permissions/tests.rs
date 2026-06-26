use super::*;

#[test]
fn permission_names_are_correct() {
    assert_eq!(CanRead::name(), "read");
    assert_eq!(CanReadInternal::name(), "read_internal");
    assert_eq!(CanReadSensitive::name(), "read_sensitive");
    assert_eq!(CanWrite::name(), "write");
    assert_eq!(CanWriteSensitive::name(), "write_sensitive");
    assert_eq!(CanDelete::name(), "delete");
    assert_eq!(CanExecute::name(), "execute");
    assert_eq!(CanDelegate::name(), "delegate");
    assert_eq!(CanDeclassify::name(), "declassify");
    assert_eq!(AiCanInfer::name(), "ai:infer");
    assert_eq!(AiCanTrain::name(), "ai:train");
    assert_eq!(AiCanExfiltrate::name(), "ai:exfiltrate");
}

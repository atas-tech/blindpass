// SPDX-License-Identifier: AGPL-3.0-only
use blindpass_core::deployment::Directory;
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt, symlink},
    path::PathBuf,
};
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "p06-publish-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn st03_atomic_publication_preserves_existing_empty_destination() {
    let root = Root::new();
    for name in ["source", "destination"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.0.join(name))
            .unwrap();
    }
    let inode = fs::metadata(root.0.join("destination")).unwrap().ino();
    let parent = Directory::open_private(&root.0).unwrap();
    assert!(
        parent.publish_directory("source", "destination").is_err(),
        "publication replaced existing destination"
    );
    assert_eq!(
        fs::metadata(root.0.join("destination")).unwrap().ino(),
        inode
    );
    assert!(root.0.join("source").is_dir());
}
#[test]
fn st03_atomic_publication_moves_complete_private_directory_and_rejects_links() {
    let root = Root::new();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root.0.join("source"))
        .unwrap();
    fs::write(root.0.join("source/receipt"), b"P06_DUMMY_RECEIPT").unwrap();
    let parent = Directory::open_private(&root.0).unwrap();
    symlink("source", root.0.join("linked")).unwrap();
    assert!(parent.publish_directory("linked", "destination").is_err());
    assert!(
        parent
            .publish_directory("../source", "destination")
            .is_err()
    );
    parent.publish_directory("source", "destination").unwrap();
    assert!(!root.0.join("source").exists());
    assert_eq!(
        fs::read(root.0.join("destination/receipt")).unwrap(),
        b"P06_DUMMY_RECEIPT"
    );
}

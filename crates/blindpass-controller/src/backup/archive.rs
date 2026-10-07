// SPDX-License-Identifier: AGPL-3.0-only
//! Version 1 accepts exactly one canonical USTAR regular-file representation.
//! Header names never become arbitrary filesystem paths.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Sqlite,
    Postgres,
}
impl Backend {
    pub(super) const fn member(self) -> &'static str {
        match self {
            Self::Sqlite => "database.sqlite",
            Self::Postgres => "database.pgcustom",
        }
    }
    fn members(self) -> [&'static str; 4] {
        [
            "root-secret",
            "agent-jwt-secret",
            "issuer-key",
            self.member(),
        ]
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberDigest {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveManifest {
    pub format_version: u32,
    pub controller_version: String,
    pub backend: Backend,
    pub snapshot: SnapshotInfo,
    pub members: Vec<MemberDigest>,
}
impl ArchiveManifest {
    fn validate(&self) -> Result<()> {
        let version_parts: Vec<_> = self.controller_version.split('.').collect();
        if self.format_version != 1
            || self.controller_version.len() > 32
            || version_parts.len() != 3
            || version_parts
                .iter()
                .any(|part| part.parse::<u32>().is_err())
            || !super::supported_snapshot_schema(self.snapshot.schema_version)
            || self.snapshot.tenant_id.is_empty()
            || self.snapshot.tenant_id.len() > 128
            || self.snapshot.recovery_generation == 0
            || self.snapshot.clock_ms < 1
            || self.snapshot.table_rows.len() > 256
            || self.members.len() != 4
        {
            return Err(BackupError("unsupported backup manifest"));
        }
        let mut total = 0u64;
        for (index, (member, expected)) in
            self.members.iter().zip(self.backend.members()).enumerate()
        {
            if member.name != expected
                || member.bytes == 0
                || (index < 3 && member.bytes != 32)
                || member.bytes > MAX_BUNDLE_BYTES
                || member.sha256.len() != 64
                || !member
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(BackupError("invalid backup members"));
            }
            total = total
                .checked_add(member.bytes)
                .ok_or(BackupError("backup exceeds limit"))?;
        }
        // Reserve the maximum manifest plus every header, padding and EOF
        // block, so a successful write also fits the complete tar limit.
        if total > MAX_BUNDLE_BYTES - 65536 - 8192 {
            return Err(BackupError("backup exceeds limit"));
        }
        Ok(())
    }
}

pub(crate) fn digest(path: &Path, work: &Path) -> Result<String> {
    let stage = Stage::new(work)?;
    let output = stage.member("sha256");
    tool(
        openssl(&["dgst", "-sha256", "-binary"]),
        Some(private_input(path, MAX_BUNDLE_BYTES)?),
        private_create(&output)?,
    )?;
    let digest = read_private_file(&output, 32).map_err(|_| BackupError("backup digest failed"))?;
    if digest.len() != 32 {
        return Err(BackupError("backup digest failed"));
    }
    Ok(digest
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn header(name: &str, size: u64) -> Result<[u8; 512]> {
    if name.len() > 99 || size > MAX_BUNDLE_BYTES {
        return Err(BackupError("invalid backup member"));
    }
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(b"0000600\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u64 = header.iter().map(|b| u64::from(*b)).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    Ok(header)
}
fn read_header(file: &mut File, name: &str, limit: u64) -> Result<u64> {
    let mut actual = [0u8; 512];
    file.read_exact(&mut actual)
        .map_err(|_| BackupError("truncated backup archive"))?;
    if actual[135] != 0 || !actual[124..135].iter().all(|b| (b'0'..=b'7').contains(b)) {
        return Err(BackupError("invalid backup member size"));
    }
    let size = u64::from_str_radix(
        std::str::from_utf8(&actual[124..135])
            .map_err(|_| BackupError("invalid backup member size"))?,
        8,
    )
    .map_err(|_| BackupError("invalid backup member size"))?;
    if size == 0 || size > limit || actual != header(name, size)? {
        return Err(BackupError("unsafe or noncanonical backup archive"));
    }
    Ok(size)
}
fn padding(file: &mut File, size: u64) -> Result<()> {
    let n = ((512 - size % 512) % 512) as usize;
    let mut bytes = [0u8; 512];
    file.read_exact(&mut bytes[..n])
        .map_err(|_| BackupError("truncated backup archive"))?;
    if bytes[..n].iter().any(|b| *b != 0) {
        return Err(BackupError("invalid backup archive padding"));
    }
    Ok(())
}
fn write_padding(file: &mut File, size: u64) -> Result<()> {
    file.write_all(&[0; 512][..((512 - size % 512) % 512) as usize])
        .map_err(|_| BackupError("backup write failed"))
}

pub fn write_archive(
    source: &Path,
    output: &Path,
    backend: Backend,
    snapshot: &SnapshotInfo,
) -> Result<()> {
    Directory::open_private(source).map_err(|_| BackupError("unsafe backup member directory"))?;
    let mut members = Vec::new();
    for name in backend.members() {
        let path = source.join(name);
        let bytes = private_input(&path, MAX_BUNDLE_BYTES)?
            .metadata()
            .map_err(|_| BackupError("backup member unavailable"))?
            .len();
        members.push(MemberDigest {
            name: name.into(),
            bytes,
            sha256: digest(&path, source)?,
        });
    }
    let manifest = ArchiveManifest {
        format_version: 1,
        controller_version: env!("CARGO_PKG_VERSION").into(),
        backend,
        snapshot: snapshot.clone(),
        members,
    };
    manifest.validate()?;
    let bytes = serde_json::to_vec(&manifest)
        .map_err(|_| BackupError("backup manifest encoding failed"))?;
    if bytes.len() > 65536 {
        return Err(BackupError("backup manifest exceeds limit"));
    }
    let mut file = private_create(output)?;
    let result = (|| {
        file.write_all(&header("manifest.json", bytes.len() as u64)?)
            .and_then(|()| file.write_all(&bytes))
            .map_err(|_| BackupError("backup write failed"))?;
        write_padding(&mut file, bytes.len() as u64)?;
        for member in &manifest.members {
            file.write_all(&header(&member.name, member.bytes)?)
                .map_err(|_| BackupError("backup write failed"))?;
            let input = private_input(&source.join(&member.name), MAX_BUNDLE_BYTES)?;
            let written = std::io::copy(&mut input.take(member.bytes + 1), &mut file)
                .map_err(|_| BackupError("backup write failed"))?;
            if written != member.bytes {
                return Err(BackupError("backup member changed during capture"));
            }
            write_padding(&mut file, member.bytes)?;
        }
        file.write_all(&[0; 1024])
            .and_then(|()| file.sync_all())
            .map_err(|_| BackupError("backup flush failed"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(output);
    }
    result
}

pub fn extract_archive(input: &Path, target: &Path) -> Result<ArchiveManifest> {
    Directory::open_private(target)
        .map_err(|_| BackupError("unsafe backup extraction directory"))?;
    if fs::read_dir(target)
        .map_err(|_| BackupError("backup extraction directory unavailable"))?
        .next()
        .is_some()
    {
        return Err(BackupError("backup extraction directory must be empty"));
    }
    let mut file = private_input(input, MAX_BUNDLE_BYTES)?;
    let size = read_header(&mut file, "manifest.json", 65536)?;
    let mut bytes = vec![0u8; size as usize];
    file.read_exact(&mut bytes)
        .map_err(|_| BackupError("truncated backup manifest"))?;
    padding(&mut file, size)?;
    let manifest: ArchiveManifest =
        serde_json::from_slice(&bytes).map_err(|_| BackupError("invalid backup manifest"))?;
    manifest.validate()?;
    let mut created = Vec::new();
    let result = (|| {
        for member in &manifest.members {
            let size = read_header(&mut file, &member.name, member.bytes)?;
            if size != member.bytes {
                return Err(BackupError("backup member size mismatch"));
            }
            // Names have already been compared to a fixed compiled allowlist.
            let path = target.join(&member.name);
            let mut output = private_create(&path)?;
            created.push(path.clone());
            let n = std::io::copy(&mut (&mut file).take(size), &mut output)
                .map_err(|_| BackupError("backup extraction failed"))?;
            if n != size {
                return Err(BackupError("truncated backup archive"));
            }
            output
                .sync_all()
                .map_err(|_| BackupError("backup extraction flush failed"))?;
            padding(&mut file, size)?;
            if digest(&path, target)? != member.sha256 {
                return Err(BackupError("backup member digest mismatch"));
            }
        }
        let mut end = [0u8; 1024];
        file.read_exact(&mut end)
            .map_err(|_| BackupError("truncated backup archive"))?;
        let mut extra = [0u8; 1];
        if end != [0; 1024]
            || file
                .read(&mut extra)
                .map_err(|_| BackupError("backup archive read failed"))?
                != 0
        {
            return Err(BackupError(
                "unexpected backup archive members or trailing data",
            ));
        }
        Ok(())
    })();
    if result.is_err() {
        for path in created {
            let _ = fs::remove_file(path);
        }
    }
    result?;
    Ok(manifest)
}

//! Bounded, discard-only package uploads for online-owner Shared Install.
//! This namespace is never canonical Raft staging or application evidence.

use super::*;
use crate::agent::package_admission::{AdmittedActorPackage, admit_actor_package};
use crate::agent_sdk::wire::CanonicalWire as _;
use crate::network::agent_protocol::{
    AgentFrame, AgentGenerationRoute, AgentMessage, ForwardedSharedInstallOperation,
    ForwardedSharedInstallOwner, ForwardedSharedInstallRequest,
};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;

pub(super) const FORWARDED_INSTALL_DIRECTORY: &str = "forwarded-install";
const BINDING_FILE: &str = "binding";
const PACKAGE_DIRECTORY: &str = "package";
const MAX_UPLOAD_OWNERS: usize = 3;
const MAX_BINDING_BYTES: usize = crate::agent_sdk::wire::MAX_MANAGEMENT_REQUEST_WIRE_BYTES
    + crate::agent_sdk::wire::MAX_AUTHORITY_RECEIPT_WIRE_BYTES
    + 1024;

fn fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn pin_directory(path: &Path) -> Result<File, SharedArtifactStagerError> {
    require_directory(path)?;
    let before = fs::symlink_metadata(path).map_err(|_| SharedArtifactStagerError::Unavailable)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| SharedArtifactStagerError::Unavailable)?;
    let after = file
        .metadata()
        .map_err(|_| SharedArtifactStagerError::Unavailable)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(SharedArtifactStagerError::Conflict);
    }
    Ok(file)
}

fn present(path: &Path) -> Result<bool, SharedArtifactStagerError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(SharedArtifactStagerError::Unavailable),
    }
}

fn protocol_route(generation: AgentGenerationRouteKey) -> AgentGenerationRoute {
    AgentGenerationRoute {
        space: crate::agent_sdk::SpaceId(generation.space().0),
        agent: crate::agent_sdk::AgentId(generation.agent().0),
        generation: crate::agent_sdk::Hash(generation.replication_id()),
    }
}

fn binding_bytes(
    generation: AgentGenerationRouteKey,
    owner: crate::agent_sdk::NodeId,
    request: &ForwardedSharedInstallRequest,
) -> Result<Vec<u8>, SharedArtifactStagerError> {
    let mut control = request.clone();
    control.operation = ForwardedSharedInstallOperation::Progress;
    AgentFrame {
        route: protocol_route(generation),
        sender: owner,
        message: AgentMessage::ForwardedSharedInstallRequest(control),
    }
    .encode()
    .map_err(|_| SharedArtifactStagerError::Corrupt)
}

struct UploadDirectory {
    file: File,
    parent: Option<usize>,
    name: String,
}
struct UploadFile {
    directory: usize,
    name: String,
    device: u64,
    inode: u64,
}
struct UploadCleanup {
    directories: Vec<UploadDirectory>,
    files: Vec<UploadFile>,
}
impl UploadCleanup {
    fn directory(&mut self, parent: usize, name: &str) -> Result<usize, SharedArtifactStagerError> {
        let file = pin_directory(&fd_path(&self.directories[parent].file).join(name))?;
        let index = self.directories.len();
        self.directories.push(UploadDirectory {
            file,
            parent: Some(parent),
            name: name.to_owned(),
        });
        Ok(index)
    }
    fn file(
        &mut self,
        directory: usize,
        name: &str,
        maximum: usize,
        read: bool,
    ) -> Result<(usize, Vec<u8>), SharedArtifactStagerError> {
        let path = fd_path(&self.directories[directory].file).join(name);
        require_regular(&path)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| SharedArtifactStagerError::Unavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| SharedArtifactStagerError::Unavailable)?;
        if !metadata.is_file() || metadata.len() > maximum as u64 {
            return Err(SharedArtifactStagerError::LimitExceeded);
        }
        let length = metadata.len() as usize;
        let mut bytes = Vec::new();
        if read {
            bytes
                .try_reserve_exact(length)
                .map_err(|_| SharedArtifactStagerError::LimitExceeded)?;
            file.take(maximum.saturating_add(1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| SharedArtifactStagerError::Unavailable)?;
            if bytes.len() != length {
                return Err(SharedArtifactStagerError::Conflict);
            }
        }
        let named =
            fs::symlink_metadata(path).map_err(|_| SharedArtifactStagerError::Unavailable)?;
        if named.dev() != metadata.dev()
            || named.ino() != metadata.ino()
            || named.len() != metadata.len()
        {
            return Err(SharedArtifactStagerError::Conflict);
        }
        self.files.push(UploadFile {
            directory,
            name: name.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        });
        Ok((length, bytes))
    }
    fn discard(self, subtree: usize) -> Result<(), SharedArtifactStagerError> {
        // The complete bounded tree was checked before the first unlink.
        // Every unlink is relative to its independently pinned directory.
        let belongs = |mut index: usize| {
            loop {
                if index == subtree {
                    return true;
                }
                let Some(parent) = self.directories[index].parent else {
                    return false;
                };
                index = parent;
            }
        };
        for entry in self.files.iter().filter(|entry| belongs(entry.directory)) {
            let parent = &self.directories[entry.directory].file;
            let path = fd_path(parent).join(&entry.name);
            let metadata =
                fs::symlink_metadata(&path).map_err(|_| SharedArtifactStagerError::Unavailable)?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.dev() != entry.device
                || metadata.ino() != entry.inode
            {
                return Err(SharedArtifactStagerError::Conflict);
            }
            fs::remove_file(path).map_err(|_| SharedArtifactStagerError::Unavailable)?;
            parent
                .sync_all()
                .map_err(|_| SharedArtifactStagerError::Unavailable)?;
        }
        for (_, entry) in self
            .directories
            .iter()
            .enumerate()
            .rev()
            .filter(|(index, _)| belongs(*index))
        {
            let Some(parent_index) = entry.parent else {
                continue;
            };
            let parent = &self.directories[parent_index].file;
            let path = fd_path(parent).join(&entry.name);
            let current =
                fs::symlink_metadata(&path).map_err(|_| SharedArtifactStagerError::Unavailable)?;
            let pinned = entry
                .file
                .metadata()
                .map_err(|_| SharedArtifactStagerError::Unavailable)?;
            if !current.is_dir()
                || current.file_type().is_symlink()
                || current.dev() != pinned.dev()
                || current.ino() != pinned.ino()
            {
                return Err(SharedArtifactStagerError::Conflict);
            }
            fs::remove_dir(path).map_err(|_| SharedArtifactStagerError::Unavailable)?;
            parent
                .sync_all()
                .map_err(|_| SharedArtifactStagerError::Unavailable)?;
        }
        Ok(())
    }
}

fn names(file: &File, maximum: usize) -> Result<Vec<String>, SharedArtifactStagerError> {
    let mut names = Vec::new();
    for entry in fs::read_dir(fd_path(file)).map_err(|_| SharedArtifactStagerError::Unavailable)? {
        if names.len() == maximum {
            return Err(SharedArtifactStagerError::LimitExceeded);
        }
        let name = entry
            .map_err(|_| SharedArtifactStagerError::Unavailable)?
            .file_name()
            .into_string()
            .map_err(|_| SharedArtifactStagerError::Corrupt)?;
        names.push(name);
    }
    names.sort();
    Ok(names)
}

fn audit_generation_file(
    plan: &mut UploadCleanup,
    directory: usize,
    name: &str,
    generation: AgentGenerationRouteKey,
) -> Result<(), SharedArtifactStagerError> {
    let expected = generation.encode();
    let (_, bytes) = plan.file(directory, name, expected.len(), true)?;
    if (name == STAGING_ROUTE_FILE && bytes != expected)
        || (name != STAGING_ROUTE_FILE && !expected.starts_with(&bytes))
    {
        return Err(SharedArtifactStagerError::Conflict);
    }
    Ok(())
}

fn audit_owner(
    plan: &mut UploadCleanup,
    directory: usize,
    owner: crate::agent_sdk::NodeId,
    generation: AgentGenerationRouteKey,
) -> Result<(), SharedArtifactStagerError> {
    let entries = names(&plan.directories[directory].file, 3)?;
    let mut binding = None;
    let mut partial_binding = None;
    for name in &entries {
        match name.as_str() {
            BINDING_FILE => {
                let (_, bytes) = plan.file(directory, name, MAX_BINDING_BYTES, true)?;
                let frame =
                    AgentFrame::decode(&bytes).map_err(|_| SharedArtifactStagerError::Corrupt)?;
                let AgentMessage::ForwardedSharedInstallRequest(request) = &frame.message else {
                    return Err(SharedArtifactStagerError::Corrupt);
                };
                if frame.sender != owner
                    || frame.route != protocol_route(generation)
                    || request.operation != ForwardedSharedInstallOperation::Progress
                    || frame.encode().ok().as_deref() != Some(bytes.as_slice())
                {
                    return Err(SharedArtifactStagerError::Conflict);
                }
                binding = Some(request.clone());
            }
            "binding.next" => {
                partial_binding = Some(plan.file(directory, name, MAX_BINDING_BYTES, true)?.1);
            }
            PACKAGE_DIRECTORY => {}
            _ => return Err(SharedArtifactStagerError::Corrupt),
        }
    }
    if let (Some(binding), Some(partial)) = (&binding, &partial_binding) {
        if !binding_bytes(generation, owner, binding)?.starts_with(partial) {
            return Err(SharedArtifactStagerError::Conflict);
        }
    }
    if !entries.iter().any(|name| name == PACKAGE_DIRECTORY) {
        return Ok(());
    }
    let binding = binding.ok_or(SharedArtifactStagerError::Corrupt)?;
    let crate::agent_sdk::ManagementRequest::Install(install) = &binding.request else {
        return Err(SharedArtifactStagerError::Corrupt);
    };
    let package = plan.directory(directory, PACKAGE_DIRECTORY)?;
    let package_entries = names(&plan.directories[package].file, 3)?;
    let mut batches = 0;
    for name in package_entries.iter() {
        if name == STAGING_ROUTE_FILE || name == &format!("{STAGING_ROUTE_FILE}.next") {
            audit_generation_file(plan, package, name, generation)?;
            continue;
        }
        batches += 1;
        if batches > 1
            || !package_entries
                .iter()
                .any(|entry| entry == STAGING_ROUTE_FILE)
        {
            return Err(SharedArtifactStagerError::Corrupt);
        }
        let batch = decode_batch_directory_name(name)?;
        let batch_dir = plan.directory(package, name)?;
        let entries = names(&plan.directories[batch_dir].file, 2 + 2 * 128)?;
        let mut manifest = None;
        if entries.iter().any(|name| name == STAGING_MANIFEST_FILE) {
            let (_, bytes) = plan.file(
                batch_dir,
                STAGING_MANIFEST_FILE,
                super::super::shared_raft::MAX_ARTIFACT_BATCH_MANIFEST_BYTES,
                true,
            )?;
            let decoded = ArtifactBatchManifest::decode(&bytes)
                .map_err(|_| SharedArtifactStagerError::Corrupt)?;
            if decoded.encode() != bytes
                || decoded.id() != batch
                || decoded.route().generation() != generation
                || decoded.artifacts().len() != 1
                || decoded.artifacts()[0].hash.0 != install.package.hash.0
                || decoded.artifacts()[0].len != install.package.len
            {
                return Err(SharedArtifactStagerError::Conflict);
            }
            manifest = Some(decoded);
        }
        let allowed = (0..install.package.len)
            .step_by(ARTIFACT_CHUNK_DATA_BYTES)
            .flat_map(|offset| {
                let name = chunk_file_name(0, offset);
                [
                    (name.clone(), (offset, false)),
                    (format!("{name}.next"), (offset, true)),
                ]
            })
            .collect::<BTreeMap<_, _>>();
        for name in entries {
            if name == STAGING_MANIFEST_FILE {
                continue;
            }
            if name == format!("{STAGING_MANIFEST_FILE}.next") {
                let (_, bytes) = plan.file(
                    batch_dir,
                    &name,
                    super::super::shared_raft::MAX_ARTIFACT_BATCH_MANIFEST_BYTES,
                    true,
                )?;
                if let Some(manifest) = &manifest {
                    if !manifest.encode().starts_with(&bytes) {
                        return Err(SharedArtifactStagerError::Conflict);
                    }
                }
                continue;
            }
            let (offset, partial) = allowed
                .get(&name)
                .ok_or(SharedArtifactStagerError::Corrupt)?;
            if manifest.is_none() {
                return Err(SharedArtifactStagerError::Corrupt);
            }
            let expected =
                (install.package.len - *offset).min(ARTIFACT_CHUNK_DATA_BYTES as u64) as usize;
            let (length, _) = plan.file(batch_dir, &name, expected, false)?;
            if !*partial && length != expected {
                return Err(SharedArtifactStagerError::Corrupt);
            }
        }
    }
    Ok(())
}

fn pin_artifact_root(stager: &FileSharedArtifactStager) -> Result<File, SharedArtifactStagerError> {
    let root = pin_directory(&stager.root)?;
    let root_generation = read_regular_bounded(
        &fd_path(&root).join(STAGING_ROUTE_FILE),
        super::super::shared_raft::MAX_AGENT_GENERATION_ROUTE_KEY_BYTES,
    )?;
    if root_generation != stager.generation.encode() {
        return Err(SharedArtifactStagerError::Conflict);
    }
    Ok(root)
}

fn cleanup_plan(
    stager: &FileSharedArtifactStager,
) -> Result<Option<UploadCleanup>, SharedArtifactStagerError> {
    let root = pin_artifact_root(stager)?;
    if !present(&fd_path(&root).join(FORWARDED_INSTALL_DIRECTORY))? {
        return Ok(None);
    }
    let mut plan = UploadCleanup {
        directories: vec![UploadDirectory {
            file: root,
            parent: None,
            name: String::new(),
        }],
        files: Vec::new(),
    };
    let uploads = plan.directory(0, FORWARDED_INSTALL_DIRECTORY)?;
    let entries = names(&plan.directories[uploads].file, MAX_UPLOAD_OWNERS + 2)?;
    let mut owners = 0;
    for name in &entries {
        if name == STAGING_ROUTE_FILE || name == &format!("{STAGING_ROUTE_FILE}.next") {
            audit_generation_file(&mut plan, uploads, name, stager.generation)?;
            continue;
        }
        owners += 1;
        if owners > MAX_UPLOAD_OWNERS {
            return Err(SharedArtifactStagerError::LimitExceeded);
        }
        if !entries.iter().any(|entry| entry == STAGING_ROUTE_FILE) {
            return Err(SharedArtifactStagerError::Corrupt);
        }
        let id = decode_batch_directory_name(name)?;
        let owner = crate::agent_sdk::NodeId(*id.as_bytes());
        if owner == crate::agent_sdk::NodeId::ZERO {
            return Err(SharedArtifactStagerError::Corrupt);
        }
        let directory = plan.directory(uploads, name)?;
        audit_owner(&mut plan, directory, owner, stager.generation)?;
    }
    Ok(Some(plan))
}

pub(super) fn audit_forwarded_install_uploads(
    stager: &FileSharedArtifactStager,
) -> Result<(), SharedArtifactStagerError> {
    cleanup_plan(stager).map(|_| ())
}
pub(super) fn discard_forwarded_install_uploads(
    stager: &FileSharedArtifactStager,
) -> Result<(), SharedArtifactStagerError> {
    if let Some(plan) = cleanup_plan(stager)? {
        plan.discard(1)?;
    }
    Ok(())
}

fn repair_upload_partial(
    parent: &File,
    name: &str,
    expected: &[u8],
) -> Result<(), SharedArtifactStagerError> {
    let partial_name = format!("{name}{STAGING_NEXT_SUFFIX}");
    let partial = fd_path(parent).join(&partial_name);
    if !present(&partial)? {
        return Ok(());
    }
    require_regular(&partial)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&partial)
        .map_err(|_| SharedArtifactStagerError::Unavailable)?;
    let pinned = file
        .metadata()
        .map_err(|_| SharedArtifactStagerError::Unavailable)?;
    if pinned.len() > expected.len() as u64 {
        return Err(SharedArtifactStagerError::LimitExceeded);
    }
    let mut bytes = Vec::new();
    file.take(expected.len().saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SharedArtifactStagerError::Unavailable)?;
    if !expected.starts_with(&bytes) {
        return Err(SharedArtifactStagerError::Conflict);
    }
    // Only this recognized, nonauthoritative temporary file is replaceable.
    // Reuse the parent already pinned by the audited upload operation. Its
    // proc-fd path is a process-owned link, not an untrusted filesystem parent
    // to reopen (and the ordinary no-symlink guard must remain strict).
    let current = fs::symlink_metadata(fd_path(parent).join(&partial_name))
        .map_err(|_| SharedArtifactStagerError::Unavailable)?;
    if !current.is_file()
        || current.file_type().is_symlink()
        || current.dev() != pinned.dev()
        || current.ino() != pinned.ino()
    {
        return Err(SharedArtifactStagerError::Conflict);
    }
    fs::remove_file(fd_path(parent).join(&partial_name))
        .map_err(|_| SharedArtifactStagerError::Unavailable)?;
    parent
        .sync_all()
        .map_err(|_| SharedArtifactStagerError::Unavailable)
}

impl FileSharedArtifactStager {
    fn upload_manifest(
        &self,
        request: &ForwardedSharedInstallRequest,
        route: super::super::shared_raft::AgentRouteKey,
    ) -> Result<ArtifactBatchManifest, SharedArtifactStagerError> {
        if !request.is_valid(protocol_route(self.generation))
            || route.generation() != self.generation
        {
            return Err(SharedArtifactStagerError::Conflict);
        }
        let crate::agent_sdk::ManagementRequest::Install(install) = &request.request else {
            return Err(SharedArtifactStagerError::Corrupt);
        };
        ArtifactBatchManifest::new(
            route,
            vec![BlobRef {
                hash: Hash(install.package.hash.0),
                len: install.package.len,
            }],
        )
        .map_err(|_| SharedArtifactStagerError::Corrupt)
    }

    fn upload_package(
        &self,
        owner: crate::agent_sdk::NodeId,
        request: &ForwardedSharedInstallRequest,
    ) -> Result<(File, File, File, FileSharedArtifactStager), SharedArtifactStagerError> {
        if owner == crate::agent_sdk::NodeId::ZERO {
            return Err(SharedArtifactStagerError::Conflict);
        }
        self.audit_namespace()?;
        let root = pin_artifact_root(self)?;
        let uploads_path = fd_path(&root).join(FORWARDED_INSTALL_DIRECTORY);
        ensure_plain_directory(&uploads_path)?;
        let uploads = pin_directory(&uploads_path)?;
        let generation_path = fd_path(&uploads).join(STAGING_ROUTE_FILE);
        repair_upload_partial(&uploads, STAGING_ROUTE_FILE, &self.generation.encode())?;
        install_immutable_file(&generation_path, &self.generation.encode())?;
        let owner_name = encode_hex(owner.as_bytes());
        let owner_path = fd_path(&uploads).join(&owner_name);
        let expected = binding_bytes(self.generation, owner, request)?;
        if !present(&owner_path)?
            && names(&uploads, MAX_UPLOAD_OWNERS + 2)?
                .iter()
                .filter(|name| {
                    name.as_str() != STAGING_ROUTE_FILE
                        && name.as_str() != format!("{STAGING_ROUTE_FILE}.next")
                })
                .count()
                >= MAX_UPLOAD_OWNERS
        {
            return Err(SharedArtifactStagerError::LimitExceeded);
        }
        if present(&owner_path)? {
            let directory = pin_directory(&owner_path)?;
            let binding_path = fd_path(&directory).join(BINDING_FILE);
            if present(&binding_path)?
                && read_regular_bounded(&binding_path, MAX_BINDING_BYTES)? != expected
            {
                let plan = cleanup_plan(self)?.ok_or(SharedArtifactStagerError::Corrupt)?;
                let index = plan
                    .directories
                    .iter()
                    .position(|entry| entry.parent == Some(1) && entry.name == owner_name)
                    .ok_or(SharedArtifactStagerError::Corrupt)?;
                plan.discard(index)?;
            }
        }
        ensure_plain_directory(&owner_path)?;
        let directory = pin_directory(&owner_path)?;
        let binding_path = fd_path(&directory).join(BINDING_FILE);
        repair_upload_partial(&directory, BINDING_FILE, &expected)?;
        install_immutable_file(&binding_path, &expected)?;
        let package_path = fd_path(&directory).join(PACKAGE_DIRECTORY);
        ensure_plain_directory(&package_path)?;
        let package = pin_directory(&package_path)?;
        let generation_path = fd_path(&package).join(STAGING_ROUTE_FILE);
        repair_upload_partial(&package, STAGING_ROUTE_FILE, &self.generation.encode())?;
        install_immutable_file(&generation_path, &self.generation.encode())?;
        let stager = FileSharedArtifactStager {
            root: fd_path(&package),
            generation: self.generation,
        };
        Ok((root, uploads, package, stager))
    }

    fn upload_progress(
        &self,
        owner: crate::agent_sdk::NodeId,
        request: &ForwardedSharedInstallRequest,
        route: super::super::shared_raft::AgentRouteKey,
    ) -> Result<u64, SharedArtifactStagerError> {
        let manifest = self.upload_manifest(request, route)?;
        let (_root, _uploads, _package, stager) = self.upload_package(owner, request)?;
        stager.package_progress(&manifest)
    }

    fn package_progress(
        &self,
        manifest: &ArtifactBatchManifest,
    ) -> Result<u64, SharedArtifactStagerError> {
        let stager = self;
        let batch = stager.batch_path(manifest.id());
        if !present(&batch)? {
            return Ok(0);
        }
        let directory = pin_directory(&batch)?;
        let manifest_path = fd_path(&directory).join(STAGING_MANIFEST_FILE);
        if !present(&manifest_path)? {
            return Ok(0);
        }
        if &stager.manifest(manifest.id(), &fd_path(&directory))? != manifest {
            return Err(SharedArtifactStagerError::Conflict);
        }
        let reference = &manifest.artifacts()[0];
        for offset in (0..reference.len).step_by(ARTIFACT_CHUNK_DATA_BYTES) {
            let path = fd_path(&directory).join(chunk_file_name(0, offset));
            if !present(&path)? {
                return Ok(offset);
            }
            let expected = (reference.len - offset).min(ARTIFACT_CHUNK_DATA_BYTES as u64) as usize;
            if read_regular_bounded(&path, ARTIFACT_CHUNK_DATA_BYTES)?.len() != expected {
                return Err(SharedArtifactStagerError::Corrupt);
            }
        }
        Ok(reference.len)
    }

    fn stage_upload(
        &self,
        owner: crate::agent_sdk::NodeId,
        request: &ForwardedSharedInstallRequest,
        route: super::super::shared_raft::AgentRouteKey,
    ) -> Result<u64, SharedArtifactStagerError> {
        let manifest = self.upload_manifest(request, route)?;
        let ForwardedSharedInstallOperation::Chunk(chunk) = &request.operation else {
            return Err(SharedArtifactStagerError::Conflict);
        };
        if chunk.manifest() != &manifest {
            return Err(SharedArtifactStagerError::Conflict);
        }
        let (_root, _uploads, _package, mut stager) = self.upload_package(owner, request)?;
        let offset = stager.package_progress(&manifest)?;
        if chunk.offset() > offset {
            return Err(SharedArtifactStagerError::Conflict);
        }
        let batch = stager.batch_path(manifest.id());
        ensure_plain_directory(&batch)?;
        let directory = pin_directory(&batch)?;
        repair_upload_partial(&directory, STAGING_MANIFEST_FILE, &manifest.encode())?;
        repair_upload_partial(
            &directory,
            &chunk_file_name(0, chunk.offset()),
            chunk.bytes(),
        )?;
        stager.stage(chunk)?;
        stager.package_progress(&manifest)
    }

    fn load_upload(
        &self,
        owner: crate::agent_sdk::NodeId,
        request: &ForwardedSharedInstallRequest,
        route: super::super::shared_raft::AgentRouteKey,
    ) -> Result<AdmittedActorPackage, SharedArtifactStagerError> {
        let manifest = self.upload_manifest(request, route)?;
        let (_root, _uploads, _package, stager) = self.upload_package(owner, request)?;
        let (loaded, mut bytes) = stager.load_complete(route, manifest.id())?;
        if loaded != manifest || bytes.len() != 1 {
            return Err(SharedArtifactStagerError::Conflict);
        }
        let package = admit_actor_package(&bytes.remove(0).bytes)
            .map_err(|_| SharedArtifactStagerError::Corrupt)?;
        Ok(package)
    }

    fn retire_upload(
        &self,
        owner: crate::agent_sdk::NodeId,
        request: &ForwardedSharedInstallRequest,
    ) -> Result<(), SharedArtifactStagerError> {
        let Some(plan) = cleanup_plan(self)? else {
            return Ok(());
        };
        let name = encode_hex(owner.as_bytes());
        let Some(index) = plan
            .directories
            .iter()
            .position(|entry| entry.parent == Some(1) && entry.name == name)
        else {
            return Ok(());
        };
        let binding = read_regular_bounded(
            &fd_path(&plan.directories[index].file).join(BINDING_FILE),
            MAX_BINDING_BYTES,
        )?;
        if binding != binding_bytes(self.generation, owner, request)? {
            return Err(SharedArtifactStagerError::Conflict);
        }
        plan.discard(index)
    }
}

type FileDriver = SharedJournalAgentDriver<
    super::super::journal_store::FileAgentJournalStore,
    FileSharedArtifactStager,
>;

fn invalid_owner() -> SharedJournalDriverError {
    SharedJournalDriverError::Executor(LocalReplayExecutorError::InvalidAuthority)
}

impl FileDriver {
    /// Upload authorization is only a signed, current family binding. Finish
    /// additionally authenticates the immutable successful policy capsule.
    pub(crate) fn validate_forwarded_install_owner(
        &self,
        sender: crate::agent_sdk::NodeId,
        owner: ForwardedSharedInstallOwner,
        request: &crate::agent_sdk::ManagementRequest,
        receipt: &crate::agent_sdk::authority::AuthorityReceipt,
        managed: crate::agent_sdk::authority::ManagedAgentTarget,
        require_approval: bool,
    ) -> Result<(), SharedJournalDriverError> {
        use crate::actors::codec::Decode as _;
        use crate::agent_sdk::authority::{
            AuthorityActorTarget, AuthorityCredentialCall, ManagementApproval,
        };
        use crate::agent_sdk::{
            InvocationAuthorization, InvocationStatus, MethodMode, RuntimeOutcome, RuntimeWork,
        };
        let route = self.active_route()?;
        let committee = self.active_committee()?;
        if protocol_route(route.generation()) != owner.system
            || committee.members().len() != 3
            || committee.voter_count() != 3
            || sender == crate::agent_sdk::NodeId::ZERO
            || !matches!(request, crate::agent_sdk::ManagementRequest::Install(_))
        {
            return Err(invalid_owner());
        }
        let manifest = if require_approval {
            // Reuse the existing driver verifier on the freshly settled
            // ledger view, not a second independently selected manifest.
            self.verified_recovery_manifest_from_read(
                self.ledger.current_management_recovery_manifest()?,
            )?
        } else {
            // Bounded uploads are not mutation admission or proof of policy
            // approval; do not repeat full physical/capsule audits per chunk.
            self.ledger.recovery_manifest_if_present()?
        }
        .ok_or(SharedJournalDriverError::Store(
            JournalStoreError::Unavailable,
        ))?;
        let slot = manifest
            .management_slot(NodeId(sender.0))
            .filter(|slot| {
                !slot.is_released() && slot.registration().commitment().0 == owner.registration.0
            })
            .ok_or(SharedJournalDriverError::Store(
                JournalStoreError::Unavailable,
            ))?;
        self.validate_management_registration_runtime(slot.registration().request())?;
        slot.registration()
            .verify(route.generation(), &committee)
            .map_err(|_| invalid_owner())?;
        let index = slot
            .members()
            .iter()
            .position(|member| member.commitment().0 == owner.member.0)
            .ok_or_else(invalid_owner)?;
        // Only the family's original authorize member can transport a mutation.
        let member = &slot.members()[index];
        if index != 0 || member.parent().is_some() {
            return Err(invalid_owner());
        }
        let RuntimeWork::Invoke {
            context,
            state,
            invocation,
            authorization,
            observed_slot,
        } = member.envelope()
        else {
            return Err(invalid_owner());
        };
        let message = crate::actors::value::Msg::try_decode(
            invocation
                .message
                .strip_prefix(&[crate::actors::value::TAG_DYNAMIC])
                .ok_or_else(invalid_owner)?,
        )
        .ok_or_else(invalid_owner)?;
        if message.name != "authorize" {
            return Err(invalid_owner());
        }
        let call = AuthorityCredentialCall::decode(
            message
                .args
                .get("call")
                .and_then(|value| value.as_bytes())
                .ok_or_else(invalid_owner)?,
        )
        .map_err(|_| invalid_owner())?;
        // A custody holder is not necessarily the original submitting owner.
        // Only the signed first acquisition can identify that node, including
        // calls which intentionally do not contain a transport-node attestor.
        if call.authenticated_node.is_some_and(|node| node != sender)
            || (require_approval && slot.origin_owner().0 != sender.0)
        {
            return Err(invalid_owner());
        }
        let descriptor = self.clean_descriptor()?;
        let target = AuthorityActorTarget {
            space: descriptor.identity.space,
            system_agent: descriptor.identity.agent,
            system_runtime_deployment: descriptor.identity.runtime_deployment,
            binding: descriptor.authority,
        };
        let intent = super::super::clean_management_intent::CleanManagementIntent::new(
            target,
            managed,
            request.clone(),
            call.clone(),
            &super::super::clean_bootstrap::RawCredentialVerifier,
        )
        .map_err(|_| invalid_owner())?;
        if *context != crate::agent_sdk::RuntimeExecutionContext::Direct
            || !state.is_empty()
            || invocation.space != target.space
            || invocation.agent != target.system_agent
            || invocation.runtime_deployment != target.system_runtime_deployment
            || invocation.actor != target.binding.issuer.actor
            || invocation.deployment != target.binding.issuer.deployment
            || invocation.program != target.binding.issuer.program
            || invocation.invocation != call.invocation
            || invocation.mode != MethodMode::Linear
            || invocation.origin != intent.authorization_origin()
            || invocation.roles != crate::agent_sdk::InvocationRoleClaims::none()
            || invocation.message != intent.authorization_message()
            || invocation.recovery_only
            || **authorization
                != InvocationAuthorization::PublicPreflight(
                    crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot),
                )
        {
            return Err(invalid_owner());
        }
        if require_approval {
            let evidence =
                slot.members_evidence()[index]
                    .invoke()
                    .ok_or(SharedJournalDriverError::Store(
                        JournalStoreError::Unavailable,
                    ))?;
            let RuntimeOutcome::Completed(Ok(reply)) = evidence.outcome() else {
                return Err(invalid_owner());
            };
            if reply.invocation != invocation.invocation
                || reply.actor != invocation.actor
                || reply.incarnation != invocation.incarnation
                || reply.deployment != invocation.deployment
                || reply.mode != invocation.mode
                || reply.status != InvocationStatus::Done
            {
                return Err(invalid_owner());
            }
            let Some(crate::actors::value::Value::Bytes(bytes)) =
                crate::actors::value::Value::try_decode(&reply.reply)
            else {
                return Err(invalid_owner());
            };
            let approval = ManagementApproval::decode(&bytes).map_err(|_| invalid_owner())?;
            if !approval.matches_call(&call)
                || !crate::agent_sdk::authority::receipt_matches_approval(receipt, &approval)
            {
                return Err(invalid_owner());
            }
            // The global host guard excludes application/materialization
            // writes. The independent System worker may still move its raw
            // commit/log cursor: preserve the existing strict physical gate.
            if self.ledger.current_management_recovery_manifest()?.as_ref() != Some(&manifest) {
                return Err(SharedJournalDriverError::Store(
                    JournalStoreError::Unavailable,
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn transfer_forwarded_install_package(
        &self,
        sender: crate::agent_sdk::NodeId,
        request: &ForwardedSharedInstallRequest,
    ) -> Result<u64, SharedJournalDriverError> {
        let route = self.active_route()?;
        match &request.operation {
            ForwardedSharedInstallOperation::Progress => self
                .artifacts
                .upload_progress(sender, request, route)
                .map_err(Into::into),
            ForwardedSharedInstallOperation::Chunk(_) => self
                .artifacts
                .stage_upload(sender, request, route)
                .map_err(Into::into),
            ForwardedSharedInstallOperation::Finish => Err(invalid_owner()),
        }
    }
    pub(crate) fn load_forwarded_install(
        &self,
        sender: crate::agent_sdk::NodeId,
        request: &ForwardedSharedInstallRequest,
    ) -> Result<AdmittedActorPackage, SharedJournalDriverError> {
        self.artifacts
            .load_upload(sender, request, self.active_route()?)
            .map_err(Into::into)
    }
    pub(crate) fn retire_forwarded_install(
        &self,
        sender: crate::agent_sdk::NodeId,
        request: &ForwardedSharedInstallRequest,
    ) -> Result<(), SharedJournalDriverError> {
        self.artifacts
            .retire_upload(sender, request)
            .map_err(Into::into)
    }
    pub(crate) fn retained_forwarded_install(
        &self,
        request: &crate::agent_sdk::ManagementRequest,
        authority: &crate::agent_sdk::authority::AuthorityReceipt,
    ) -> Result<
        Option<(ReplayInputId, crate::agent_sdk::RuntimeOutcome, u64)>,
        SharedJournalDriverError,
    > {
        if !matches!(request, crate::agent_sdk::ManagementRequest::Install(_)) {
            return Err(invalid_owner());
        }
        let Some(evidence) = self.materialization.clean_management_evidence() else {
            return Ok(None);
        };
        if evidence.request != request.replay_commitment()
            || evidence.authority != authority.commitment()
            || evidence.epoch != authority.selector.epoch
            || evidence.sequence != authority.selector.decision_sequence
        {
            return Ok(None);
        }
        let expired = super::super::driver::verify_clean_management_journal_receipt(
            &self.clean_descriptor()?,
            request,
            authority,
            evidence.observed_slot,
            false,
        )
        .map_err(|_| invalid_owner())?;
        if expired
            && evidence.result != Err(crate::agent_sdk::ManagementError::ExpiredBeforeApplication)
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        Ok(Some((
            evidence.input,
            crate::agent_sdk::RuntimeOutcome::Management(evidence.result.clone()),
            evidence.observed_slot,
        )))
    }
}

#[cfg(all(test, feature = "experimental-state-blocks"))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static NEXT: AtomicUsize = AtomicUsize::new(1);
            let target = std::env::var_os("CARGO_TARGET_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"));
            let base = target.join("task-tmp");
            fs::create_dir_all(&base).unwrap();
            loop {
                let path = base.join(format!(
                    "forwarded-install-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("cannot create forwarding fixture: {error}"),
                }
            }
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture() -> (
        TestDirectory,
        FileSharedArtifactStager,
        ForwardedSharedInstallRequest,
        crate::agent::shared_raft::AgentRouteKey,
        crate::agent_sdk::NodeId,
    ) {
        let (_, request) = crate::network::agent_protocol::forwarded_shared_install_for_test(true);
        let ForwardedSharedInstallOperation::Chunk(chunk) = &request.operation else {
            unreachable!();
        };
        let route = chunk.manifest().route();
        let directory = TestDirectory::new();
        let stager =
            FileSharedArtifactStager::open(directory.path().join("artifacts"), route.generation())
                .unwrap();
        (
            directory,
            stager,
            request,
            route,
            crate::agent_sdk::NodeId([71; 32]),
        )
    }

    fn owner_path(stager: &FileSharedArtifactStager, owner: crate::agent_sdk::NodeId) -> PathBuf {
        stager
            .root
            .join(FORWARDED_INSTALL_DIRECTORY)
            .join(encode_hex(owner.as_bytes()))
    }

    #[test]
    fn forwarded_upload_is_noncanonical_exact_and_discarded_on_reopen() {
        let (_directory, mut stager, request, route, owner) = fixture();
        let ForwardedSharedInstallOperation::Chunk(chunk) = &request.operation else {
            unreachable!();
        };
        assert_eq!(stager.upload_progress(owner, &request, route).unwrap(), 0);
        assert_eq!(
            stager.stage_upload(owner, &request, route).unwrap(),
            chunk.artifact().len
        );
        assert_eq!(
            stager.stage_upload(owner, &request, route).unwrap(),
            chunk.artifact().len
        );
        assert!(
            !stager.contains(chunk).unwrap(),
            "temporary upload must not skip canonical Raft chunks"
        );
        assert!(stager.load_complete(route, chunk.batch()).is_err());
        assert_eq!(
            stager
                .load_upload(owner, &request, route)
                .unwrap()
                .exact_bytes(),
            chunk.bytes()
        );
        stager.stage(chunk).unwrap();
        let canonical = stager.load_complete(route, chunk.batch()).unwrap();
        let temp = owner_path(&stager, owner)
            .join(PACKAGE_DIRECTORY)
            .join(encode_hex(chunk.batch().as_bytes()))
            .join(format!("{}.next", chunk_file_name(0, 0)));
        fs::write(&temp, &chunk.bytes()[..chunk.bytes().len() / 2]).unwrap();
        assert!(
            stager.audit(route.generation()).is_ok(),
            "recognized nonauthoritative partial is separately audited"
        );
        let root = stager.root.clone();
        drop(stager);
        let reopened = FileSharedArtifactStager::open(root, route.generation()).unwrap();
        assert!(!reopened.root.join(FORWARDED_INSTALL_DIRECTORY).exists());
        assert_eq!(
            reopened.load_complete(route, chunk.batch()).unwrap(),
            canonical
        );
        assert!(reopened.contains(chunk).unwrap());
    }

    #[test]
    fn forwarded_upload_partial_repair_requires_exact_resent_prefix() {
        let (_directory, stager, request, route, owner) = fixture();
        let ForwardedSharedInstallOperation::Chunk(chunk) = &request.operation else {
            unreachable!();
        };
        stager.upload_progress(owner, &request, route).unwrap();
        let path = owner_path(&stager, owner)
            .join(PACKAGE_DIRECTORY)
            .join(encode_hex(chunk.batch().as_bytes()));
        fs::create_dir(&path).unwrap();
        let encoded = chunk.manifest().encode();
        fs::write(path.join("manifest.next"), &encoded[..encoded.len() / 2]).unwrap();
        assert_eq!(
            stager.stage_upload(owner, &request, route).unwrap(),
            chunk.artifact().len
        );
        fs::remove_file(path.join(chunk_file_name(0, 0))).unwrap();
        let partial = path.join(format!("{}.next", chunk_file_name(0, 0)));
        fs::write(&partial, &chunk.bytes()[..chunk.bytes().len() / 2]).unwrap();
        assert_eq!(
            stager.stage_upload(owner, &request, route).unwrap(),
            chunk.artifact().len
        );
        assert!(!partial.exists());
        fs::remove_file(path.join(chunk_file_name(0, 0))).unwrap();
        fs::write(&partial, b"conflicting partial").unwrap();
        assert!(stager.stage_upload(owner, &request, route).is_err());
        assert_eq!(fs::read(&partial).unwrap(), b"conflicting partial");
        assert!(!path.join(chunk_file_name(0, 0)).exists());
    }

    #[test]
    fn forwarded_upload_unknown_or_symlink_residue_is_not_discarded() {
        for fault in 0..5 {
            let (_directory, stager, request, route, owner) = fixture();
            stager.stage_upload(owner, &request, route).unwrap();
            let path = owner_path(&stager, owner);
            let binding = fs::read(path.join(BINDING_FILE)).unwrap();
            match fault {
                0 => fs::write(path.join("unknown"), b"untouched").unwrap(),
                1 => {
                    fs::remove_file(path.join(BINDING_FILE)).unwrap();
                    symlink(
                        stager.root.join(STAGING_ROUTE_FILE),
                        path.join(BINDING_FILE),
                    )
                    .unwrap();
                }
                2 => fs::write(
                    stager
                        .root
                        .join(FORWARDED_INSTALL_DIRECTORY)
                        .join(STAGING_ROUTE_FILE),
                    b"wrong generation",
                )
                .unwrap(),
                3 => fs::write(path.join("binding.next"), vec![0; MAX_BINDING_BYTES + 1]).unwrap(),
                _ => {
                    fs::remove_dir_all(path.join(PACKAGE_DIRECTORY)).unwrap();
                    symlink(&stager.root, path.join(PACKAGE_DIRECTORY)).unwrap();
                }
            }
            assert!(stager.audit(route.generation()).is_err());
            assert!(discard_forwarded_install_uploads(&stager).is_err());
            assert!(
                path.exists(),
                "failed whitelist audit must precede every unlink"
            );
            if fault != 1 {
                assert_eq!(fs::read(path.join(BINDING_FILE)).unwrap(), binding);
            }
        }
    }

    #[test]
    fn forwarded_upload_scope_replacement_preserves_other_owner_and_canonical_bytes() {
        let (_directory, mut stager, request, route, owner) = fixture();
        let ForwardedSharedInstallOperation::Chunk(chunk) = &request.operation else {
            unreachable!();
        };
        let other = crate::agent_sdk::NodeId([72; 32]);
        stager.stage_upload(owner, &request, route).unwrap();
        stager.stage_upload(other, &request, route).unwrap();
        stager.stage(chunk).unwrap();
        let canonical = stager.load_complete(route, chunk.batch()).unwrap();
        let mut replacement = request.clone();
        replacement.owner.registration = crate::agent_sdk::Hash([73; 32]);
        // Production invokes this only after verifying the new current signed
        // family. This standalone stager test confers no admission authority.
        assert_eq!(
            stager.upload_progress(owner, &replacement, route).unwrap(),
            0
        );
        assert_eq!(
            stager.upload_progress(other, &request, route).unwrap(),
            chunk.artifact().len
        );
        stager.retire_upload(owner, &replacement).unwrap();
        assert!(owner_path(&stager, other).exists());
        assert_eq!(
            stager.load_complete(route, chunk.batch()).unwrap(),
            canonical
        );
        for byte in [74, 75] {
            stager
                .upload_progress(crate::agent_sdk::NodeId([byte; 32]), &request, route)
                .unwrap();
        }
        assert!(
            stager
                .upload_progress(crate::agent_sdk::NodeId([76; 32]), &request, route)
                .is_err()
        );
    }

    #[test]
    fn forwarded_upload_largest_valid_install_reference_resumes_at_actual_chunk_boundary() {
        let (_directory, stager, mut request, route, owner) = fixture();
        let bytes = vec![0x5b; crate::agent::MAX_CATALOG_ARTIFACT_BYTES as usize];
        let reference = crate::agent_sdk::BlobRef::of_bytes(&bytes);
        let crate::agent_sdk::ManagementRequest::Install(install) = &mut request.request else {
            unreachable!();
        };
        install.package = reference.clone();
        install.entry.package = reference.clone();
        request.authority.selector.evidence.package = Some(reference.clone());
        request.authority.selector.request = request.request.commitment();
        let manifest = ArtifactBatchManifest::new(
            route,
            vec![BlobRef {
                hash: Hash(reference.hash.0),
                len: reference.len,
            }],
        )
        .unwrap();
        request.operation = ForwardedSharedInstallOperation::Progress;
        // Structural transfer-ceiling test only; these arbitrary bytes do not
        // claim package admission or replace genuine public Install evidence.
        assert!(request.is_valid(protocol_route(stager.generation)));
        assert_eq!(stager.upload_progress(owner, &request, route).unwrap(), 0);
        for offset in [0, ARTIFACT_CHUNK_DATA_BYTES as u64] {
            request.operation = ForwardedSharedInstallOperation::Chunk(
                ArtifactChunk::new(
                    manifest.clone(),
                    0,
                    offset,
                    bytes[offset as usize..offset as usize + ARTIFACT_CHUNK_DATA_BYTES].to_vec(),
                )
                .unwrap(),
            );
            assert_eq!(
                stager.stage_upload(owner, &request, route).unwrap(),
                offset + ARTIFACT_CHUNK_DATA_BYTES as u64
            );
        }
        request.operation = ForwardedSharedInstallOperation::Progress;
        assert_eq!(
            stager.upload_progress(owner, &request, route).unwrap(),
            2 * ARTIFACT_CHUNK_DATA_BYTES as u64
        );
        assert_eq!(reference.len, 8 * 1024 * 1024);
        assert!(
            !stager
                .root
                .join(encode_hex(manifest.id().as_bytes()))
                .exists()
        );
    }
}

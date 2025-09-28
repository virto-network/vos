use crate::wait_pollable;
use std::io;
use wasi::{
    filesystem::{
        preopens::get_directories,
        types::{
            Descriptor, DescriptorFlags, DirectoryEntry, DirectoryEntryStream, OpenFlags, PathFlags,
        },
    },
    io::streams::StreamError,
};

type Result<T> = std::result::Result<T, io::Error>;

/// An file handle for WASI-based async I/O operations.
///
/// This struct provides file operations using WASI's streaming I/O interface.
/// Files are opened through [`File::open`] or [`File::create`] methods, or via [`OpenOptions`].
pub struct File {
    descriptor: Descriptor,
    position: u64,
}

impl File {
    /// Opens a file in read-only mode.
    ///
    /// This function will return an error if `path` doesn't exist or if the file cannot be read.
    /// The file must be within one of the WASI preopened directories.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file doesn't exist
    /// - Permission is denied
    /// - No preopen directory matches the path
    pub fn open(path: impl AsRef<str>) -> Result<Self> {
        OpenOptions::new().read(true).open(path)
    }

    /// Opens a file in write-only mode, creating it if it doesn't exist and truncating if it does.
    ///
    /// This function will create a file if it does not exist, and will truncate it if it does.
    /// The file must be within one of the WASI preopened directories.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Permission is denied
    /// - No preopen directory matches the path
    /// - The path is a directory
    pub fn create(path: impl AsRef<str>) -> Result<Self> {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
    }

    /// Truncates or extends the underlying file.
    ///
    /// If the `size` is less than the current file's size, then the file will be shrunk.
    /// If it is greater than the current file's size, then the file will be extended.
    pub fn set_len(&self, size: u64) -> Result<()> {
        self.descriptor
            .set_size(size)
            .map_err(wasi_error_to_io_error)?;
        Ok(())
    }

    /// Attempts to sync all OS-internal metadata to disk.
    ///
    /// This function will ensure that all in-memory data reaches the filesystem before returning.
    pub fn sync_data(&self) -> Result<()> {
        self.descriptor
            .sync_data()
            .map_err(wasi_error_to_io_error)?;
        Ok(())
    }

    /// Queries metadata about the file.
    ///
    /// Returns information such as file type, size, and timestamps.
    pub fn metadata(&self) -> Result<Metadata> {
        let stat = self.descriptor.stat().map_err(wasi_error_to_io_error)?;

        Ok(Metadata {
            file_type: stat.type_,
            len: stat.size,
            modified: stat.data_modification_timestamp,
            accessed: stat.data_access_timestamp,
        })
    }
}

impl crate::io::Read for File {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let stream = self
            .descriptor
            .read_via_stream(self.position)
            .map_err(|e| io::Error::other(format!("Failed to create read stream: {:?}", e)))?;

        // Wait for stream to be readable
        let subscription = stream.subscribe();
        wait_pollable(&subscription).await;

        match stream.read(buf.len() as u64) {
            Ok(data) if data.is_empty() => Ok(0),
            Ok(data) => {
                let bytes_read = data.len();
                buf[0..bytes_read].copy_from_slice(&data);
                self.position += bytes_read as u64;
                Ok(bytes_read)
            }
            Err(StreamError::Closed) => Ok(0),
            Err(StreamError::LastOperationFailed(err)) => {
                Err(io::Error::other(err.to_debug_string()))
            }
        }
    }
}

impl crate::io::Write for File {
    async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let stream = self
            .descriptor
            .write_via_stream(self.position)
            .map_err(|e| io::Error::other(format!("Failed to create write stream: {:?}", e)))?;

        let writable = loop {
            match stream.check_write() {
                Ok(0) => {
                    wait_pollable(&stream.subscribe()).await;
                    continue;
                }
                Ok(available) => {
                    let writable = (available as usize).min(buf.len());
                    match stream.write(&buf[0..writable]) {
                        Ok(()) => {
                            self.position += writable as u64;
                            break writable;
                        }
                        Err(StreamError::Closed) => {
                            return Err(io::ErrorKind::BrokenPipe.into());
                        }
                        Err(StreamError::LastOperationFailed(err)) => {
                            return Err(io::Error::other(err.to_debug_string()));
                        }
                    }
                }
                Err(StreamError::Closed) => return Err(io::ErrorKind::BrokenPipe.into()),
                Err(StreamError::LastOperationFailed(err)) => {
                    return Err(io::Error::other(err.to_debug_string()));
                }
            }
        };

        self.descriptor
            .sync_data()
            .map_err(wasi_error_to_io_error)?;
        log::trace!("Synced {writable} bytes to disk");

        Ok(writable)
    }
}

impl crate::io::ErrorType for File {
    type Error = io::Error;
}

impl crate::io::Seek for File {
    async fn seek(&mut self, pos: crate::io::SeekFrom) -> Result<u64> {
        use crate::io::SeekFrom;

        let new_position = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                let metadata = self.metadata()?;
                let file_size = metadata.len();
                if offset < 0 && (-offset as u64) > file_size {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Invalid seek to before beginning of file",
                    ));
                }
                if offset >= 0 {
                    file_size + (offset as u64)
                } else {
                    file_size - ((-offset) as u64)
                }
            }
            SeekFrom::Current(offset) => {
                if offset < 0 && (-offset as u64) > self.position {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Invalid seek to before beginning of file",
                    ));
                }
                if offset >= 0 {
                    self.position + (offset as u64)
                } else {
                    self.position - ((-offset) as u64)
                }
            }
        };

        self.position = new_position;
        Ok(new_position)
    }
}

/// Reads the entire contents of a file into a string.
///
/// This is a convenience function for reading a file's contents as UTF-8 text.
/// It opens the file, reads all bytes, and converts them to a UTF-8 string.
///
/// # Errors
///
/// Returns an error if:
/// - The file doesn't exist
/// - Permission is denied
/// - The file contents are not valid UTF-8
/// - Any I/O error occurs during reading
pub async fn read_to_string<P: AsRef<str>>(path: P) -> Result<String> {
    use crate::io::Read;
    let mut file = File::open(path)?;
    let mut contents = String::new();
    let mut buf = [0u8; 4096];

    loop {
        let bytes_read = file.read(&mut buf).await?;
        if bytes_read == 0 {
            break;
        }
        let s = std::str::from_utf8(&buf[..bytes_read])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        contents.push_str(s);
    }

    Ok(contents)
}

/// Entries returned by the [`ReadDir`] iterator.
///
/// An instance of `DirEntry` represents an entry inside a directory on the filesystem.
/// Each entry carries metadata about the file or directory it represents.
pub struct DirEntry {
    entry: DirectoryEntry,
    base_path: String,
}

impl DirEntry {
    /// Returns the full path to this entry.
    ///
    /// This combines the directory path with the file name to create the complete path.
    pub fn path(&self) -> String {
        format!("{}/{}", self.base_path, self.entry.name)
    }

    /// Returns just the file name of this directory entry.
    ///
    /// This is the final component of the path, without any leading directories.
    pub fn file_name(&self) -> &str {
        &self.entry.name
    }

    /// Returns the file type for this entry.
    ///
    /// Returns the WASI descriptor type indicating whether this entry is a file,
    /// directory, symbolic link, etc.
    pub fn file_type(&self) -> wasi::filesystem::types::DescriptorType {
        self.entry.type_
    }
}

/// Iterator over the entries in a directory.
///
/// This iterator is returned from the [`read_dir`] function and will yield
/// instances of [`DirEntry`].
pub struct ReadDir {
    stream: DirectoryEntryStream,
    base_path: String,
}

impl Iterator for ReadDir {
    type Item = Result<DirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.stream.read_directory_entry() {
            Ok(Some(entry)) => Some(Ok(DirEntry {
                entry,
                base_path: self.base_path.clone(),
            })),
            Ok(None) => None,
            Err(e) => Some(Err(wasi_error_to_io_error(e))),
        }
    }
}

/// Returns an iterator over the entries within a directory.
///
/// The iterator will yield instances of [`DirEntry`]. The order in which entries
/// are returned is not guaranteed to be sorted.
///
/// # Errors
///
/// Returns an error if:
/// - The path doesn't exist
/// - Permission is denied
/// - The path is not a directory
/// - No preopen directory matches the path
pub fn read_dir(path: impl AsRef<str>) -> Result<ReadDir> {
    let path = path.as_ref();
    let preopens = get_directories();

    for (descriptor, preopen_path) in preopens {
        if path.starts_with(&preopen_path) {
            let relative_path = path
                .strip_prefix(&preopen_path)
                .unwrap_or(path)
                .trim_start_matches('/');

            let dir_descriptor = descriptor
                .open_at(
                    PathFlags::empty(),
                    relative_path,
                    OpenFlags::empty(),
                    DescriptorFlags::READ,
                )
                .map_err(wasi_error_to_io_error)?;

            let stream = dir_descriptor
                .read_directory()
                .map_err(wasi_error_to_io_error)?;

            return Ok(ReadDir {
                stream,
                base_path: path.to_string(),
            });
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("No preopen found for path: {}", path),
    ))
}

/// Options and flags which can be used to configure how a file is opened.
///
/// This builder exposes the ability to configure how a [`File`] is opened and
/// what operations are permitted on the open file. The [`File::open`] and
/// [`File::create`] methods are aliases for commonly used options using this builder.
pub struct OpenOptions {
    read: bool,
    write: bool,
    create: bool,
    truncate: bool,
    append: bool,
}

impl OpenOptions {
    /// Creates a blank new set of options ready for configuration.
    ///
    /// All options are initially set to `false`.
    pub fn new() -> Self {
        Self {
            read: false,
            write: false,
            create: false,
            truncate: false,
            append: false,
        }
    }

    /// Sets the option for read access.
    ///
    /// This option, when true, will indicate that the file should be readable if opened.
    pub fn read(mut self, read: bool) -> Self {
        self.read = read;
        self
    }

    /// Sets the option for write access.
    ///
    /// This option, when true, will indicate that the file should be writable if opened.
    pub fn write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }

    /// Sets the option to create a new file, failing if it already exists.
    ///
    /// This option, when true, will create the file if it doesn't exist.
    /// In combination with [`truncate`](Self::truncate), it can be used to create or overwrite a file.
    pub fn create(mut self, create: bool) -> Self {
        self.create = create;
        self
    }

    /// Sets the option for truncating the file to 0 bytes on opening.
    ///
    /// This option, when true, will truncate the file to 0 bytes if it exists.
    /// The file must be opened for writing for this to have any effect.
    pub fn truncate(mut self, truncate: bool) -> Self {
        self.truncate = truncate;
        self
    }

    /// Sets the option for the append mode.
    ///
    /// This option, when true, means that writes will append to the end of the file
    /// instead of overwriting previous contents.
    pub fn append(mut self, append: bool) -> Self {
        self.append = append;
        self
    }

    /// Opens a file at `path` with the options specified by `self`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file doesn't exist and create is false
    /// - Permission is denied
    /// - No preopen directory matches the path
    /// - The options are invalid (e.g., truncate without write)
    pub fn open(self, path: impl AsRef<str>) -> Result<File> {
        let path = path.as_ref();
        let preopens = get_directories();

        for (descriptor, preopen_path) in preopens {
            if path.starts_with(&preopen_path) {
                let relative_path = path
                    .strip_prefix(&preopen_path)
                    .unwrap_or(path)
                    .trim_start_matches('/');

                let mut open_flags = OpenFlags::empty();
                let mut descriptor_flags = DescriptorFlags::empty();

                if self.create {
                    open_flags |= OpenFlags::CREATE;
                }
                if self.truncate {
                    open_flags |= OpenFlags::TRUNCATE;
                }
                if self.read {
                    descriptor_flags |= DescriptorFlags::READ;
                }
                if self.write {
                    descriptor_flags |= DescriptorFlags::WRITE;
                }

                let file_descriptor = descriptor
                    .open_at(
                        PathFlags::empty(),
                        relative_path,
                        open_flags,
                        descriptor_flags,
                    )
                    .map_err(wasi_error_to_io_error)?;

                let position = if self.append {
                    file_descriptor.stat().map_err(wasi_error_to_io_error)?.size
                } else {
                    0
                };
                return Ok(File {
                    descriptor: file_descriptor,
                    position,
                });
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("No preopen found for path: {}", path),
        ))
    }
}

/// Metadata information about a file.
///
/// This structure represents the metadata of a file, including its type, size, and timestamps.
pub struct Metadata {
    file_type: wasi::filesystem::types::DescriptorType,
    len: u64,
    modified: Option<wasi::filesystem::types::Datetime>,
    accessed: Option<wasi::filesystem::types::Datetime>,
}

impl Metadata {
    /// Returns the file type for this metadata.
    ///
    /// The returned type indicates whether this is a regular file, directory,
    /// symbolic link, or other special file type.
    pub fn file_type(&self) -> wasi::filesystem::types::DescriptorType {
        self.file_type
    }

    /// Returns the size of the file, in bytes, this metadata is for.
    ///
    /// For directories and other special file types, this may return 0 or
    /// an undefined value.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Returns `true` if this metadata is for a directory.
    ///
    /// This is equivalent to checking if `file_type()` is `DescriptorType::Directory`.
    pub fn is_dir(&self) -> bool {
        matches!(
            self.file_type,
            wasi::filesystem::types::DescriptorType::Directory
        )
    }

    /// Returns `true` if this metadata is for a regular file.
    ///
    /// This is equivalent to checking if `file_type()` is `DescriptorType::RegularFile`.
    pub fn is_file(&self) -> bool {
        matches!(
            self.file_type,
            wasi::filesystem::types::DescriptorType::RegularFile
        )
    }

    /// Returns the last modification time listed in this metadata.
    ///
    /// Returns `None` if the timestamp is not available or not supported
    /// by the filesystem.
    pub fn modified(&self) -> Option<wasi::filesystem::types::Datetime> {
        self.modified
    }

    /// Returns the last access time of this metadata.
    ///
    /// Returns `None` if the timestamp is not available or not supported
    /// by the filesystem.
    pub fn accessed(&self) -> Option<wasi::filesystem::types::Datetime> {
        self.accessed
    }
}

/// Convert WASI ErrorCode to std::io::Error via ErrorKind
fn wasi_error_to_io_error(error_code: wasi::filesystem::types::ErrorCode) -> io::Error {
    use io::ErrorKind;
    use wasi::filesystem::types::ErrorCode;

    let kind = match error_code {
        ErrorCode::Access => ErrorKind::PermissionDenied,
        ErrorCode::WouldBlock => ErrorKind::Other,
        ErrorCode::BadDescriptor => ErrorKind::InvalidInput,
        ErrorCode::Exist => ErrorKind::AlreadyExists,
        ErrorCode::FileTooLarge => ErrorKind::InvalidData,
        ErrorCode::IllegalByteSequence => ErrorKind::InvalidData,
        ErrorCode::Interrupted => ErrorKind::Interrupted,
        ErrorCode::Invalid => ErrorKind::InvalidInput,
        ErrorCode::Io => ErrorKind::Other,
        ErrorCode::IsDirectory => ErrorKind::InvalidInput,
        ErrorCode::TooManyLinks => ErrorKind::Other,
        ErrorCode::NameTooLong => ErrorKind::InvalidInput,
        ErrorCode::NoEntry => ErrorKind::NotFound,
        ErrorCode::InsufficientMemory => ErrorKind::OutOfMemory,
        ErrorCode::InsufficientSpace => ErrorKind::OutOfMemory,
        ErrorCode::NotDirectory => ErrorKind::InvalidInput,
        ErrorCode::NotEmpty => ErrorKind::InvalidInput,
        ErrorCode::Unsupported => ErrorKind::Unsupported,
        ErrorCode::NotPermitted => ErrorKind::PermissionDenied,
        ErrorCode::Pipe => ErrorKind::BrokenPipe,
        ErrorCode::ReadOnly => ErrorKind::PermissionDenied,
        ErrorCode::InvalidSeek => ErrorKind::InvalidInput,
        ErrorCode::CrossDevice => ErrorKind::Other,
        _ => ErrorKind::Other,
    };

    io::Error::from(std::io::ErrorKind::from(kind))
}

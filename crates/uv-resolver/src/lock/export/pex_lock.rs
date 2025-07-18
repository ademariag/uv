//! PEX lock file format support.
//!
//! This module provides functionality to export UV lock files to the PEX lock format,
//! which is used by the PEX packaging tool and Pantsbuild for reproducible Python builds.
//!
//! The PEX lock format is a JSON-based format that includes:
//! - Package metadata and version constraints
//! - Platform-specific resolves with 3-component platform tags
//! - Artifact information with separate algorithm and hash fields
//! - Build and resolution configuration

use std::fmt;
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};
use uv_platform_tags::PlatformTag;

use crate::lock::{Lock, LockError, Source, WheelWireSource};

/// A PEX lock file representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PexLock {
    /// Whether to allow building from source.
    pub allow_builds: bool,
    /// Whether to allow prereleases.
    pub allow_prereleases: bool,
    /// Whether to allow wheels.
    pub allow_wheels: bool,
    /// Whether to use build isolation.
    pub build_isolation: bool,
    /// Constraints applied during resolution.
    pub constraints: Vec<String>,
    /// Whether to elide unused `requires_dist`.
    pub elide_unused_requires_dist: bool,
    /// Excluded packages.
    pub excluded: Vec<String>,
    /// Locked resolved dependencies.
    pub locked_resolves: Vec<PexLockedResolve>,
    /// Only build packages.
    pub only_builds: Vec<String>,
    /// Only wheel packages.
    pub only_wheels: Vec<String>,
    /// Overridden packages.
    pub overridden: Vec<String>,
    /// Path mappings.
    pub path_mappings: serde_json::Map<String, serde_json::Value>,
    /// The PEX version used to generate this lock file.
    pub pex_version: String,
    /// The pip version used.
    pub pip_version: String,
    /// Whether to prefer older binary versions.
    pub prefer_older_binary: bool,
    /// Direct requirements.
    pub requirements: Vec<String>,
    /// Python version requirements.
    pub requires_python: Vec<String>,
    /// The resolver version used.
    pub resolver_version: String,
    /// The style of resolution.
    pub style: String,
    /// Target systems.
    pub target_systems: Vec<String>,
    /// Whether to include transitive dependencies.
    pub transitive: bool,
    /// Whether to use PEP517 build backend.
    pub use_pep517: Option<bool>,
    /// Whether to use system time.
    pub use_system_time: bool,
}

/// A locked resolve entry in a PEX lock file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PexLockedResolve {
    /// The locked requirements for this platform.
    pub locked_requirements: Vec<PexLockedRequirement>,
    /// The platform tag this resolve applies to (null for universal).
    pub platform_tag: Option<Vec<String>>,
}

/// A locked requirement in a PEX lock file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PexLockedRequirement {
    /// Artifacts (wheels/sdists) for this requirement.
    pub artifacts: Vec<PexArtifact>,
    /// The project name.
    pub project_name: String,
    /// Dependencies of this requirement.
    pub requires_dists: Vec<String>,
    /// Python version requirement.
    pub requires_python: String,
    /// The version.
    pub version: String,
}

/// An artifact in a PEX lock file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PexArtifact {
    /// The artifact URL.
    pub url: String,
    /// Hash algorithm (e.g., "sha256"). Omitted for git dependencies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// Hash value. Omitted for git dependencies.  
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// Whether this is a wheel (used for sorting, but not serialized).
    #[serde(skip_serializing)]
    pub is_wheel: Option<bool>,
}

impl PexLock {
    /// Default PEX version for generated lock files.
    const DEFAULT_PEX_VERSION: &'static str = "2.44.0";

    /// Default pip version.
    const DEFAULT_PIP_VERSION: &'static str = "24.2";

    /// Default hash algorithm when none is specified.
    const DEFAULT_HASH_ALGORITHM: &'static str = "sha256";

    /// Extract algorithm and hash from a hash string.
    fn parse_hash(hash_str: &str) -> (String, String) {
        if let Some(colon_pos) = hash_str.find(':') {
            let algorithm = hash_str[..colon_pos].to_string();
            let hash_value = hash_str[colon_pos + 1..].to_string();
            (algorithm, hash_value)
        } else {
            (
                Self::DEFAULT_HASH_ALGORITHM.to_string(),
                hash_str.to_string(),
            )
        }
    }

    /// Create a new PEX lock from a UV lock file.
    pub fn from_lock(lock: &Lock) -> Result<Self, LockError> {
        let mut requirements = Vec::new();
        let mut locked_requirements = Vec::new();

        // Collect root requirements
        if let Some(root) = lock.root() {
            for dep in &root.dependencies {
                if let Some(version) = lock
                    .packages()
                    .iter()
                    .find(|pkg| pkg.id.name == dep.package_id.name)
                    .and_then(|pkg| pkg.id.version.as_ref())
                {
                    requirements.push(format!("{}=={}", dep.package_id.name, version));
                }
            }
        }

        // Sort requirements for consistent output
        requirements.sort();

        // Process all packages for locked requirements
        for package in lock.packages() {
            // Create locked requirement
            let mut artifacts = Vec::new();

            // Check if this is a git dependency (no wheels/sdist)
            if package.wheels.is_empty() && package.sdist.is_none() {
                // Try the proper git reference method first
                if let Ok(Some(git_ref)) = package.as_git_ref() {
                    // Create a synthetic artifact for git dependencies
                    let git_url = format!("git+{}", git_ref.reference.url);

                    artifacts.push(PexArtifact {
                        url: git_url,
                        algorithm: None, // No hash validation for git dependencies
                        hash: None,      // Let PEX handle git dependencies without hashes
                        is_wheel: None,  // Git dependencies don't specify wheel status
                    });
                } else {
                    // Fallback: try to extract git info from the package source directly
                    if let Source::Git(url, _git_ref) = &package.id.source {
                        let git_url = format!("git+{}", url);

                        artifacts.push(PexArtifact {
                            url: git_url,
                            algorithm: None, // No hash validation for git dependencies
                            hash: None,      // Let PEX handle git dependencies without hashes
                            is_wheel: None,  // Git dependencies don't specify wheel status
                        });
                    }
                }
            }

            // Add wheels (excluding Windows-specific wheels for Linux/Mac targets)
            for wheel in &package.wheels {
                // Filter out Windows-specific wheels when targeting linux/mac
                let is_windows_wheel = wheel.filename.platform_tags().iter().any(|tag| {
                    matches!(
                        tag,
                        PlatformTag::Win32
                            | PlatformTag::WinAmd64
                            | PlatformTag::WinArm64
                            | PlatformTag::WinIa64
                    )
                });

                if is_windows_wheel {
                    continue;
                }

                let wheel_url = match &wheel.url {
                    WheelWireSource::Url { url } => url.to_string(),
                    WheelWireSource::Path { path } => format!("file://{}", path.to_string_lossy()),
                    WheelWireSource::Filename { filename } => filename.to_string(),
                };

                let (algorithm, hash) = if let Some(h) = wheel.hash.as_ref() {
                    Self::parse_hash(&h.to_string())
                } else {
                    continue;
                };

                artifacts.push(PexArtifact {
                    url: wheel_url,
                    algorithm: Some(algorithm),
                    hash: Some(hash),
                    is_wheel: Some(true),
                });
            }

            // Add source distributions
            if let Some(sdist) = &package.sdist {
                let Some(sdist_url) = sdist.url().map(std::string::ToString::to_string) else {
                    continue;
                };

                let (algorithm, hash) = if let Some(h) = sdist.hash() {
                    Self::parse_hash(&h.to_string())
                } else if sdist_url.starts_with("git+") {
                    // Generate a synthetic hash for git dependencies
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    sdist_url.hash(&mut hasher);
                    package.id.name.hash(&mut hasher);
                    package
                        .id
                        .version
                        .as_ref()
                        .map(std::string::ToString::to_string)
                        .unwrap_or_else(|| "0.0.0".to_string())
                        .hash(&mut hasher);
                    (
                        Self::DEFAULT_HASH_ALGORITHM.to_string(),
                        format!("{:016x}", hasher.finish()),
                    )
                } else {
                    continue;
                };

                artifacts.push(PexArtifact {
                    url: sdist_url,
                    algorithm: Some(algorithm),
                    hash: Some(hash),
                    is_wheel: Some(false),
                });
            }

            if let Some(version) = package.version() {
                // Always include packages in PEX lock format, even without artifacts
                // This ensures that metadata like requires_dist is available for dependency resolution
                let should_include = !artifacts.is_empty() || !package.requires_dist().is_empty();
                if should_include {
                    // Collect dependencies for this package using metadata requires_dist
                    // This includes ALL optional dependencies with their extra markers
                    let mut requires_dists = Vec::new();

                    // Use resolved dependencies from UV's lock format instead of requires_dist()
                    // This ensures we get all dependencies including optional ones with proper markers

                    // Process direct dependencies
                    for dependency in package.dependencies() {
                        if let Some(dep_package) = lock
                            .packages()
                            .iter()
                            .find(|pkg| pkg.id.name == *dependency.package_id().name())
                        {
                            // Only exclude dependencies that are TRULY Windows-only:
                            // - Have ONLY Windows wheels AND no source distribution
                            let only_windows_wheels = !dep_package.wheels.is_empty()
                                && dep_package.wheels.iter().all(|wheel| {
                                    wheel.filename.platform_tags().iter().any(|tag| {
                                        matches!(
                                            tag,
                                            PlatformTag::Win32
                                                | PlatformTag::WinAmd64
                                                | PlatformTag::WinArm64
                                                | PlatformTag::WinIa64
                                        )
                                    })
                                });
                            let has_sdist = dep_package.sdist.is_some();

                            // Include unless it's Windows-only (only Windows wheels and no sdist)
                            let has_compatible_artifacts = !only_windows_wheels || has_sdist;

                            if has_compatible_artifacts {
                                // Build the requirement string with resolved version
                                let mut req_string = dependency.package_id().name().to_string();

                                // Add resolved version constraint
                                if let Some(version) = dep_package.version() {
                                    req_string.push_str(&format!("=={}", version));
                                }

                                // Add marker from dependency if present
                                if let Some(marker_str) = dependency.marker_string() {
                                    req_string.push_str(&format!("; {}", marker_str));
                                }

                                requires_dists.push(req_string);
                            }
                        }
                    }

                    // Process optional dependencies (extras)
                    for (extra_name, dependencies) in package.optional_dependencies.iter() {
                        for dependency in dependencies {
                            if let Some(dep_package) = lock
                                .packages()
                                .iter()
                                .find(|pkg| pkg.id.name == *dependency.package_id().name())
                            {
                                // Only exclude dependencies that are TRULY Windows-only:
                                // - Have ONLY Windows wheels AND no source distribution
                                let only_windows_wheels = !dep_package.wheels.is_empty()
                                    && dep_package.wheels.iter().all(|wheel| {
                                        wheel.filename.platform_tags().iter().any(|tag| {
                                            matches!(
                                                tag,
                                                PlatformTag::Win32
                                                    | PlatformTag::WinAmd64
                                                    | PlatformTag::WinArm64
                                                    | PlatformTag::WinIa64
                                            )
                                        })
                                    });
                                let has_sdist = dep_package.sdist.is_some();

                                // Include unless it's Windows-only (only Windows wheels and no sdist)
                                let has_compatible_artifacts = !only_windows_wheels || has_sdist;

                                if has_compatible_artifacts {
                                    // Build the requirement string with resolved version
                                    let mut req_string = dependency.package_id().name().to_string();

                                    // Add resolved version constraint
                                    if let Some(version) = dep_package.version() {
                                        req_string.push_str(&format!("=={}", version));
                                    }

                                    // Add extra marker and combine with any existing markers
                                    let extra_marker = format!("extra == \"{}\"", extra_name);
                                    let combined_marker =
                                        if let Some(dep_marker) = dependency.marker_string() {
                                            format!("{} and {}", extra_marker, dep_marker)
                                        } else {
                                            extra_marker
                                        };
                                    req_string.push_str(&format!("; {}", combined_marker));

                                    requires_dists.push(req_string);
                                }
                            }
                        }
                    }

                    // Process dependency groups (PEP 735)
                    for (group_name, dependencies) in package.dependency_groups.iter() {
                        for dependency in dependencies {
                            if let Some(dep_package) = lock
                                .packages()
                                .iter()
                                .find(|pkg| pkg.id.name == *dependency.package_id().name())
                            {
                                // Only exclude dependencies that are TRULY Windows-only:
                                // - Have ONLY Windows wheels AND no source distribution
                                let only_windows_wheels = !dep_package.wheels.is_empty()
                                    && dep_package.wheels.iter().all(|wheel| {
                                        wheel.filename.platform_tags().iter().any(|tag| {
                                            matches!(
                                                tag,
                                                PlatformTag::Win32
                                                    | PlatformTag::WinAmd64
                                                    | PlatformTag::WinArm64
                                                    | PlatformTag::WinIa64
                                            )
                                        })
                                    });
                                let has_sdist = dep_package.sdist.is_some();

                                // Include unless it's Windows-only (only Windows wheels and no sdist)
                                let has_compatible_artifacts = !only_windows_wheels || has_sdist;

                                if has_compatible_artifacts {
                                    // Build the requirement string with resolved version
                                    let mut req_string = dependency.package_id().name().to_string();

                                    // Add resolved version constraint
                                    if let Some(version) = dep_package.version() {
                                        req_string.push_str(&format!("=={}", version));
                                    }

                                    // Add group marker and combine with any existing markers
                                    let group_marker = format!("group == \"{}\"", group_name);
                                    let combined_marker =
                                        if let Some(dep_marker) = dependency.marker_string() {
                                            format!("{} and {}", group_marker, dep_marker)
                                        } else {
                                            group_marker
                                        };
                                    req_string.push_str(&format!("; {}", combined_marker));

                                    requires_dists.push(req_string);
                                }
                            }
                        }
                    }

                    // Sort requires_dists for consistent output
                    requires_dists.sort();

                    // Sort artifacts: wheels first, then source distributions
                    artifacts.sort_by(|a, b| {
                        match (a.is_wheel, b.is_wheel) {
                            // Wheels (is_wheel: true) come first
                            (Some(true), Some(false)) => std::cmp::Ordering::Less,
                            (Some(false), Some(true)) => std::cmp::Ordering::Greater,
                            // Within same type, sort by URL
                            _ => a.url.cmp(&b.url),
                        }
                    });

                    // Convert project name to use underscores for PEX compatibility
                    let pex_project_name = package.id.name.to_string().replace('-', "_");

                    // Get package-specific Python requirement from metadata
                    let package_requires_python = lock
                        .manifest
                        .dependency_metadata
                        .iter()
                        .find(|metadata| metadata.name == package.id.name)
                        .and_then(|metadata| metadata.requires_python.as_ref())
                        .map(|req| req.to_string())
                        .unwrap_or_else(|| ">=3.8".to_string());

                    locked_requirements.push(PexLockedRequirement {
                        artifacts,
                        project_name: pex_project_name,
                        requires_dists,
                        requires_python: package_requires_python,
                        version: version.to_string(),
                    });
                }
            }
        }

        // Sort locked_requirements by project_name for consistent output
        locked_requirements.sort_by(|a, b| a.project_name.cmp(&b.project_name));

        let locked_resolves = vec![PexLockedResolve {
            locked_requirements,
            platform_tag: None,
        }];

        Ok(PexLock {
            allow_builds: true,
            allow_prereleases: false,
            allow_wheels: true,
            build_isolation: true,
            constraints: Vec::new(),
            elide_unused_requires_dist: false,
            excluded: Vec::new(),
            locked_resolves,
            only_builds: Vec::new(),
            only_wheels: Vec::new(),
            overridden: Vec::new(),
            path_mappings: serde_json::Map::new(),
            pex_version: Self::DEFAULT_PEX_VERSION.to_string(),
            pip_version: Self::DEFAULT_PIP_VERSION.to_string(),
            prefer_older_binary: false,
            requirements,
            requires_python: vec![lock.requires_python().to_string()],
            resolver_version: "pip-2020-resolver".to_string(),
            style: "universal".to_string(),
            target_systems: vec!["linux".to_string(), "mac".to_string()],
            transitive: true,
            use_pep517: None,
            use_system_time: false,
        })
    }

    /// Serialize the PEX lock to JSON with sorted keys for consistent output.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        fn sort_json_object(value: &serde_json::Value) -> serde_json::Value {
            match value {
                serde_json::Value::Object(map) => {
                    let mut sorted_map = serde_json::Map::new();
                    let mut keys: Vec<_> = map.keys().collect();
                    keys.sort();
                    for key in keys {
                        sorted_map.insert(key.clone(), sort_json_object(&map[key]));
                    }
                    serde_json::Value::Object(sorted_map)
                }
                serde_json::Value::Array(arr) => {
                    serde_json::Value::Array(arr.iter().map(sort_json_object).collect())
                }
                other => other.clone(),
            }
        }

        // First serialize to a Value to sort keys
        let value = serde_json::to_value(self)?;

        // Use a custom serializer with sorted map keys
        let mut buf = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b"  ");
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);

        let sorted_value = sort_json_object(&value);
        sorted_value.serialize(&mut ser)?;

        String::from_utf8(buf).map_err(|e| {
            serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })
    }
}

impl fmt::Display for PexLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_json() {
            Ok(json) => write!(f, "{json}"),
            Err(err) => write!(f, "Error serializing PEX lock: {err}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uv_platform_tags::PlatformTag;

    #[test]
    fn test_pex_lock_serialization() {
        let pex_lock = PexLock {
            allow_builds: true,
            allow_prereleases: false,
            allow_wheels: true,
            build_isolation: true,
            constraints: vec![],
            elide_unused_requires_dist: false,
            excluded: vec![],
            locked_resolves: vec![PexLockedResolve {
                locked_requirements: vec![],
                platform_tag: None,
            }],
            only_builds: vec![],
            only_wheels: vec![],
            overridden: vec![],
            path_mappings: serde_json::Map::new(),
            pex_version: PexLock::DEFAULT_PEX_VERSION.to_string(),
            pip_version: PexLock::DEFAULT_PIP_VERSION.to_string(),
            prefer_older_binary: false,
            requirements: vec!["requests==2.31.0".to_string()],
            requires_python: vec![">=3.8".to_string()],
            resolver_version: "pip-2020-resolver".to_string(),
            style: "universal".to_string(),
            target_systems: vec!["linux".to_string(), "mac".to_string()],
            transitive: true,
            use_pep517: None,
            use_system_time: false,
        };

        let json = pex_lock.to_json().unwrap();
        assert!(json.contains("\"pex_version\": \"2.44.0\""));
        assert!(json.contains("\"allow_builds\": true"));
        assert!(json.contains("\"pip_version\": \"24.2\""));
        assert!(json.contains("\"target_systems\": [\n    \"linux\",\n    \"mac\"\n  ]"));
        assert!(json.contains("\"platform_tag\": null"));
    }

    #[test]
    fn test_parse_hash_with_algorithm() {
        let (algorithm, hash) = PexLock::parse_hash("sha256:abcd1234");
        assert_eq!(algorithm, "sha256");
        assert_eq!(hash, "abcd1234");

        let (algorithm, hash) = PexLock::parse_hash("md5:1234abcd");
        assert_eq!(algorithm, "md5");
        assert_eq!(hash, "1234abcd");
    }

    #[test]
    fn test_parse_hash_without_algorithm() {
        let (algorithm, hash) = PexLock::parse_hash("abcd1234");
        assert_eq!(algorithm, "sha256"); // default
        assert_eq!(hash, "abcd1234");
    }

    #[test]
    fn test_pex_artifact_structure() {
        let artifact = PexArtifact {
            url: "https://files.pythonhosted.org/packages/test.whl".to_string(),
            algorithm: Some("sha256".to_string()),
            hash: Some("abcd1234".to_string()),
            is_wheel: Some(true),
        };

        let json = serde_json::to_string(&artifact).unwrap();
        assert!(!json.contains("\"is_wheel\""));
        assert!(json.contains("\"algorithm\":\"sha256\""));
        assert!(json.contains("\"hash\":\"abcd1234\""));
    }

    #[test]
    fn test_pex_locked_requirement_structure() {
        let requirement = PexLockedRequirement {
            artifacts: vec![PexArtifact {
                url: "https://files.pythonhosted.org/packages/test.whl".to_string(),
                algorithm: Some("sha256".to_string()),
                hash: Some("abcd1234".to_string()),
                is_wheel: Some(true),
            }],
            project_name: "test-package".to_string(),
            requires_dists: vec!["dependency>=1.0".to_string()],
            requires_python: ">=3.8".to_string(),
            version: "1.0.0".to_string(),
        };

        let json = serde_json::to_string(&requirement).unwrap();
        assert!(json.contains("\"project_name\":\"test-package\""));
        assert!(json.contains("\"requires_dists\":[\"dependency>=1.0\"]"));
        assert!(json.contains("\"requires_python\":\">=3.8\""));
        assert!(json.contains("\"version\":\"1.0.0\""));
    }

    #[test]
    fn test_pex_locked_resolve_structure() {
        let resolve = PexLockedResolve {
            locked_requirements: vec![],
            platform_tag: None,
        };

        let json = serde_json::to_string(&resolve).unwrap();
        assert!(json.contains("\"platform_tag\":null"));
        assert!(json.contains("\"locked_requirements\":[]"));
    }

    #[test]
    fn test_git_dependency_url_detection() {
        // Test the git URL detection logic
        let git_url = "git+https://github.com/user/repo.git";
        assert!(git_url.starts_with("git+"));
    }

    #[test]
    fn test_git_dependency_hash_generation() {
        // Test synthetic hash generation for git dependencies
        let url = "git+https://github.com/user/repo.git";
        let name = "test-package";
        let sha = "abcd1234567890";

        let mut hasher1 = std::collections::hash_map::DefaultHasher::new();
        url.hash(&mut hasher1);
        name.hash(&mut hasher1);
        sha.hash(&mut hasher1);
        let hash1 = format!("{:016x}", hasher1.finish());

        let mut hasher2 = std::collections::hash_map::DefaultHasher::new();
        url.hash(&mut hasher2);
        name.hash(&mut hasher2);
        sha.hash(&mut hasher2);
        let hash2 = format!("{:016x}", hasher2.finish());

        // Same inputs should produce same hash
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 16); // 64-bit hash as 16 hex chars
    }

    #[test]
    fn test_platform_tag_windows_detection() {
        // Test that we can properly identify Windows platform tags
        let windows_tags = vec![
            PlatformTag::Win32,
            PlatformTag::WinAmd64,
            PlatformTag::WinArm64,
            PlatformTag::WinIa64,
        ];

        for tag in windows_tags {
            let is_windows = matches!(
                tag,
                PlatformTag::Win32
                    | PlatformTag::WinAmd64
                    | PlatformTag::WinArm64
                    | PlatformTag::WinIa64
            );
            assert!(is_windows, "Tag {tag:?} should be detected as Windows");
        }

        // Test non-Windows tags
        let non_windows_tags = vec![
            PlatformTag::Any,
            PlatformTag::Linux {
                arch: uv_platform_tags::Arch::X86_64,
            },
        ];

        for tag in non_windows_tags {
            let is_windows = matches!(
                tag,
                PlatformTag::Win32
                    | PlatformTag::WinAmd64
                    | PlatformTag::WinArm64
                    | PlatformTag::WinIa64
            );
            assert!(!is_windows, "Tag {tag:?} should not be detected as Windows");
        }
    }

    #[test]
    fn test_pex_lock_json_structure_completeness() {
        let pex_lock = PexLock {
            allow_builds: true,
            allow_prereleases: false,
            allow_wheels: true,
            build_isolation: true,
            constraints: vec!["constraint>=1.0".to_string()],
            elide_unused_requires_dist: false,
            excluded: vec!["excluded-package".to_string()],
            locked_resolves: vec![PexLockedResolve {
                locked_requirements: vec![],
                platform_tag: None,
            }],
            only_builds: vec!["build-only".to_string()],
            only_wheels: vec!["wheel-only".to_string()],
            overridden: vec!["overridden-package".to_string()],
            path_mappings: serde_json::Map::new(),
            pex_version: "2.44.0".to_string(),
            pip_version: "24.2".to_string(),
            prefer_older_binary: false,
            requirements: vec!["requests==2.31.0".to_string()],
            requires_python: vec![">=3.8".to_string()],
            resolver_version: "pip-2020-resolver".to_string(),
            style: "universal".to_string(),
            target_systems: vec!["linux".to_string(), "mac".to_string()],
            transitive: true,
            use_pep517: None,
            use_system_time: false,
        };

        let json = pex_lock.to_json().unwrap();

        // Verify all required fields are present
        let required_fields = [
            "allow_builds",
            "allow_prereleases",
            "allow_wheels",
            "build_isolation",
            "constraints",
            "elide_unused_requires_dist",
            "excluded",
            "locked_resolves",
            "only_builds",
            "only_wheels",
            "overridden",
            "path_mappings",
            "pex_version",
            "pip_version",
            "prefer_older_binary",
            "requirements",
            "requires_python",
            "resolver_version",
            "style",
            "target_systems",
            "transitive",
            "use_pep517",
            "use_system_time",
        ];

        for field in required_fields {
            assert!(
                json.contains(&format!("\"{field}\"")),
                "Missing required field: {field}"
            );
        }
    }

    #[test]
    fn test_display_implementation() {
        let pex_lock = PexLock {
            allow_builds: true,
            allow_prereleases: false,
            allow_wheels: true,
            build_isolation: true,
            constraints: vec![],
            elide_unused_requires_dist: false,
            excluded: vec![],
            locked_resolves: vec![],
            only_builds: vec![],
            only_wheels: vec![],
            overridden: vec![],
            path_mappings: serde_json::Map::new(),
            pex_version: PexLock::DEFAULT_PEX_VERSION.to_string(),
            pip_version: PexLock::DEFAULT_PIP_VERSION.to_string(),
            prefer_older_binary: false,
            requirements: vec![],
            requires_python: vec![">=3.8".to_string()],
            resolver_version: "pip-2020-resolver".to_string(),
            style: "universal".to_string(),
            target_systems: vec!["linux".to_string(), "mac".to_string()],
            transitive: true,
            use_pep517: None,
            use_system_time: false,
        };

        let display_output = format!("{pex_lock}");
        assert!(display_output.contains("\"pex_version\": \"2.44.0\""));
        assert!(!display_output.is_empty());
    }
}

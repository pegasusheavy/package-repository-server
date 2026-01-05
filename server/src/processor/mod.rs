#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageType {
    Deb,
    Rpm,
    Arch,
    Alpine,
    Cargo,
    Npm,
}

impl PackageType {
    pub fn from_extension(filename: &str) -> Option<Self> {
        let lower = filename.to_lowercase();
        if lower.ends_with(".deb") {
            Some(PackageType::Deb)
        } else if lower.ends_with(".rpm") {
            Some(PackageType::Rpm)
        } else if lower.contains(".pkg.tar") {
            Some(PackageType::Arch)
        } else if lower.ends_with(".apk") {
            Some(PackageType::Alpine)
        } else if lower.ends_with(".crate") {
            Some(PackageType::Cargo)
        } else if lower.ends_with(".tgz") {
            Some(PackageType::Npm)
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PackageType::Deb => "deb",
            PackageType::Rpm => "rpm",
            PackageType::Arch => "arch",
            PackageType::Alpine => "alpine",
            PackageType::Cargo => "cargo",
            PackageType::Npm => "npm",
        }
    }
}

impl std::fmt::Display for PackageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

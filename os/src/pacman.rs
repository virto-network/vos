use crate::Action;
use embedded_io_async::Read;
use heapless::{FnvIndexMap, String, Vec};
use miniserde::Deserialize;

pub async fn load(_action: &str) -> Result<impl Read, ()> {
    // TODO
    Ok(&[0u8; 0][..])
}

type Registry = ();

/// Package manager
pub struct Pacman<'r> {
    registry: &'r Registry,
    pkgs: FnvIndexMap<Id, PkgInfo, { Pacman::MAX_PKG }>,
    bins: FnvIndexMap<Id, BinType, { Pacman::MAX_BIN }>,
}

impl<'r> Pacman<'r> {
    const NAME_LEN: usize = 16;
    const MAX_PKG: usize = 64;
    const MAX_BIN: usize = Self::MAX_PKG * 4;

    pub async fn find(&self, _name: &str) -> Option<(Id, PkgInfo)> {
        None
    }

    pub async fn install(&mut self, name: &str) -> Result<&[Id], ()> {
        let Some((pkg, info)) = self.find(name).await else {
            return Err(());
        };
        for bin in info.bins.iter() {
            self.bins
                .insert(bin.clone(), BinType::Wasm)
                .map_err(|_| ())?;
        }
        self.pkgs.insert(pkg.clone(), info);
        self.pkgs.get(&pkg).map(|p| p.bins.as_slice()).ok_or(())
    }

    pub async fn remove(&self, _name: &str) -> Result<(), ()> {
        Err(())
    }

    pub fn list_pkgs(&self) -> impl Iterator<Item = &Id> {
        self.pkgs.keys()
    }
    pub fn list_bins(&self, pkg: &Id) -> impl Iterator<Item = &Id> {
        self.pkgs
            .get(pkg)
            .map(|p| p.bins.as_slice())
            .unwrap_or(&[])
            .iter()
    }

    pub fn info(&self, pkg: &Id) -> Option<&PkgInfo> {
        self.pkgs.get(pkg)
    }
}

type Id = String<{ Pacman::NAME_LEN }>;
pub struct PkgInfo {
    bins: Vec<Id, 8>,
}

/// A program
pub struct Bin {
    action: Action,
    ty: BinType,
}
#[derive(Copy, Clone)]
pub enum BinType {
    Wasm,
}

impl Bin {
    pub fn ty(&self) -> BinType {
        self.ty
    }
}

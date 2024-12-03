use embassy_executor::SendSpawner;
use heapless::{String, Vec};
use wasmi::Module;

use super::pacman::{Bin, BinType, Cmd};

#[embassy_executor::task]
pub async fn run(s: SendSpawner) {}

/// The capabilities expexted by the prgram for its correct functioning
struct Resources {
    raw_io: bool,
    mount_points: Vec<String<10>, 10>,
}
impl Resources {
    fn get(bin: &Bin) -> Resources {
        match bin.ty() {
            BinType::Wasm => Resources {
                raw_io: true,
                mount_points: Vec::new(),
            },
        }
    }
}

// macro_rules! impl_vm {
//     ($($vm:ident),+) => {
//         #[allow(non_snake_case)]
//         #[derive(Default)]
//         pub struct Vm {
//             $($vm: $vm),+
//         }
//         pub enum Cmd { $($vm(<$vm as super::Runnable>::Cmd)),+ }
//         pub enum Error { $($vm(<$vm as super::Runnable>::Err)),+ }
//         impl super::Runnable for Vm {
//             type Cmd = Cmd;
//             type Err = Error;
//             fn run(&'static self, cmd: Self::Cmd) -> impl core::future::Future<Output = Result<(), Self::Err>> + 'static {
//                 async move {
//                     match cmd {
//                         $( Cmd::$vm(cmd) => self.$vm.run(cmd).await.map_err(|e| Error::$vm(e)), ),+
//                     }
//                 }
//             }
//         }
//     };
// }

// impl_vm!(WasmVm);

// pub mod wasm {
//     use embassy_executor::Spawner;
//     use wasmi::{Linker, Module, Store};

//     use crate::os::Receiver;

//     use super::Loader;

//     #[derive(Default)]
//     pub struct Vm(wasmi::Engine);

//     impl crate::os::Runnable for Vm {
//         type Cmd = &'static str;
//         type Err = wasmi::Error;

//         fn run(
//             &'static self,
//             path: Self::Cmd,
//         ) -> impl core::future::Future<Output = Result<(), Self::Err>> + 'static {
//             async {
//                 let wasm = Loader::load(path).await;
//                 let module = Module::new(&self.0, &wasm)?;
//                 let mut store = Store::new(&self.0, ());
//                 let linker = <Linker<()>>::new(&self.0);
//                 let instance = linker.instantiate(&mut store, &module)?.start(&mut store)?;
//                 let hello = instance.get_typed_func::<(), ()>(&store, "hello")?;
//                 hello.call(store, ());
//                 Ok(())
//             }
//         }
//     }

//     #[embassy_executor::task]
//     async fn foo(s: Spawner, rx: Receiver<'static, ()>) {
//         loop {
//             let cmd = rx.receive().await;
//             s.spawn(run_cmd(cmd));
//         }
//     }

//     #[embassy_executor::task]
//     async fn run_cmd(_cmd: ()) {}
// }

// pub struct Loader;
// impl Loader {
//     async fn load(_path: &str) -> Vec<u8> {
//         Vec::new()
//     }
// }

use alloc::boxed::Box;
use static_cell::ConstStaticCell;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::{js_sys::global, DedicatedWorkerGlobalScope, MessageEvent};

use super::{Input, Io, Output};
use crate::os::{Channel, Receiver, Sender};

pub struct WorkerIo {
    ch_in: &'static Channel<Input>,
    ch_out: &'static Channel<Output>,
    _on_msg: JsValue,
}

impl Io for WorkerIo {
    type Cfg = ();

    async fn connection(_cfg: Self::Cfg) -> Self {
        // in web we only expect one persistent connection with the main thread
        static IN: ConstStaticCell<Channel<Input>> = ConstStaticCell::new(Channel::new());
        static OUT: ConstStaticCell<Channel<Output>> = ConstStaticCell::new(Channel::new());

        let ch_in = IN.take();
        let ch_out = OUT.take();
        let _on_msg = Self::setup_worker(ch_in.sender(), ch_out.receiver());
        Self {
            ch_in,
            ch_out,
            _on_msg,
        }
    }
    fn io_stream(&self) -> super::Stream {
        (self.ch_in.receiver(), self.ch_out.sender())
    }
}

impl WorkerIo {
    fn setup_worker(input: Sender<'static, Input>, output: Receiver<'static, Output>) -> JsValue {
        let worker = global()
            .dyn_into::<DedicatedWorkerGlobalScope>()
            .expect("worker");

        spawn_local(async move {
            let worker = global().unchecked_into::<DedicatedWorkerGlobalScope>();
            loop {
                let out = output.receive().await;
                let out = serde_wasm_bindgen::to_value(&out).expect("output serialized");
                worker.post_message(&out).expect("output sent");
            }
        });

        let cb = Closure::wrap(Box::new(move |event| {
            spawn_local(async move {
                if let Err(err) = Self::process_worker_message(input, event).await {
                    log::error!(
                        "{}",
                        &err.as_string()
                            .unwrap_or_else(|| "incoming message error".into())
                    )
                }
            })
        }) as Box<dyn FnMut(MessageEvent)>);
        let on_msg = cb.into_js_value();
        worker.set_onmessage(Some(on_msg.unchecked_ref()));

        on_msg
    }

    async fn process_worker_message(
        sender: Sender<'_, Input>,
        event: MessageEvent,
    ) -> Result<(), JsValue> {
        // let Ok(message) = event.data().dyn_into::<Object>() else {
        //     return Ok(());
        // };
        let input: Input = serde_wasm_bindgen::from_value(event.data())?;
        // let id = Reflect::get(&message, &"id".into())?
        //     .as_f64()
        //     .ok_or("Missing msg id")?
        //     .round() as u32;
        // let cmd = Reflect::get(&message, &"cmd".into())?
        //     .as_string()
        //     .ok_or("Invalid command")?;

        sender.send(input).await;
        Ok(())
    }
}

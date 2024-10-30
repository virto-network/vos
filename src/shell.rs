use std::pin::Pin;

use futures_util::{SinkExt, StreamExt};
use matrix_sdk::{ruma::UserId, Client as MxClient, Room};

pub mod io;

/// A reference to a matrix room where programs can be executed
pub struct Session {
    in_stream: Pin<Box<dyn io::InputStream>>,
    mx: Option<MxClient>,
    cwr: Option<Room>,
}

impl Session {
    pub fn new(input: impl io::InputStream) -> Self {
        Self {
            in_stream: Box::pin(input),
            mx: None,
            cwr: None,
        }
    }

    pub async fn process_input_stream(mut self, mut out: Pin<Box<dyn io::OutputSink>>) {
        while let Some(input) = self.in_stream.next().await {
            out.send(self.handle_input(input).await)
                .await
                .unwrap_or_else(|_| {
                    log::warn!("failed sending output");
                });
        }
    }

    async fn handle_input(&mut self, input: io::Input) -> io::Result {
        use io::{Input::*, Output};
        if !self.mx.as_ref().is_some_and(|m| m.logged_in()) {
            return Ok(Output::WaitingAuth([0; 32]));
        }
        Ok(match input {
            Empty => todo!(),
            Auth(user, auth) => todo!(),
            Prompt(_) => todo!(),
            Open(_) => todo!(),
            Answer(_) => todo!(),
            Data(_) => todo!(),
        })
    }

    // pub async fn connect(&mut self, user: &str, credentials: Auth) -> io::Result {
    //     let mid = UserId::parse(user).map_err(|_| ())?;
    //     let mx = MxClient::new(mid.server_name().as_str().try_into().unwrap())
    //         .await
    //         .map_err(|_| ())?;

    //     let auth = mx.matrix_auth();
    //     let flows = auth.get_login_types().await.map_err(|_| ())?.flows;
    //     log::info!("{:?}", flows);

    //     match credentials {
    //         Auth::Pwd { user: _, pwd: _ } => todo!(),
    //         Auth::Authenticator(_) => todo!(),
    //     }

    //     self.mx.replace(mx);
    //     Ok(Output::Empty)
    // }
}

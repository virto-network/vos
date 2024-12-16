use picoserve::{
    extract::Form,
    io,
    request::Request,
    response::{
        sse::{EventSource, EventWriter},
        EventStream, IntoResponse, Response, ResponseWriter, StatusCode,
    },
    routing::{get, post, post_service, PathRouter, RequestHandlerService},
    ResponseSent, Router,
};

pub fn api() -> Router<impl PathRouter> {
    Router::new()
        .route("/prompt", post(handle_cmd))
        .route("/data", post_service(Data))
        .route("/events", get(|| EventStream(Events)))
}

struct Data;
impl RequestHandlerService<()> for Data {
    async fn call_request_handler_service<R, W>(
        &self,
        _state: &(),
        _params: (),
        req: Request<'_, R>,
        w: W,
    ) -> Result<ResponseSent, W::Error>
    where
        R: io::Read,
        W: ResponseWriter<Error = R::Error>,
    {
        let headers = req.parts.headers();
        if !matches!(headers.get("Content-Type"), Some(ct) if ct == "multipart/form-data") {
            return StatusCode::UNSUPPORTED_MEDIA_TYPE
                .write_to(req.body_connection.finalize().await?, w)
                .await;
        }
        // TODO parse multipart
        Response::ok("")
            .write_to(req.body_connection.finalize().await?, w)
            .await
    }
}

#[derive(serde::Deserialize)]
pub struct Prompt {
    id: u16,
    cmd: String,
}

pub async fn handle_cmd(Form(Prompt { id, cmd }): Form<Prompt>) -> String {
    format!("got {id}:{cmd}!")
}

struct Events;
impl EventSource for Events {
    async fn write_events<W: io::Write>(self, mut w: EventWriter<W>) -> Result<(), W::Error> {
        w.write_event("test", "todo!").await
    }
}

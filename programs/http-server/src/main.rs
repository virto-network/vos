use picoserve::{serve, Config, Router, Timeouts};
use picoserve_wasi::{WasiSocket, WasiTimer};
use wstd::{io, iter::AsyncIterator as _, net::TcpListener, time::Duration};

mod shell_io;

const CONF: Config<Duration> = Config::new(Timeouts {
    start_read_request: None,
    read_request: None,
    write: None,
});

#[wstd::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:12345").await?;
    println!("Listening on {}", listener.local_addr()?);

    let app = Router::new().nest("/io", shell_io::api());

    let mut incoming = listener.incoming();
    while let Some(stream) = incoming.next().await {
        let stream = stream?;
        match serve(&app, WasiTimer, &CONF, &mut [0; 2048], WasiSocket(stream)).await {
            Ok(n) => println!("served {n} requests"),
            Err(e) => eprintln!("{e:?}"),
        }
    }
    Ok(())
}

mod picoserve_wasi {
    use picoserve::{
        io::{Error, ErrorKind, ErrorType, Read, Socket, Write},
        Timer,
    };
    use wstd::future::FutureExt;
    use wstd::io::{AsyncRead, AsyncWrite};
    use wstd::net::TcpStream;

    pub struct WasiTimer;
    impl Timer for WasiTimer {
        type Duration = wstd::time::Duration;
        type TimeoutError = std::io::Error;

        async fn run_with_timeout<F: core::future::Future>(
            &mut self,
            duration: Self::Duration,
            future: F,
        ) -> Result<F::Output, Self::TimeoutError> {
            future.timeout(duration).await
        }
    }

    #[derive(Debug)]
    pub struct WasiIoError;
    impl Error for WasiIoError {
        fn kind(&self) -> ErrorKind {
            ErrorKind::Other
        }
    }

    pub struct ReadHalf<'a>(&'a TcpStream);
    pub struct WriteHalf<'a>(&'a TcpStream);

    impl<'a> ErrorType for ReadHalf<'a> {
        type Error = WasiIoError;
    }
    impl<'a> ErrorType for WriteHalf<'a> {
        type Error = WasiIoError;
    }

    impl<'a> Read for ReadHalf<'a> {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            self.0.read(buf).await.map_err(|_| WasiIoError)
        }
    }

    impl<'a> Write for WriteHalf<'a> {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.0.write(buf).await.map_err(|_| WasiIoError)
        }
    }

    pub struct WasiSocket(pub TcpStream);
    impl Socket for WasiSocket {
        type Error = WasiIoError;
        type ReadHalf<'a> = ReadHalf<'a>;
        type WriteHalf<'a> = WriteHalf<'a>;

        fn split(&mut self) -> (Self::ReadHalf<'_>, Self::WriteHalf<'_>) {
            (ReadHalf(&self.0), WriteHalf(&self.0))
        }

        async fn shutdown<Timer: picoserve::Timer>(
            mut self,
            timeouts: &picoserve::Timeouts<Timer::Duration>,
            timer: &mut Timer,
        ) -> Result<(), picoserve::Error<Self::Error>> {
            let (rx, tx) = self.split();
            if let Some(timeout) = timeouts.write.clone() {
                timer
                    .run_with_timeout(timeout, flush(tx))
                    .await
                    .map_err(|_| picoserve::Error::WriteTimeout)??;
            } else {
                flush(tx).await?;
            }
            if let Some(timeout) = timeouts.read_request.clone() {
                timer
                    .run_with_timeout(timeout, read_all(rx))
                    .await
                    .map_err(|_| picoserve::Error::ReadTimeout)??;
            } else {
                read_all(rx).await?;
            }
            Ok(())
        }
    }

    async fn read_all<'a>(mut rx: ReadHalf<'a>) -> Result<usize, picoserve::Error<WasiIoError>> {
        let mut buf = [0; 128];
        rx.0.read(&mut buf)
            .await
            .map_err(|_| picoserve::Error::Read(WasiIoError))
    }
    async fn flush<'a>(mut tx: WriteHalf<'a>) -> Result<(), picoserve::Error<WasiIoError>> {
        tx.0.flush()
            .await
            .map_err(|_| picoserve::Error::Write(WasiIoError))
    }
}

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use http_body::Body;

pub trait BodyExt: Body + Sized {
    /// Wraps a `Body` into a type that implements `Stream`.
    fn into_stream(self) -> IntoStream<Self>;
}

#[pin_project::pin_project]
pub struct IntoStream<B> {
    #[pin]
    body: B,
}

impl<B: Body> BodyExt for B {
    fn into_stream(self) -> IntoStream<Self> {
        IntoStream { body: self }
    }
}

impl<B: Body> Stream for IntoStream<B> {
    type Item = Result<B::Data, B::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().body.poll_data(cx)
    }
}

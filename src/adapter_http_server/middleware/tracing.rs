use tower_http::{
    classify::{ServerErrorsAsFailures, SharedClassifier},
    trace::{
        DefaultOnBodyChunk, DefaultOnEos, MakeSpan, OnEos, OnFailure, OnRequest, OnResponse,
        TraceLayer,
    },
};

pub fn layer() -> TraceLayer<
    SharedClassifier<ServerErrorsAsFailures>,
    SpanCreator,
    EventBuilder,
    EventBuilder,
    DefaultOnBodyChunk,
    DefaultOnEos,
    EventBuilder,
> {
    TraceLayer::new_for_http()
        .make_span_with(SpanCreator)
        .on_request(EventBuilder)
        .on_response(EventBuilder)
        .on_failure(EventBuilder)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SpanCreator;

impl<B> MakeSpan<B> for SpanCreator {
    fn make_span(&mut self, req: &http::Request<B>) -> tracing::Span {
        let uri = req.uri();
        let span_name = format!("{} {uri}", req.method());
        let span = tracing::info_span!(
            parent: None,
            "http.server.request",
            "error.type" = tracing::field::Empty,
            "exception.message" = tracing::field::Empty,
            "exception.stacktrace" = tracing::field::Empty,
            "http.request.header" = ?req.headers(),
            "http.request.method" = %req.method(),
            "http.response.status_code" = tracing::field::Empty,
            "network.protocol.version" = ?req.version(),
            "otel.kind" = "server",
            "otel.name" = span_name,
            "otel.status_code" = tracing::field::Empty,
            "otel.status_description" = tracing::field::Empty,
            "resource.name" = span_name,
            "server.address" = tracing::field::Empty,
            "server.port" = tracing::field::Empty,
            "span.name" = span_name,
            "span.kind" = "server",
            "span.type" = "web",
            "url.full" = %uri,
            "url.path" = uri.path(),
            "url.query" = tracing::field::Empty,
            "url.scheme" = tracing::field::Empty,
        );
        if let Some(query) = uri.query() {
            span.record("url.query", query);
        }
        if let Some(scheme) = uri.scheme_str() {
            span.record("url.scheme", scheme);
        }
        if let Some(host) = uri.host() {
            span.record("server.address", host);
        }
        if let Some(port) = uri.port_u16() {
            span.record("server.port", port);
        }
        span
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct EventBuilder;

impl<B> OnRequest<B> for EventBuilder {
    fn on_request(&mut self, _req: &axum::extract::Request<B>, _span: &tracing::Span) {
        tracing::info!("request started");
    }
}

impl<B> OnResponse<B> for EventBuilder {
    fn on_response(
        self,
        res: &http::Response<B>,
        latency: std::time::Duration,
        span: &tracing::Span,
    ) {
        span.record("http.response.status_code", res.status().as_str());

        tracing::info!(latency_ns = latency.as_nanos(), "request processed");
    }
}

impl<F> OnFailure<F> for EventBuilder
where
    F: std::fmt::Display,
{
    fn on_failure(
        &mut self,
        failure_classification: F,
        latency: std::time::Duration,
        span: &tracing::Span,
    ) {
        span.record("error.type", "server");
        span.record("exception.message", failure_classification.to_string());
        span.record("otel.status_code", "error");
        span.record(
            "otel.status_description",
            failure_classification.to_string(),
        );

        tracing::info!(
            error = %failure_classification,
            latency_ns = latency.as_nanos(),
            "response failed",
        );
    }
}

impl OnEos for EventBuilder {
    fn on_eos(
        self,
        _trailers: Option<&http::HeaderMap>,
        stream_duration: std::time::Duration,
        _span: &tracing::Span,
    ) {
        tracing::debug!(
            stream_duration_ns = stream_duration.as_nanos(),
            "end of stream",
        );
    }
}

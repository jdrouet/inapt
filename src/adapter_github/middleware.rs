use opentelemetry_semantic_conventions::attribute as semver;
use reqwest::Request;
use reqwest_middleware::Middleware;
use reqwest_tracing::OtelPathNames;
use tracing::Instrument;

#[derive(Clone, Debug, Default)]
pub struct TracingMiddleware;

#[async_trait::async_trait]
impl Middleware for TracingMiddleware {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        let span_name = create_span_name(&req, extensions);
        let span = tracing::info_span!(
            "http.client.request",
            "error.type" = tracing::field::Empty,
            "error.message" = tracing::field::Empty,
            "error.stacktrace" = tracing::field::Empty,
            "http.request.method" = %req.method(),
            "http.response.status_code" = tracing::field::Empty,
            "network.protocol.name" = "http",
            "network.protocol.version" = ?req.version(),
            "otel.kind" = "client",
            "otel.name" = span_name,
            "otel.status_code" = tracing::field::Empty,
            "otel.status_description" = tracing::field::Empty,
            "peer.service" = "github",
            "resource.name" = span_name,
            "server.address" = tracing::field::Empty,
            "server.port" = tracing::field::Empty,
            "span.kind" = "client",
            "span.type" = "http",
            "span.name" = span_name,
            "url.path" = req.url().path(),
            "url.scheme" = req.url().scheme(),
            // deprecated
            "http.host" = tracing::field::Empty,
            "http.method" = %req.method(),
            "http.scheme" = req.url().scheme(),
            "net.host.port" = tracing::field::Empty,
        );
        if let Some(host) = req.url().host_str() {
            span.record("server.address", host);
            span.record("http.host", host);
        }
        if let Some(port) = req.url().port() {
            span.record("server.port", port);
            span.record("net.host.port", port);
        }

        let _ = span.enter();
        next.run(req, extensions)
            .instrument(span.clone())
            .await
            .inspect(|res| {
                let status = res.status();
                if status.is_server_error() {
                    span.record(semver::ERROR_TYPE, "server");
                    span.record(semver::OTEL_STATUS_CODE, "ERROR");
                    if let Some(msg) = status.canonical_reason() {
                        span.record(semver::OTEL_STATUS_DESCRIPTION, msg);
                    }
                } else if status.is_client_error() {
                    span.record(semver::ERROR_TYPE, "client");
                    span.record(semver::OTEL_STATUS_CODE, "ERROR");
                    if let Some(msg) = status.canonical_reason() {
                        span.record(semver::OTEL_STATUS_DESCRIPTION, msg);
                    }
                } else {
                    span.record(semver::OTEL_STATUS_CODE, "OK");
                }
                span.record(semver::HTTP_RESPONSE_STATUS_CODE, res.status().as_str());
            })
            .inspect_err(|err| {
                span.record(semver::OTEL_STATUS_CODE, "ERROR");
                span.record(semver::OTEL_STATUS_DESCRIPTION, err.to_string());
                span.record("error.message", err.to_string());
                span.record("error.stacktrace", format!("{err:?}"));
                if let Some(code) = err.status() {
                    span.record(semver::HTTP_RESPONSE_STATUS_CODE, code.as_str());
                    span.record(
                        semver::ERROR_TYPE,
                        if code.is_client_error() {
                            "client"
                        } else {
                            "server"
                        },
                    );
                } else {
                    span.record(semver::ERROR_TYPE, "client");
                }
            })
    }
}

fn create_span_name(req: &Request, ext: &http::Extensions) -> String {
    if let Some(path_names) = ext.get::<OtelPathNames>() {
        path_names
            .find(req.url().path())
            .map(|path| format!("{} {}", req.method(), path))
            .unwrap_or_else(|| {
                tracing::warn!("no OTEL path name found");
                format!("{} {}", req.method(), req.url().path())
            })
    } else {
        format!("{} {}", req.method(), req.url().path())
    }
}

use std::borrow::Cow;

use anyhow::Context;
use opentelemetry::trace::TracerProvider;
use opentelemetry::{InstrumentationScope, KeyValue};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::tonic_types::transport::ClientTlsConfig;
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::{BatchSpanProcessor, SdkTracerProvider};
use opentelemetry_semantic_conventions::attribute as semconv;
use tracing::level_filters::LevelFilter;
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

fn with_env_or<T>(name: &str, default_value: T) -> Cow<'static, str>
where
    T: Into<Cow<'static, str>>,
{
    std::env::var(name)
        .ok()
        .map(Cow::Owned)
        .unwrap_or_else(|| default_value.into())
}

fn with_env_as_or<T>(name: &str, default_value: T) -> anyhow::Result<T>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    let Ok(value) = std::env::var(name) else {
        return Ok(default_value);
    };
    value
        .parse::<T>()
        .with_context(|| format!("unable to parse value from {name:?}"))
}

pub enum Config {
    Console(ConsoleConfig),
    Otel(OtelConfig),
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        match std::env::var("TRACING_MODE").as_deref() {
            Ok("console") | Err(_) => Ok(Self::Console(ConsoleConfig::from_env()?)),
            Ok("otel") | Ok("opentelemetry") => Ok(Self::Otel(OtelConfig::from_env()?)),
            Ok(other) => Err(anyhow::anyhow!("unknown tracing mode {other:?}")),
        }
    }

    pub fn install(self) -> anyhow::Result<TracingProvider> {
        match self {
            Self::Console(inner) => inner.install(),
            Self::Otel(inner) => inner.install(),
        }
    }
}

pub struct ConsoleConfig {
    color: bool,
}

impl ConsoleConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            color: with_env_as_or("TRACING_CONSOLE_COLOR", true)?,
        })
    }

    fn install(self) -> anyhow::Result<TracingProvider> {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_ansi(self.color))
            .with(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .with_env_var("TRACING_LEVEL")
                    .from_env_lossy(),
            )
            .try_init()?;
        Ok(TracingProvider::Console)
    }
}

pub struct OtelConfig {
    endpoint: Cow<'static, str>,
    internal_level: Cow<'static, str>,
    environment: Cow<'static, str>,
}

impl OtelConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            endpoint: with_env_or("TRACING_OTEL_ENDPOINT", "http://localhost:4317"),
            internal_level: with_env_or("TRACING_OTEL_INTERNAL_LEVEL", "error"),
            environment: with_env_or("ENV", "local"),
        })
    }

    fn attributes(&self) -> Vec<KeyValue> {
        let mut attrs = vec![
            // Service attributes
            KeyValue::new(semconv::SERVICE_NAME, env!("CARGO_PKG_NAME")),
            KeyValue::new(semconv::SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
            // Deployment attributes
            KeyValue::new(
                semconv::DEPLOYMENT_ENVIRONMENT_NAME,
                self.environment.to_string(),
            ),
            // Process attributes
            KeyValue::new(semconv::PROCESS_PID, std::process::id() as i64),
        ];

        // Process executable info
        if let Ok(exe_path) = std::env::current_exe() {
            attrs.push(KeyValue::new(
                semconv::PROCESS_EXECUTABLE_PATH,
                exe_path.to_string_lossy().into_owned(),
            ));
            if let Some(exe_name) = exe_path.file_name() {
                attrs.push(KeyValue::new(
                    semconv::PROCESS_EXECUTABLE_NAME,
                    exe_name.to_string_lossy().into_owned(),
                ));
            }
        }

        // Process command arguments
        let args: Vec<String> = std::env::args().collect();
        if !args.is_empty() {
            attrs.push(KeyValue::new(
                semconv::PROCESS_COMMAND_ARGS,
                format!("{:?}", args),
            ));
        }

        // OS attributes
        attrs.push(KeyValue::new(semconv::OS_TYPE, std::env::consts::OS));

        // Host attributes
        if let Ok(hostname) = hostname::get() {
            attrs.push(KeyValue::new(
                semconv::HOST_NAME,
                hostname.to_string_lossy().into_owned(),
            ));
        }
        attrs.push(KeyValue::new(semconv::HOST_ARCH, std::env::consts::ARCH));

        attrs
    }

    fn resources(&self) -> Resource {
        Resource::builder()
            .with_attributes(self.attributes())
            .build()
    }

    fn metric_provider(&self) -> anyhow::Result<opentelemetry_sdk::metrics::SdkMeterProvider> {
        let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_protocol(opentelemetry_otlp::Protocol::Grpc)
            .with_endpoint(self.endpoint.as_ref())
            .with_tls_config(ClientTlsConfig::new().with_enabled_roots())
            .build()?;

        Ok(opentelemetry_sdk::metrics::MeterProviderBuilder::default()
            .with_periodic_exporter(metric_exporter)
            .with_resource(self.resources())
            .build())
    }

    fn tracer_provider(&self) -> anyhow::Result<opentelemetry_sdk::trace::SdkTracerProvider> {
        let trace_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_protocol(opentelemetry_otlp::Protocol::Grpc)
            .with_endpoint(self.endpoint.as_ref())
            .with_tls_config(ClientTlsConfig::new().with_enabled_roots())
            .build()?;

        let trace_processor = BatchSpanProcessor::builder(trace_exporter).build();

        Ok(opentelemetry_sdk::trace::TracerProviderBuilder::default()
            .with_span_processor(trace_processor)
            .with_resource(self.resources())
            .build())
    }

    fn logger_provider(&self) -> anyhow::Result<opentelemetry_sdk::logs::SdkLoggerProvider> {
        let log_exporter = opentelemetry_otlp::LogExporter::builder()
            .with_tonic()
            .with_protocol(opentelemetry_otlp::Protocol::Grpc)
            .with_endpoint(self.endpoint.as_ref())
            .with_tls_config(ClientTlsConfig::new().with_enabled_roots())
            .build()?;

        Ok(opentelemetry_sdk::logs::SdkLoggerProvider::builder()
            .with_resource(self.resources())
            .with_batch_exporter(log_exporter)
            .build())
    }

    fn internal_filter(&self) -> EnvFilter {
        EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .with_env_var("TRACING_LEVEL")
            .from_env_lossy()
            .add_directive(
                format!("opentelemetry={}", self.internal_level)
                    .parse()
                    .unwrap(),
            )
    }

    fn install(self) -> anyhow::Result<TracingProvider> {
        let scope = InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
            .with_version(env!("CARGO_PKG_VERSION"))
            .with_schema_url(opentelemetry_semantic_conventions::SCHEMA_URL)
            .with_attributes(self.attributes())
            .build();

        let metric = self.metric_provider()?;
        let tracer = self.tracer_provider()?;
        let logger = self.logger_provider()?;

        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
        opentelemetry::global::set_meter_provider(metric.clone());
        opentelemetry::global::set_tracer_provider(tracer.clone());

        let trace = tracer.tracer_with_scope(scope.clone());

        tracing_subscriber::registry()
            .with(self.internal_filter())
            .with(OpenTelemetryLayer::new(trace))
            .with(MetricsLayer::new(metric.clone()))
            .with(OpenTelemetryTracingBridge::new(&logger))
            .try_init()?;

        Ok(TracingProvider::Otel {
            logger,
            metric,
            tracer,
        })
    }
}

pub enum TracingProvider {
    Console,
    Otel {
        logger: SdkLoggerProvider,
        metric: SdkMeterProvider,
        tracer: SdkTracerProvider,
    },
}

impl TracingProvider {
    pub fn shutdown(self) {
        match self {
            Self::Console => {}
            Self::Otel {
                logger,
                metric,
                tracer,
            } => {
                if let Err(err) = logger.shutdown() {
                    tracing::warn!(message = "failed shutting down logger provider", error = ?err);
                }
                if let Err(err) = metric.shutdown() {
                    tracing::warn!(message = "failed shutting down metric provider", error = ?err);
                }
                if let Err(err) = tracer.shutdown() {
                    tracing::warn!(message = "failed shutting down trace provider", error = ?err);
                }
            }
        }
    }
}

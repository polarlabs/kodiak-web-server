use kodiak_web_server::Config;
use env_logger::Target;
use log::LevelFilter;

pub fn init_logger(config: &Config) {
    let mut builder = env_logger::builder();

    builder.target(Target::Stdout);
    builder.filter_module("kodiak_web_server", LevelFilter::from(config.log_level()));
    builder.filter_level(LevelFilter::Warn);

    builder.format_level(true);
    builder.format_timestamp_micros();
    builder.format_indent(None);
    builder.format_module_path(true);
    builder.format_target(false);

    builder.init();
}

# Kodiak web server

Kodiak web server is part of Kodiak's architecture. It is developed in Rust and delivered 
as a Docker image including the [Kodiak web client](https://github.com/polarlabs/kodiak-web-client).

# Roadmap

## Version 0.4.0 (planned)

:pencil: tbd

## Version 0.3.0 (planned)

:pencil: Support user authentication.

## Version 0.2.0 (in progress)

:heavy_check_mark: Support HTTPS: achieve an overall rating of 'A' at [ssllabs.com](https://www.ssllabs.com/ssltest/index.html).

:heavy_check_mark: Enforce HTTPS, i.e. redirect any traffic on port HTTP (8080) to HTTPS (8443).

:heavy_check_mark: Automate HTTPS certificate management via Let's encrypt.

:pencil: Deploy to kodiak.polarlabs.dev.

:pencil: Provide CRUD operations for `Schemas` via REST API.

:pencil: Allow to create `Concepts` via REST API.

:pencil: Update connected clients via WebSocket.
 
:pencil: Use database migration scripts to create and maintain database schema.

:pencil: Implement a logging facility.

:pencil: Run Kodiak's web server as non-root within Docker container.

## Version 0.1.0 (delivered)

:heavy_check_mark: Initial release.

# Supported database engines

Kodiak is going to support SQLite first. However, the SQL library Kodiak is based on, also supports 
PostgreSQL and MySQL. So, extending support to other database engines will be on the roadmap at some 
time in the future.

# Coding principles

12-factor app
https://12factor.net/

Clean code principles: see book.

## Error handling

Kodiak's Error system should cover the whole server
i.e. all third party errors have to be translated into Kodiak own errors.
[Custom error types](https://www.gyata.ai/rust/custom-error-types-and-traits)

## Build release

Use 

    cargo run --no-default-features

to disable development specific settings, dependencies and code.

# Configuration

Hierarchie, i.e. config parameters provided as command line options overwrite env variables, 
overwrite settings from configuration files.

1. Command Line Options
2. Environment Variables
3. Configuration Files

# Links

[SQLite as an Application File Format](https://www.sqlite.org/appfileformat.html)

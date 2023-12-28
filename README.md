# Kodiak web server

Kodiak web server is part of Kodiak's architecture. It is developed in Rust and delivered 
as a Docker image including the [Kodiak web client](https://github.com/polarlabs/kodiak-web-client).

# Roadmap

## Version 0.4.0 (planned)

tbd

## Version 0.3.0 (planned)

- Support user authentication.

## Version 0.2.0 (in progress)

- Enforce HTTPS, i.e. redirecting any traffic on port 80 to 443.
- Automate HTTPS certificate management via Let's encrypt. 
- Deploy to kodiak.polarlabs.dev.
- Provide CRUD operations for `Namespaces` via REST API.
- Update connected clients via WebSocket.
- Use database migration scripts to create and maintain database schema.
- Implement a logging facility.
- Run Kodiak's web server as non-root within Docker container.

## Version 0.1.0 (delivered)

- Initial release.

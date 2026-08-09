# NetOps Examples

Every value in this directory is synthetic. IPv4 addresses use RFC 5737
documentation networks, domains use `.example`, and MAC addresses use the
locally administered range.

- `profiles/profile.toml` is a neutral profile starting point.
- `channels/` contains declarative ingest examples.
- `data/` contains matching offline fixtures.
- `drivers/` demonstrates a read-only declarative device driver.

Copy only the examples you intend to use into the active profile paths shown by
`netops profile paths`. Review every path, URL, field map, and capability before
enabling a channel or driver.

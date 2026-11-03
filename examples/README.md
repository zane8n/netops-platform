# Netrune Examples

Every value in this directory is synthetic. IPv4 addresses use RFC 5737
documentation networks, domains use `.example`, and MAC addresses use the
locally administered range.

- `profiles/profile.toml` is a neutral profile starting point.
- `channels/` contains declarative ingest examples.
- `data/` contains matching offline fixtures.
- `drivers/` demonstrates a read-only declarative device driver.
- `maps/` holds a network map in the text format and the same kind of map as a
  CSV of links, for `netrune map import` (handbook section 21B).

Copy only the examples you intend to use into the active profile paths shown by
`netrune profile paths`. Review every path, URL, field map, and capability before
enabling a channel or driver.

# Third-Party Notices

NetOps depends on third-party Python packages whose licenses are distributed by
their respective packages. Direct runtime dependencies include Rich and
Textual. Development and release tooling may additionally use pytest,
pytest-asyncio, pytest-textual-snapshot, build, and Twine.

The WebUI uses Vue and Tabler, with Vite, Tailwind CSS, and TypeScript in its
build toolchain. `webui/package-lock.json` records the complete locked frontend
dependency graph used for reproducible builds.

Vendor and product names such as Cisco, Aruba, RUCKUS, SmartZone, NetBox, Linux,
and Windows are trademarks of their respective owners. Their use describes
interoperability and does not imply endorsement.

Generated release SBOMs record the declared Python dependency inventory for a
given artifact; the frontend lockfile records the WebUI build graph. Run
`python build_release.py --help` to create checksums, an SBOM, and provenance
metadata for a release directory.

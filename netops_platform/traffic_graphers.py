"""Grapher adapters: one neutral dashboard model, several renderers.

Netrune's data is already tool-neutral. It publishes Prometheus exposition,
VictoriaMetrics stores it, and anything that speaks the Prometheus query API can
query it -- Grafana, Perses, vmui, or something not written yet. The only
tool-specific things left are the dashboard file format and how the tool is
deployed, which is exactly what an adapter here supplies.

Adding a grapher means implementing `Grapher` and registering it. Nothing in the
collector, the exposition, the storage, or the dashboard definitions changes,
because none of them ever refers to a particular tool.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Protocol, Sequence

from netops_platform.traffic_dashboards import (
    Dashboard, Level, Panel, PanelKind, Unit, Variable)


class Grapher(Protocol):
    """What Netrune needs from a dashboard tool to drive it from files."""

    name: str
    display_name: str
    default_port: int
    #: Container image, or "" when the tool is expected on the host.
    image: str

    def files(self, dashboards: Sequence[Dashboard], datasource_url: str,
              root: Path) -> Dict[Path, str]:
        """Provisioning files, keyed by the path each belongs at."""

    def container_mounts(self, root: Path) -> List[str]:
        """`-v` arguments that put those files where the tool reads them."""

    def container_env(self) -> Dict[str, str]:
        """Environment the container needs, if any."""

    def container_args(self) -> List[str]:
        """Extra `docker run` arguments the tool needs."""

    def dashboard_url(self, base_url: str, dashboard: Dashboard) -> str:
        """Where a human opens one dashboard."""

    def health_path(self) -> str:
        """A path that answers 200 when the tool is ready."""

    def resolve_datasource_url(self, vm_url: str, containerized: bool) -> str:
        """The storage URL from this grapher's own point of view.

        A grapher that proxies queries through its own process reads this from
        inside its container, where 127.0.0.1 is the container. One that has the
        browser fetch directly reads it on the host, where 127.0.0.1 is correct.
        """


# ---------------------------------------------------------------------------
# Grafana
# ---------------------------------------------------------------------------

GRAFANA_UNITS = {
    Unit.BITS_PER_SECOND: "bps",
    Unit.PACKETS_PER_SECOND: "pps",
    Unit.PERCENT: "percent",
    Unit.RATIO: "percentunit",
    Unit.SECONDS: "s",
    Unit.COUNT: "short",
    Unit.CELSIUS: "celsius",
}


#: Status colours are reserved for state and never used to tell series apart.
#: Every tile shows its title and value too, so state is never colour alone.
GRAFANA_LEVELS = {Level.OK: "green", Level.WARNING: "orange", Level.CRITICAL: "red"}

HOST_ALIAS = "host.docker.internal"

#: Neutral, because the line at zero is a boundary and not a state. A status
#: colour there would read as a judgement about traffic that crosses it.
ZERO_LINE_COLOR = "#8e8e8e"


#: Only the characters that mean something in a regular expression. Python's
#: re.escape also escapes a space, as "\ ", which is a valid identity escape in
#: Python and an invalid one in a JavaScript unicode regex -- so a link whose
#: name contains a space produced an override the grapher could not compile,
#: and the panel rendered as an error with no data rather than as a chart.
_REGEX_META = set(r".^$*+?()[]{}|\/")


def _regex_literal(text: str) -> str:
    return "".join("\\" + char if char in _REGEX_META else char for char in text)


def _grafana_steps(panel: Panel) -> List[Dict[str, Any]]:
    """Status bands, lowest first. The first step has no bound: it is the floor."""
    return [{"color": GRAFANA_LEVELS[t.level], "value": None if index == 0 else t.value}
            for index, t in enumerate(panel.thresholds)] or [{"color": "green", "value": None}]


#: Grafana's own default, and the name anonymous access asks for unless told
#: otherwise. Renaming the organisation in the UI does not change its id, so
#: provisioning keeps working -- but anonymous access looks the organisation up
#: by name and stops finding it, and every page answers "organization not
#: found" with nothing to say which name it wanted.
DEFAULT_GRAFANA_ORG = "Main Org."


class GrafanaGrapher:
    """Grafana proxies queries server-side, so its datasource URL is resolved
    inside the container. Docker Desktop and native Docker both provide
    host.docker.internal when given --add-host=host.docker.internal:host-gateway,
    and it reaches a service bound to the host's loopback.
    """

    name = "grafana"
    #: Set from traffic_grafana_org when the organisation has been renamed.
    org = DEFAULT_GRAFANA_ORG
    #: Where Grafana listens. Loopback unless an operator says otherwise, and
    #: saying otherwise serves the dashboards to anything that can reach the
    #: address -- there is no login in front of them by design.
    http_addr = "127.0.0.1"
    display_name = "Grafana"
    default_port = 3000
    image = "grafana/grafana:latest"

    def resolve_datasource_url(self, vm_url: str, containerized: bool) -> str:
        if not containerized:
            return vm_url
        for loopback in ("127.0.0.1", "localhost", "[::1]", "::1"):
            if f"//{loopback}" in vm_url:
                return vm_url.replace(f"//{loopback}", f"//{HOST_ALIAS}", 1)
        return vm_url

    def files(self, dashboards: Sequence[Dashboard], datasource_url: str,
              root: Path, native: bool = False,
              kept: Optional[Mapping[str, str]] = None) -> Dict[Path, str]:
        base = root / "grafana"
        files: Dict[Path, str] = {
            base / "provisioning" / "datasources" / "netrune.yaml":
                self._datasource(datasource_url),
            base / "provisioning" / "dashboards" / "netrune.yaml":
                self._dashboard_provider(
                    str(base / "dashboards") if native else "/var/lib/grafana/dashboards"),
        }
        for dashboard in dashboards:
            # A kept dashboard wins. The reason it was kept is that it is not
            # what the generator produces, so regenerating over it would undo
            # the only thing the operator asked for.
            body = (kept or {}).get(dashboard.uid)
            files[base / "dashboards" / f"{dashboard.uid}.json"] = (
                body if body else json.dumps(self._dashboard(dashboard), indent=2) + "\n")
        return files

    def _datasource(self, url: str) -> str:
        return f"""# Generated by 'netrune traffic stack init'.
#
# VictoriaMetrics answers the Prometheus query API, so Grafana's built-in
# Prometheus datasource reads it directly. No third-party plugin is involved.
apiVersion: 1

datasources:
  - name: Netrune
    uid: netrune-victoriametrics
    type: prometheus
    access: proxy
    url: {url}
    isDefault: true
    jsonData:
      timeInterval: 15s
      httpMethod: POST
    editable: false
"""

    def _dashboard_provider(self, dashboards_path: str = "/var/lib/grafana/dashboards") -> str:
        return f"""# Generated by 'netrune traffic stack init'.
#
# allowUiUpdates is true so a change made in the browser is not wiped by the next
# provisioning sweep before anyone can keep it. It is still not where a change
# lives: 'netrune traffic dashboard save' copies the edited dashboard back into
# the generated set, and 'dashboard revert' drops it again. Without that, an
# edit survives only until the next 'stack init'.
apiVersion: 1

providers:
  - name: Netrune
    orgId: 1
    folder: Netrune
    type: file
    disableDeletion: false
    allowUiUpdates: true
    updateIntervalSeconds: 30
    options:
      path: {dashboards_path}
      foldersFromFilesStructure: false
"""

    def _series_overrides(self, dashboard: Dashboard) -> List[Dict[str, Any]]:
        """Pin a colour to every series whose name contains a chosen link's.

        A series is drawn as "AFRIX download" or "AFRIX upload" depending on the
        panel, so the match is on the name appearing rather than on the whole
        label. Longest name first, so "WAN" cannot claim a link that happens to
        contain it.
        """
        return [
            {"matcher": {"id": "byRegexp", "options": f"/.*{_regex_literal(name)}.*/"},
             "properties": [{"id": "color",
                             "value": {"mode": "fixed", "fixedColor": color}}]}
            for name, color in sorted(dashboard.series_colors.items(),
                                      key=lambda item: -len(item[0]))
        ]

    def _dashboard(self, dashboard: Dashboard) -> Dict[str, Any]:
        panels: List[Dict[str, Any]] = []
        overrides = self._series_overrides(dashboard)
        # A row advances by its tallest panel, not by whichever happened to be
        # last. Advancing by the last one leaves shorter panels overlapping the
        # row below, and the grapher floats them into whatever gap it can find
        # -- so one chart ends up a row higher than the two beside it.
        x = y = tallest = 0
        for index, panel in enumerate(dashboard.panels):
            if x + panel.width > 24:
                x = 0
                y += tallest
                tallest = 0
            tallest = max(tallest, panel.height)
            rendered = self._panel(panel, index + 1, x, y)
            # Only where colour carries identity. A bar gauge is coloured by the
            # band its value falls in, and replacing that with a link's own
            # colour would trade a warning for a decoration.
            if overrides and panel.kind == PanelKind.TIMESERIES:
                rendered["fieldConfig"]["overrides"] = (
                    list(rendered["fieldConfig"].get("overrides") or []) + overrides)
            panels.append(rendered)
            x += panel.width
            if x >= 24:
                x = 0
                y += tallest
                tallest = 0
        return {
            "uid": dashboard.uid,
            "title": dashboard.title,
            "description": dashboard.description,
            "schemaVersion": 39,
            "version": 1,
            # Editable, and edits are kept only when asked for: they survive
            # the provisioning sweep, and 'traffic dashboard save' is what makes
            # them survive the next 'stack init'.
            "editable": True,
            "refresh": dashboard.refresh,
            "time": {"from": f"now-{dashboard.window}", "to": "now"},
            "timezone": "browser",
            "tags": ["netrune"],
            "templating": {"list": [self._variable(v) for v in dashboard.variables]},
            "panels": panels,
        }

    def _variable(self, variable: Variable) -> Dict[str, Any]:
        return {
            "name": variable.name,
            "label": variable.label,
            "type": "query",
            "datasource": {"type": "prometheus", "uid": "netrune-victoriametrics"},
            "query": {"query": f"label_values({variable.metric}, {variable.label_name})",
                      "refId": f"{variable.name}-values"},
            "refresh": 2,
            "includeAll": True,
            "multi": True,
            "current": {"selected": True, "text": ["All"], "value": ["$__all"]},
            "sort": 1,
        }

    def _panel(self, panel: Panel, panel_id: int, x: int, y: int) -> Dict[str, Any]:
        if panel.kind == PanelKind.STAT:
            return self._stat_panel(panel, panel_id, x, y)
        if panel.kind == PanelKind.BARGAUGE:
            return self._bar_panel(panel, panel_id, x, y)
        if panel.kind == PanelKind.TABLE:
            return self._table_panel(panel, panel_id, x, y)
        return {
            "id": panel_id,
            "title": panel.title,
            "description": panel.description,
            "type": "timeseries",
            "datasource": {"type": "prometheus", "uid": "netrune-victoriametrics"},
            "gridPos": {"h": panel.height, "w": panel.width, "x": x, "y": y},
            "fieldConfig": {
                "defaults": {
                    "unit": GRAFANA_UNITS[panel.unit],
                    "min": 0 if panel.min_zero else None,
                    "max": panel.max_value,
                    "thresholds": ({"mode": "absolute",
                                    "steps": [{"color": ZERO_LINE_COLOR, "value": None},
                                              {"color": ZERO_LINE_COLOR, "value": 0}]}
                                   if panel.zero_line
                                   else {"mode": "absolute", "steps": _grafana_steps(panel)}),
                    "custom": {
                        "drawStyle": "line",
                        "lineInterpolation": "stepAfter" if panel.stepped else "linear",
                        "lineWidth": 1,
                        "fillOpacity": 0 if panel.stepped else 12,
                        "gradientMode": "none" if panel.stepped else "opacity",
                        # Not "never": with gaps left unbridged, a lone sample
                        # between two gaps has no line to belong to and would
                        # render as nothing at all.
                        "showPoints": "auto",
                        "pointSize": 4,
                        "spanNulls": False,
                        "axisCenteredZero": panel.centered_zero,
                        "thresholdsStyle": {
                            "mode": "line" if panel.zero_line
                            else ("dashed" if panel.threshold_lines else "off")},
                        # A floor the data may exceed, so a quiet link is drawn
                        # quiet rather than auto-scaled into its own noise. A
                        # chart drawing one direction downward needs the same
                        # anchor below the line, or a link with little upload
                        # still gets its own scale and the row stops being
                        # comparable -- which is the whole reason for the row.
                        **({"axisSoftMax": panel.soft_max} if panel.soft_max else {}),
                        **({"axisSoftMin": -panel.soft_max}
                           if panel.soft_max and panel.centered_zero else {}),
                    },
                },
                "overrides": [],
            },
            "options": {
                "legend": {"displayMode": "table", "placement": "bottom",
                           # Mean beside max is what says whether a peak was the
                           # shape of the traffic or one moment in it.
                           "calcs": ["lastNotNull", "mean", "max"], "showLegend": True},
                "tooltip": {"mode": "multi", "sort": "desc"},
            },
            "targets": [
                {"expr": query.expr, "legendFormat": query.legend, "refId": chr(65 + index),
                 "datasource": {"type": "prometheus", "uid": "netrune-victoriametrics"}}
                for index, query in enumerate(panel.queries)
            ],
        }

    def _bar_panel(self, panel: Panel, panel_id: int, x: int, y: int) -> Dict[str, Any]:
        """A ranking, drawn as length.

        Which of a dozen ports is nearest its limit is a comparison, and a
        comparison is read from bar length in one look. The same numbers in a
        column have to be scanned and sorted by the reader before they answer
        anything. The name and the value stay on every bar, so the ranking never
        depends on telling two colours apart.
        """
        return {
            "id": panel_id,
            "title": panel.title,
            "description": panel.description,
            "type": "bargauge",
            "datasource": {"type": "prometheus", "uid": "netrune-victoriametrics"},
            "gridPos": {"h": panel.height, "w": panel.width, "x": x, "y": y},
            "fieldConfig": {
                "defaults": {
                    "unit": GRAFANA_UNITS[panel.unit],
                    "min": 0,
                    "max": panel.max_value,
                    "decimals": 0 if panel.unit == Unit.COUNT else 1,
                    "thresholds": {"mode": "absolute", "steps": _grafana_steps(panel)},
                    "mappings": [],
                },
                "overrides": [],
            },
            "options": {
                "reduceOptions": {"calcs": [panel.reduce], "fields": "", "values": False},
                "orientation": "horizontal",
                # A gradient reads as a fill level, which is what a bounded
                # measure is. An unbounded one has no "full", so its bars are
                # coloured by the band they fall in instead.
                "displayMode": "gradient" if panel.max_value else "basic",
                "showUnfilled": True,
                "valueMode": "color",
                "namePlacement": "left",
                "minVizWidth": 8,
                "minVizHeight": 16,
                "sizing": "auto",
            },
            "targets": [
                {"expr": query.expr, "legendFormat": query.legend, "refId": chr(65 + index),
                 "instant": True,
                 "datasource": {"type": "prometheus", "uid": "netrune-victoriametrics"}}
                for index, query in enumerate(panel.queries)
            ],
        }

    #: Labels every scraped series carries that say nothing about the thing
    #: being measured. Left in, they push the numbers off the right of a table.
    TABLE_NOISE = ("Time", "job", "instance", "__name__", "device_ip", "ifindex",
                   "collector", "source", "downlink", "service", "label",
                   "device", "interface", "name")

    def _table_panel(self, panel: Panel, panel_id: int, x: int, y: int) -> Dict[str, Any]:
        """One row per thing, one column per measure.

        A chart answers "how much". A table answers "which one, and what kind",
        and for a port reporting errors the kind is most of the diagnosis: input
        errors are a cable or an optic, output discards are congestion. Reading
        that off four overlapping lines is work; reading it off four columns is
        not.
        """
        keep = list(panel.columns) or ["link"]
        # Each query becomes one value column, named by its legend.
        renames = {f"Value #{chr(65 + index)}": query.legend
                   for index, query in enumerate(panel.queries)}
        order = {name: position for position, name in enumerate(keep)}
        for position, query in enumerate(panel.queries):
            order[f"Value #{chr(65 + position)}"] = len(keep) + position
        return {
            "id": panel_id,
            "title": panel.title,
            "description": panel.description,
            "type": "table",
            "datasource": {"type": "prometheus", "uid": "netrune-victoriametrics"},
            "gridPos": {"h": panel.height, "w": panel.width, "x": x, "y": y},
            "fieldConfig": {
                "defaults": {
                    "unit": GRAFANA_UNITS[panel.unit],
                    "decimals": 0 if panel.unit == Unit.COUNT else 2,
                    "thresholds": {"mode": "absolute", "steps": _grafana_steps(panel)},
                    "custom": {"align": "auto", "cellOptions": {"type": "auto"},
                               "filterable": False},
                },
                "overrides": [
                    # Label columns are words, not measurements: colouring them
                    # by a numeric threshold would be meaningless.
                    *({"matcher": {"id": "byName", "options": column},
                       "properties": [{"id": "unit", "value": "string"},
                                      {"id": "custom.cellOptions",
                                       "value": {"type": "color-text"}}]}
                      for column in keep),
                    # Columns need not share a unit: latency in seconds sits
                    # beside loss as a fraction, and one default cannot serve
                    # both.
                    *({"matcher": {"id": "byName", "options": query.legend},
                       "properties": [{"id": "unit", "value": GRAFANA_UNITS[query.unit]}]}
                      for query in panel.queries if query.unit),
                ],
            },
            "options": {
                "showHeader": True,
                "cellHeight": "sm",
                "footer": {"show": False, "reducer": ["sum"], "countRows": False, "fields": ""},
                **({"sortBy": [{"displayName": panel.sort_by, "desc": True}]}
                   if panel.sort_by else {}),
            },
            "transformations": [
                # Drop the scrape plumbing *before* merging, not after. Each
                # query is evaluated separately and carries its own Time column,
                # so leaving Time in means no two frames ever agree on every
                # shared field and merge produces one row per query instead of
                # one row per thing.
                {"id": "filterFieldsByName",
                 "options": {"exclude": {"names": list(self.TABLE_NOISE)}}},
                # Join explicitly on the one column that identifies a row.
                # `merge` guesses at which fields two frames share, and gets it
                # wrong the moment a query returns a single series: the value
                # columns collide and the table becomes one row per query
                # instead of one row per thing.
                {"id": "joinByField",
                 "options": {"byField": panel.join_by or keep[0], "mode": "outer"}},
                {"id": "organize", "options": {"excludeByName": {},
                                               "renameByName": renames,
                                               "indexByName": order}},
            ],
            "targets": [
                {"expr": query.expr, "refId": chr(65 + index), "instant": True,
                 "format": "table", "legendFormat": query.legend,
                 "datasource": {"type": "prometheus", "uid": "netrune-victoriametrics"}}
                for index, query in enumerate(panel.queries)
            ],
        }

    def _stat_panel(self, panel: Panel, panel_id: int, x: int, y: int) -> Dict[str, Any]:
        """A single current state, sized to be read at a glance rather than parsed."""
        steps = _grafana_steps(panel)
        return {
            "id": panel_id,
            "title": panel.title,
            "description": panel.description,
            "type": "stat",
            "datasource": {"type": "prometheus", "uid": "netrune-victoriametrics"},
            "gridPos": {"h": panel.height, "w": panel.width, "x": x, "y": y},
            "fieldConfig": {
                "defaults": {
                    "unit": GRAFANA_UNITS[panel.unit],
                    "min": 0 if panel.min_zero else None,
                    "max": panel.max_value,
                    "decimals": 0 if panel.unit == Unit.COUNT else 1,
                    "thresholds": {"mode": "absolute", "steps": steps},
                    "mappings": [],
                    **({"color": {"mode": "fixed", "fixedColor": panel.color}}
                       if panel.color else {}),
                },
                "overrides": [],
            },
            "options": {
                "reduceOptions": {"calcs": [panel.reduce], "fields": "", "values": False},
                # A tile with a colour of its own is one thing -- a link -- and
                # the colour names it, so the whole tile carries it. Everywhere
                # else the value is coloured and the tile is not, because a wall
                # of solid colour reads as an alarm even when nothing is wrong.
                "colorMode": "background_solid" if panel.color else "value",
                # Down and up side by side, the way a link is read aloud.
                "textMode": "value_and_name" if panel.color else "auto",
                # The number says where things stand. The shape behind it says
                # whether that is where they have been, and a reading on its way
                # up is a different situation from the same reading holding
                # steady.
                "graphMode": "area" if panel.spark else "none",
                "justifyMode": "center",
                "orientation": "horizontal" if panel.color else "auto",
                # A tile exists to be read across a room. Grafana sizes the
                # value to the panel by default, which on a narrow tile is
                # smaller than the title above it.
                **({"text": {"valueSize": 34, "titleSize": 14}} if panel.color else {}),
            },
            "targets": [
                # A sparkline needs the range behind the number, so the query
                # cannot be instant when there is a shape to draw.
                {"expr": query.expr, "legendFormat": query.legend, "refId": chr(65 + index),
                 "instant": not panel.spark, "range": panel.spark,
                 "datasource": {"type": "prometheus", "uid": "netrune-victoriametrics"}}
                for index, query in enumerate(panel.queries)
            ],
        }

    def container_mounts(self, root: Path) -> List[str]:
        base = root / "grafana"
        return [
            f"{base}/provisioning:/etc/grafana/provisioning:ro",
            f"{base}/dashboards:/var/lib/grafana/dashboards:ro",
            # Grafana runs as UID 472 and cannot write a host directory owned by
            # the operator. Its database holds only derived state, because the
            # dashboards and datasource come from the files above.
            "netrune-grafana-data:/var/lib/grafana",
        ]

    def container_args(self) -> List[str]:
        # Docker Desktop's --network host joins the Docker VM's namespace rather
        # than the WSL distro's, so the published port would be unreachable.
        # Bridge networking plus a host alias works on both Docker Desktop and
        # native Docker.
        return [f"--add-host={HOST_ALIAS}:host-gateway"]

    #: Binaries that mean Grafana is installed on the host. Running it natively
    #: removes a dependency on a container runtime staying up, which on a laptop
    #: is a thing that gets closed.
    NATIVE_BINARIES = ("grafana", "grafana-server")

    def native_environment(self, root: Path) -> Dict[str, str]:
        base = root / "grafana"
        return {
            "GF_PATHS_PROVISIONING": str(base / "provisioning"),
            "GF_PATHS_DATA": str(base / "data"),
            "GF_PATHS_LOGS": str(base / "logs"),
            "GF_SERVER_HTTP_ADDR": self.http_addr,
            **self.container_env(),
        }

    def container_env(self) -> Dict[str, str]:
        return {
            "GF_SERVER_HTTP_ADDR": self.http_addr,
            # The whole stack is loopback-bound and unauthenticated by design;
            # making Grafana alone demand a login would be arbitrary rather than
            # safer. Set GF_AUTH_ANONYMOUS_ENABLED=false to require one.
            "GF_AUTH_ANONYMOUS_ENABLED": "true",
            "GF_AUTH_ANONYMOUS_ORG_ROLE": "Admin",
            # By name, not by id. Rename the organisation without changing this
            # and Grafana answers "organization not found" on every page.
            "GF_AUTH_ANONYMOUS_ORG_NAME": self.org,
            "GF_AUTH_BASIC_ENABLED": "false",
            "GF_SECURITY_ALLOW_EMBEDDING": "true",
            "GF_USERS_DEFAULT_THEME": "dark",
            # Grafana refuses a dashboard refresh faster than this and silently
            # falls back to the floor, so a 5s board would tick at 10s without
            # saying so. Lowering it also puts 1s in the picker for anyone who
            # wants it -- though nothing on screen can change faster than the
            # collector polls.
            "GF_DASHBOARDS_MIN_REFRESH_INTERVAL": "1s",
            "GF_ANALYTICS_REPORTING_ENABLED": "false",
            "GF_ANALYTICS_CHECK_FOR_UPDATES": "false",
        }

    def dashboard_url(self, base_url: str, dashboard: Dashboard) -> str:
        slug = dashboard.uid
        return f"{base_url}/d/{slug}"

    def health_path(self) -> str:
        return "/api/health"


# ---------------------------------------------------------------------------
# Perses
# ---------------------------------------------------------------------------

PERSES_UNITS = {
    Unit.BITS_PER_SECOND: "bits/sec",
    Unit.PACKETS_PER_SECOND: "counts/sec",
    Unit.PERCENT: "percent",
    Unit.RATIO: "percent-decimal",
    Unit.SECONDS: "seconds",
    Unit.COUNT: "decimal",
    # Perses' unit list has no temperature, so the number is shown bare. The
    # panel title carries the scale, which is the same thing a bare axis does.
    Unit.CELSIUS: "decimal",
}

#: Perses names its status colours directly; the meanings are the same.
PERSES_LEVELS = {Level.OK: "#2b7a51", Level.WARNING: "#a1741a", Level.CRITICAL: "#a63229"}

#: Perses names its reductions differently from Grafana; both mean the same
#: thing, and the neutral model uses Grafana's spelling.
_PERSES_CALCULATIONS = {"lastNotNull": "last-number", "last": "last", "max": "max",
                        "mean": "mean", "min": "min", "sum": "sum"}

PERSES_CONTAINER_PROVISIONING = "/etc/netrune/perses"
PERSES_CONTAINER_DATA = "/perses"


class PersesGrapher:
    name = "perses"
    display_name = "Perses"
    default_port = 8080
    image = "persesdev/perses:latest"

    def files(self, dashboards: Sequence[Dashboard], datasource_url: str,
              root: Path) -> Dict[Path, str]:
        base = root / "perses"
        files: Dict[Path, str] = {
            root / "perses.yml": self._config(base),
            base / "project.json": json.dumps({
                "kind": "Project",
                "metadata": {"name": "netrune"},
                "spec": {"display": {"name": "Netrune"}},
            }, indent=2) + "\n",
            base / "datasource.json": json.dumps({
                "kind": "Datasource",
                "metadata": {"name": "netrune-victoriametrics", "project": "netrune"},
                "spec": {"default": True, "plugin": {
                    "kind": "PrometheusDatasource",
                    "spec": {"directUrl": datasource_url},
                }},
            }, indent=2) + "\n",
        }
        for dashboard in dashboards:
            files[base / f"dashboard-{dashboard.uid}.json"] = (
                json.dumps(self._dashboard(dashboard), indent=2) + "\n")
        return files

    def _config(self, provisioning_dir: Path) -> str:
        return f"""# Generated by 'netrune traffic stack init'.
#
# Provisioned resources are re-injected periodically, so editing a dashboard in
# the browser is not how it changes. Edit the files and regenerate instead.
# Paths are the container's, matching the volumes in the generated unit and
# compose file. To run the Perses binary directly instead, replace them with
# "{provisioning_dir.parent / 'perses-data'}" and "{provisioning_dir}".
database:
  file:
    folder: "{PERSES_CONTAINER_DATA}"
    extension: json

provisioning:
  folders:
    - "{PERSES_CONTAINER_PROVISIONING}"
"""

    def _dashboard(self, dashboard: Dashboard) -> Dict[str, Any]:
        panels = {panel.key: self._panel(panel) for panel in dashboard.panels}
        items: List[Dict[str, Any]] = []
        x = y = tallest = 0
        for panel in dashboard.panels:
            if x + panel.width > 24:
                x = 0
                y += tallest
                tallest = 0
            tallest = max(tallest, panel.height)
            items.append({"x": x, "y": y, "width": panel.width, "height": panel.height,
                          "content": {"$ref": f"#/spec/panels/{panel.key}"}})
            x += panel.width
            if x >= 24:
                x = 0
                y += tallest
                tallest = 0
        title = dashboard.title.split("/")[-1].strip()
        return {
            "kind": "Dashboard",
            "metadata": {"name": dashboard.uid, "project": "netrune"},
            "spec": {
                "display": {"name": title, "description": dashboard.description},
                "duration": dashboard.window,
                "refreshInterval": dashboard.refresh,
                "variables": [self._variable(v) for v in dashboard.variables],
                "panels": panels,
                "layouts": [{"kind": "Grid", "spec": {
                    "display": {"title": title, "collapse": {"open": True}},
                    "items": items,
                }}],
            },
        }

    def _variable(self, variable: Variable) -> Dict[str, Any]:
        return {
            "kind": "ListVariable",
            "spec": {
                "name": variable.name,
                "display": {"name": variable.label},
                "allowAllValue": True,
                "allowMultiple": True,
                "defaultValue": ["$__all"],
                "plugin": {"kind": "PrometheusLabelValuesVariable", "spec": {
                    "labelName": variable.label_name,
                    "matchers": [variable.metric],
                }},
            },
        }

    def _panel(self, panel: Panel) -> Dict[str, Any]:
        if panel.kind == PanelKind.STAT:
            return self._stat_panel(panel)
        if panel.kind == PanelKind.BARGAUGE:
            return self._bar_panel(panel)
        if panel.kind == PanelKind.TABLE:
            return self._table_panel(panel)
        return {
            "kind": "Panel",
            "spec": {
                "display": {"name": panel.title, "description": panel.description},
                "plugin": {"kind": "TimeSeriesChart", "spec": {
                    "legend": {"position": "bottom", "mode": "table", "values": ["last", "max"]},
                    "yAxis": {"format": {"unit": PERSES_UNITS[panel.unit]},
                              **({"max": panel.max_value} if panel.max_value else {})},
                    # Perses' TimeSeriesChart admits only "line" or "bar" here.
                    "visual": {"lineWidth": 1.5,
                               "areaOpacity": 0.0 if panel.stepped else 0.1,
                               "display": "line"},
                }},
                "queries": [
                    {"kind": "TimeSeriesQuery", "spec": {"plugin": {
                        "kind": "PrometheusTimeSeriesQuery",
                        "spec": {"query": query.expr, "seriesNameFormat": query.legend},
                    }}}
                    for query in panel.queries
                ],
            },
        }

    def _table_panel(self, panel: Panel) -> Dict[str, Any]:
        """Perses' Table, which hides columns rather than selecting them."""
        keep = set(panel.columns) or {"device", "name"}
        hidden = [{"name": column, "hide": True}
                  for column in ("timestamp", "job", "instance", "__name__", "device_ip",
                                 "ifindex", "collector", "source", "downlink", "service")
                  if column not in keep]
        return {
            "kind": "Panel",
            "spec": {
                "display": {"name": panel.title, "description": panel.description},
                "plugin": {"kind": "Table", "spec": {
                    "columnSettings": hidden,
                    "density": "compact",
                }},
                "queries": [
                    {"kind": "TimeSeriesQuery", "spec": {"plugin": {
                        "kind": "PrometheusTimeSeriesQuery",
                        "spec": {"query": query.expr, "seriesNameFormat": query.legend},
                    }}}
                    for query in panel.queries
                ],
            },
        }

    def _bar_panel(self, panel: Panel) -> Dict[str, Any]:
        """Perses' BarChart, which ranks series by one reduced value."""
        return {
            "kind": "Panel",
            "spec": {
                "display": {"name": panel.title, "description": panel.description},
                "plugin": {"kind": "BarChart", "spec": {
                    "calculation": _PERSES_CALCULATIONS[panel.reduce],
                    "format": {"unit": PERSES_UNITS[panel.unit],
                               "decimalPlaces": 0 if panel.unit == Unit.COUNT else 1},
                    "sort": "desc",
                    "mode": "value",
                }},
                "queries": [
                    {"kind": "TimeSeriesQuery", "spec": {"plugin": {
                        "kind": "PrometheusTimeSeriesQuery",
                        "spec": {"query": query.expr, "seriesNameFormat": query.legend},
                    }}}
                    for query in panel.queries
                ],
            },
        }

    def _stat_panel(self, panel: Panel) -> Dict[str, Any]:
        steps = [{"value": t.value, "color": PERSES_LEVELS[t.level]}
                 for t in panel.thresholds if t.value > 0]
        default = next((PERSES_LEVELS[t.level] for t in panel.thresholds if t.value == 0),
                       PERSES_LEVELS[Level.OK])
        return {
            "kind": "Panel",
            "spec": {
                "display": {"name": panel.title, "description": panel.description},
                "plugin": {"kind": "StatChart", "spec": {
                    "calculation": _PERSES_CALCULATIONS[panel.reduce],
                    "format": {"unit": PERSES_UNITS[panel.unit],
                               "decimalPlaces": 0 if panel.unit == Unit.COUNT else 1},
                    "thresholds": {"defaultColor": default, "steps": steps} if steps else {},
                    **({"sparkline": {"width": 1.25}} if panel.spark else {}),
                }},
                "queries": [
                    {"kind": "TimeSeriesQuery", "spec": {"plugin": {
                        "kind": "PrometheusTimeSeriesQuery",
                        "spec": {"query": query.expr, "seriesNameFormat": query.legend},
                    }}}
                    for query in panel.queries
                ],
            },
        }

    def container_mounts(self, root: Path) -> List[str]:
        return [
            f"{root}/perses.yml:/etc/perses/config.yaml:ro",
            f"{root}/perses:{PERSES_CONTAINER_PROVISIONING}:ro",
            f"netrune-perses-data:{PERSES_CONTAINER_DATA}",
        ]

    def container_env(self) -> Dict[str, str]:
        return {}

    def container_args(self) -> List[str]:
        return []

    def resolve_datasource_url(self, vm_url: str, containerized: bool) -> str:
        # directUrl is fetched by the browser on the host, so the host's own
        # address is the right one whether or not Perses is containerized.
        return vm_url

    def dashboard_url(self, base_url: str, dashboard: Dashboard) -> str:
        return f"{base_url}/projects/netrune/dashboards/{dashboard.uid}"

    def health_path(self) -> str:
        return "/api/v1/health"


# ---------------------------------------------------------------------------
# No grapher
# ---------------------------------------------------------------------------

class NoGrapher:
    """VictoriaMetrics' own vmui, which needs nothing generated for it."""

    name = "none"
    display_name = "vmui (built into VictoriaMetrics)"
    default_port = 8428
    image = ""

    def files(self, dashboards: Sequence[Dashboard], datasource_url: str,
              root: Path) -> Dict[Path, str]:
        return {}

    def container_mounts(self, root: Path) -> List[str]:
        return []

    def container_env(self) -> Dict[str, str]:
        return {}

    def container_args(self) -> List[str]:
        return []

    def resolve_datasource_url(self, vm_url: str, containerized: bool) -> str:
        return vm_url

    def dashboard_url(self, base_url: str, dashboard: Dashboard) -> str:
        return f"{base_url}/vmui"

    def health_path(self) -> str:
        return "/health"


GRAPHERS: Dict[str, Grapher] = {
    grapher.name: grapher  # type: ignore[misc]
    for grapher in (GrafanaGrapher(), PersesGrapher(), NoGrapher())
}


def get_grapher(name: str) -> Optional[Grapher]:
    return GRAPHERS.get(str(name or "").strip().lower())


def grapher_names() -> List[str]:
    return sorted(GRAPHERS)


def unit_coverage() -> Dict[str, List[str]]:
    """Semantic units each adapter can render, for compatibility checking."""
    return {
        "grafana": sorted(GRAFANA_UNITS),
        "perses": sorted(PERSES_UNITS),
    }

"""A grapher-neutral description of what Netrune's dashboards show.

The queries below are the actual product. They are PromQL, which every
component downstream of VictoriaMetrics speaks, and they say what an operator
wants to know about an interface: how much is flowing, how close that is to the
link's limit, whether the physical layer is complaining, and whether the port is
up. A grapher's job is only to draw them.

Nothing here mentions a dashboard tool. Adapters in `traffic_graphers` turn this
into Grafana JSON, Perses resources, or anything else that can render a time
series, and a new adapter needs no change to this file.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import List, Mapping, Optional, Sequence

# A rate window must span at least two scrapes or it resolves to nothing. Four
# times the usual scrape interval keeps a single missed scrape from blanking a
# panel, which otherwise reads as an outage that never happened.
RATE_WINDOW = "2m"


class Unit:
    """Semantic units, mapped to each grapher's own vocabulary by its adapter.

    Naming these by meaning rather than by any one tool's spelling is what keeps
    the dashboards portable: Grafana calls bits per second `bps`, Perses calls
    it `bits/sec`, and neither spelling belongs in a shared description.
    """

    BITS_PER_SECOND = "bits_per_second"
    PACKETS_PER_SECOND = "packets_per_second"
    PERCENT = "percent"
    RATIO = "ratio"
    SECONDS = "seconds"
    COUNT = "count"
    CELSIUS = "celsius"


@dataclass(frozen=True)
class Query:
    """One series expression and how to name the lines it returns."""

    expr: str
    legend: str
    #: Only for a table, where each query is a column and columns need not
    #: share a unit -- latency in seconds beside loss as a fraction.
    unit: str = ""


class PanelKind:
    """What shape a panel is, chosen from the job its data does.

    A magnitude over time is a line. A single current state -- is collection
    happening, is anything down -- is a number, and drawing it as a line asks
    the reader to derive the answer themselves.

    Comparing several things by one measure is neither: it is a ranking, and a
    bar length is read at a glance where a column of numbers has to be scanned
    and mentally sorted. That is what BARGAUGE is for.
    """

    TIMESERIES = "timeseries"
    STAT = "stat"
    BARGAUGE = "bargauge"
    #: Several measures of the same things, side by side. A chart answers "how
    #: much"; a table answers "which one, and what kind" -- and for a port
    #: reporting errors, the kind is most of the diagnosis.
    TABLE = "table"


class Level:
    """Reserved status colours. Never used to tell one series from another."""

    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Threshold:
    """Above `value`, the reading is at `level`."""

    value: float
    level: str


@dataclass(frozen=True)
class Panel:
    key: str
    title: str
    description: str
    unit: str
    queries: Sequence[Query]
    width: int = 24          # out of 24, the grid both graphers use
    height: int = 8
    min_zero: bool = True
    # A status series is a step function, not a measurement that interpolates.
    stepped: bool = False
    kind: str = PanelKind.TIMESERIES
    #: Status bands, lowest first. A tile carries its title and value as well as
    #: its colour, so the state is never conveyed by colour alone.
    thresholds: Sequence[Threshold] = field(default_factory=tuple)
    #: How a series becomes one number on a stat tile.
    reduce: str = "lastNotNull"
    #: Shown under the value when a tile needs a unit word of its own.
    suffix: str = ""
    #: A tile that carries its own recent history behind the number. The number
    #: says where things stand; the shape behind it says whether that is where
    #: they have been, which is most of what an operator wants from a glance.
    spark: bool = False
    #: A hard axis ceiling, for a measure that cannot exceed it by definition.
    max_value: Optional[float] = None
    #: Draw the line at zero. On a chart with traffic above it and below it,
    #: which side a line is on is the whole reading, and a grid line among
    #: other grid lines does not say where that boundary is.
    zero_line: bool = False
    #: Draw the status bands on the plot. Worth it where the bands are the
    #: reason to look -- "is this link near its limit" is answered by where the
    #: line sits relative to 85%, not by reading a number off the axis.
    threshold_lines: bool = False
    #: A fixed colour for the whole panel, where the panel *is* one thing --
    #: a link's tile. Identity, not status: a bar coloured by its threshold is
    #: saying something different and must not be overwritten with this.
    color: str = ""
    #: Centre the axis on zero. For a chart drawing one direction up and the
    #: other down, an axis that is not centred makes the same number of bits a
    #: different distance depending on which way it went.
    centered_zero: bool = False
    #: Which label columns a table keeps. Everything else is scrape plumbing
    #: that would push the numbers off the right-hand side.
    columns: Sequence[str] = ()
    #: The column a table's queries are joined on. One column, and it has to
    #: identify a row outright: joining on something repeated turns one row per
    #: thing into one row per query.
    join_by: str = ""
    #: Column to sort a table by, descending. The row worth reading first.
    sort_by: str = ""
    #: An axis floor that the data may still exceed. A quiet 1 Gbps link
    #: auto-scaled to its own noise looks identical to a saturated one; pinning
    #: the axis at the line rate keeps the picture honest without clipping a
    #: genuine excursion, which a hard maximum would hide.
    soft_max: Optional[float] = None


@dataclass(frozen=True)
class Variable:
    """A dropdown filled from a label's values in the stored data."""

    name: str
    label: str
    label_name: str
    metric: str
    depends_on: Optional[str] = None


@dataclass(frozen=True)
class Dashboard:
    uid: str
    title: str
    description: str
    panels: Sequence[Panel]
    variables: Sequence[Variable] = field(default_factory=tuple)
    window: str = "6h"
    refresh: str = "1m"
    #: Colours pinned to particular series names. A grapher otherwise assigns
    #: colours in the order series arrive, so a link changes colour whenever
    #: another one goes quiet and drops out of a topk -- which makes the colour
    #: mean a rank rather than a link.
    series_colors: Mapping[str, str] = field(default_factory=dict)


def _interface_selector() -> str:
    return '{device=~"$device", interface=~"$interface"}'


def interface_dashboard() -> Dashboard:
    """Throughput, utilisation, errors, and status. Deliberately nothing else.

    A dashboard that shows everything is read by nobody. These four answer the
    questions that lead somewhere: is it busy, is it near the limit, is the
    physical layer at fault, and is it even up.
    """
    selector = _interface_selector()
    return Dashboard(
        uid="netrune-interfaces",
        title="Netrune / Interfaces",
        description="Throughput, utilisation, errors, and status for every interface Netrune watches.",
        variables=(
            Variable("device", "Device", "device", "netrune_interface_up"),
            Variable("interface", "Interface", "interface",
                     'netrune_interface_up{device=~"$device"}', depends_on="device"),
        ),
        panels=(
            Panel(
                key="throughput",
                title="Throughput",
                description=("Bits per second in each direction, derived from the raw octet counters "
                             "at query time. Transmit is drawn negative so the two directions do "
                             "not hide each other, and the axis is centred on zero so the same "
                             "number of bits is the same distance either way. The axis follows the "
                             "data here: this is the drilled-in view, where the shape is the point. "
                             "Use Utilisation beside it to see how full the link is."),
                unit=Unit.BITS_PER_SECOND,
                min_zero=False,
                height=9,
                centered_zero=True,
                queries=(
                    Query(_named(f"8 * {_receive(selector)}", selector),
                          "{{device}} {{name}} in"),
                    Query(_named(f"-8 * {_transmit(selector)}", selector),
                          "{{device}} {{name}} out"),
                ),
            ),
            Panel(
                key="utilisation",
                title="Utilisation",
                description=("Combined throughput as a percentage of the speed the device reports for "
                             "the link. A port pinned near 100% is the one to look at first."),
                unit=Unit.PERCENT,
                width=12,
                max_value=100,
                threshold_lines=True,
                thresholds=(Threshold(0, Level.OK), Threshold(60, Level.WARNING),
                            Threshold(85, Level.CRITICAL)),
                queries=(Query(_named(_utilisation(selector), selector),
                               "{{device}} {{name}}"),),
            ),
            Panel(
                key="errors",
                title="Errors and discards",
                description=("Per-second error and discard rates. Sustained input errors point at a "
                             "cable, optic, or duplex mismatch rather than at load."),
                unit=Unit.PACKETS_PER_SECOND,
                width=12,
                queries=tuple(
                    Query(_named(_rate(f"netrune_interface_{metric}", selector,
                                       MAX_PLAUSIBLE_PACKETS_PER_SECOND), selector),
                          "{{device}} {{name}} " + label)
                    for metric, label in (
                        ("receive_errors_total", "in errors"),
                        ("transmit_errors_total", "out errors"),
                        ("receive_drops_total", "in discards"),
                        ("transmit_drops_total", "out discards"),
                    )
                ),
            ),
            Panel(
                key="status",
                title="Interface status",
                description=("1 is up. Operational at 0 while administrative is 1 is a fault; both at "
                             "0 is somebody's decision."),
                unit=Unit.COUNT,
                height=6,
                stepped=True,
                queries=(
                    Query(_named(f"netrune_interface_up{selector}", selector),
                          "{{device}} {{name}} oper"),
                    Query(_named(f"netrune_interface_admin_up{selector}", selector),
                          "{{device}} {{name}} admin"),
                ),
            ),
        ),
    )


def reachability_dashboard() -> Dashboard:
    return Dashboard(
        uid="netrune-reachability",
        title="Netrune / Reachability",
        description="Round-trip time and loss to every address Netrune probes.",
        variables=(
            Variable("target", "Target", "target", "netrune_icmp_up"),
        ),
        panels=(
            Panel(
                key="rtt",
                title="Round-trip time",
                description=("Measured from the collector, not from the device. A remote collector "
                             "answers a different question than a local one, which is why the "
                             "collector is on the legend."),
                unit=Unit.SECONDS,
                height=9,
                queries=(
                    Query('netrune_icmp_rtt_seconds{target=~"$target"}', "{{target}} from {{collector}}"),
                ),
            ),
            Panel(
                key="loss",
                title="Packet loss",
                description=("Fraction of probes lost. Latency readings taken during loss are not "
                             "trustworthy, so read this panel before the one above it."),
                unit=Unit.RATIO,
                height=7,
                queries=(
                    Query('netrune_icmp_loss_ratio{target=~"$target"}', "{{target}} from {{collector}}"),
                ),
            ),
        ),
    )


def collector_dashboard() -> Dashboard:
    """Whether the data on the other dashboards can be believed."""
    return Dashboard(
        uid="netrune-collector",
        title="Netrune / Collector",
        description="Whether collection is actually happening. Read this before trusting a flat line.",
        panels=(
            Panel(
                key="staleness",
                title="Seconds since last reading",
                description=("A stopped collector leaves flat lines rather than empty ones, because "
                             "the exposition keeps serving its last reading. This is how that looks "
                             "different from a quiet network."),
                unit=Unit.SECONDS,
                height=9,
                queries=(
                    Query(_named("time() - netrune_interface_last_poll_timestamp_seconds"),
                          "{{device}} {{name}}"),
                ),
            ),
            Panel(
                key="watchlist",
                title="Targets being collected",
                description="1 is active, 0 is paused. A paused target is a deliberate gap.",
                unit=Unit.COUNT,
                width=12,
                stepped=True,
                queries=(
                    Query(_named("netrune_interface_watch_enabled"), "{{device}} {{name}}"),
                ),
            ),
            Panel(
                key="uptime",
                title="Device uptime",
                description="A drop means the device restarted, and its counters restarted with it.",
                unit=Unit.SECONDS,
                width=12,
                queries=(
                    Query("netrune_device_uptime_seconds", "{{device}}"),
                ),
            ),
        ),
    )



#: The combined line is not a link, so its colour is not a link's.
SERIES_COLOR_WAN = "#7A5AF0"

LINK_CEILING_BPS = 1_000_000_000
"""Where a throughput axis is anchored. Matches the collector's own ceiling for
a link whose speed the device does not report, so a chart and the reading behind
it agree about what a full link looks like. See DEFAULT_LINK_CEILING_BPS."""


#: A byte rate above this did not happen on any port in any estate: 800 Gb/s,
#: the same absolute backstop the collector applies. Rates are derived from raw
#: counters at query time, so a counter that reset or was replaced mid-series
#: produces a single enormous point here no matter how careful the collector
#: was -- and one such point rescales every other line on the chart into a flat
#: row along the bottom. Filtering leaves a gap, which is the truth.
MAX_PLAUSIBLE_BYTES_PER_SECOND = 100_000_000_000

#: A 10 Gb port at minimum frame size passes about 14.9 million packets a
#: second. Error counters are 32 bits wide and their wrap is a much smaller
#: number than an octet counter's, but it is still enough to own the axis.
MAX_PLAUSIBLE_PACKETS_PER_SECOND = 20_000_000


#: Labels that identify one watched port. The join below matches on these and
#: on nothing else, so adding a label to the counters later cannot quietly
#: break it.
IDENTITY_LABELS = "device, interface, collector"


#: A shorter window for the headline tiles than for the charts. A tile is read
#: as "what is happening now", and a two-minute average of a link that just
#: went quiet still reads busy for two minutes.
TILE_RATE_WINDOW = "1m"


@dataclass(frozen=True)
class ServiceLink:
    """One purchased link, as the overview needs to know it."""

    name: str
    color: str = ""
    #: What it is sold at. The row of charts is scaled by the largest of these
    #: rather than by a fixed number, so the axis means the estate's own
    #: biggest link instead of an assumption about what one looks like.
    down_bps: int = 0
    up_bps: int = 0


#: A link somebody is paying for, in each direction the contract names.
#: `downlink` says which counter carries traffic arriving from the provider:
#: on the port that reaches the provider what the switch receives came from
#: outside, and on the port facing the LAN it is the other way round.
SERVICE_DOWN_IS_RECEIVE = '{service="yes",downlink="receive"}'
SERVICE_DOWN_IS_TRANSMIT = '{service="yes",downlink="transmit"}'


def _service_rate(direction: str, only: str = "", window: str = RATE_WINDOW) -> str:
    """Bits per second on the service links, in one direction of the contract.

    Down is provider to LAN, up is LAN to provider -- the same way SNMP's own
    counters read on the port that reaches the provider, where what the switch
    receives came from outside. Which counter measures which depends on which
    way the port faces, so both cases are written out and unioned; every link
    matches exactly one of them.
    """
    if direction == "down":
        receive_side, transmit_side = SERVICE_DOWN_IS_RECEIVE, SERVICE_DOWN_IS_TRANSMIT
    else:
        receive_side, transmit_side = SERVICE_DOWN_IS_TRANSMIT, SERVICE_DOWN_IS_RECEIVE
    if only:
        pick = f',name="{only}"'
        receive_side = receive_side[:-1] + pick + "}"
        transmit_side = transmit_side[:-1] + pick + "}"
    return (f"(({_named(f'8 * {_receive(window=window)}', receive_side)})"
            f" or ({_named(f'8 * {_transmit(window=window)}', transmit_side)}))")


def _service_share(direction: str) -> str:
    """That rate as a percentage of what the link is sold at.

    `group_left()` on the division, not decoration: a plain `/ on(...)` keeps
    only the labels named in `on`, which drops the link's name and leaves every
    bar on the chart labelled "down" or "up" with no way to tell which link is
    which.
    """
    return (f"100 * ({_service_rate(direction)})"
            f" / on({IDENTITY_LABELS}) group_left() netrune_interface_subscribed_bits"
            f'{{direction="{direction}"}}')


def _wan_total(direction: str, window: str = RATE_WINDOW) -> str:
    """Every service link added together, in one direction.

    `or vector(0)` on each side because a sum over no series is no series, and
    adding that to a number gives nothing rather than the number.
    """
    return f"(sum({_service_rate(direction, window=window)}) or vector(0))"


def _wan_share(direction: str) -> str:
    return (f"100 * {_wan_total(direction)}"
            f' / (sum(netrune_interface_subscribed_bits{{direction="{direction}"}}) or vector(1))')


def _named(expression: str, selector: str = "") -> str:
    """Carry the name a person gave a port into the series' labels.

    Multiplying by an info metric that is always 1 leaves the value untouched
    and brings `name` across with it, which is what lets a legend read
    "Warehouse uplink" instead of "Gi1/0/16". Doing it here rather than as a
    label on the counters is what keeps a rename from starting a new series and
    stranding the history under the old one.
    """
    # `link!=""` is not cosmetic. Adding a label to the info metric leaves the
    # previous shape of it in storage until it ages out, and every one of those
    # older series matches the same link -- so each counter series joins twice
    # and every row and line is duplicated. Requiring the label excludes the
    # older shape by construction rather than waiting for it to expire.
    guard = 'link!=""'
    inner = f"{{{guard},{selector[1:]}" if selector else f"{{{guard}}}"
    return (f"({expression})"
            f" * on({IDENTITY_LABELS}) group_left(name, link)"
            f" netrune_interface_info{inner}")


#: Two counter reads are never exactly an interval apart, so a port at line rate
#: computes a little over it. The same tolerance the collector applies.
RATE_TOLERANCE = 1.05


def _rate(metric: str, selector: str, ceiling: int = MAX_PLAUSIBLE_BYTES_PER_SECOND,
          window: str = RATE_WINDOW) -> str:
    """A counter rate with the physically impossible filtered out."""
    return f"(rate({metric}{selector}[{window}]) < {ceiling})"


def _throughput_rate(metric: str, selector: str, window: str) -> str:
    """A byte rate the port could actually have carried.

    Bounded by the port's own speed rather than by an absolute backstop,
    because the artifacts that matter are the ones just above line rate. A
    collector polling more slowly than the storage scrapes leaves the counter
    flat for several scrapes and then jumps, and a rate window shorter than
    twice the poll interval reads that jump as one interval's worth of traffic
    -- four gigabits on a gigabit port. Dropping the point leaves a gap, which
    is what actually happened.

    `unless` keeps ports that report no speed at all: they are unbounded rather
    than excluded, since silently dropping a port from every chart would be a
    worse failure than drawing one impossible point.
    """
    base = f"rate({metric}{selector}[{window}])"
    limit = f"(netrune_interface_speed_bits{selector} / 8 * {RATE_TOLERANCE})"
    return (f"(({base} < on({IDENTITY_LABELS}) {limit})"
            f" or ({base} unless on({IDENTITY_LABELS})"
            f" netrune_interface_speed_bits{selector}))")


def _receive(selector: str = "", window: str = RATE_WINDOW) -> str:
    return _throughput_rate("netrune_interface_receive_bytes_total", selector, window)


def _transmit(selector: str = "", window: str = RATE_WINDOW) -> str:
    return _throughput_rate("netrune_interface_transmit_bytes_total", selector, window)


def _utilisation(selector: str = "") -> str:
    """Combined throughput as a share of the speed the device reports."""
    return (f"100 * 8 * ({_receive(selector)} + {_transmit(selector)})"
            f" / netrune_interface_speed_bits{selector}")


def _throughput(selector: str = "") -> str:
    return f"8 * ({_receive(selector)} + {_transmit(selector)})"


def _complaints(selector: str = "") -> str:
    packets = MAX_PLAUSIBLE_PACKETS_PER_SECOND
    return " + ".join(
        _rate(f"netrune_interface_{name}", selector, packets)
        for name in ("receive_errors_total", "transmit_errors_total",
                     "receive_drops_total", "transmit_drops_total"))


def device_dashboard() -> Dashboard:
    """The switches behind the watched ports.

    Netrune collects this because the ports made it necessary, not because a
    switch is interesting on its own. Throughput that fell to nothing means one
    thing if the switch rebooted, another if its control plane is saturated, and
    another if the link is simply idle -- and reading those from three separate
    places is how the wrong conclusion gets drawn. Every panel here is a reason
    an interface graph might be lying.
    """
    selector = '{device=~"$device"}'
    return Dashboard(
        uid="netrune-switches",
        title="Netrune / Switches",
        description=("Uptime, load, temperature, and management-plane access for every switch "
                     "with a watched port. Collected automatically alongside the ports."),
        variables=(Variable("device", "Switch", "device", "netrune_device_uptime_seconds"),),
        panels=(
            Panel(
                key="uptime",
                title="Uptime",
                description=("A drop is a restart, and a restart zeroes every interface counter on "
                             "the switch. A throughput gap that lines up with a drop here is the "
                             "reboot, not a fault on the link."),
                unit=Unit.SECONDS,
                kind=PanelKind.BARGAUGE,
                width=8, height=7,
                thresholds=(Threshold(0, Level.CRITICAL), Threshold(3600, Level.WARNING),
                            Threshold(86400, Level.OK)),
                queries=(Query(f"netrune_device_uptime_seconds{selector}", "{{device}}"),),
            ),
            Panel(
                key="cpu",
                title="Control-plane CPU",
                description=("A pinned control plane delays SNMP replies, so readings arrive late "
                             "and rates computed from them come out low. Suspect this before "
                             "believing a sudden estate-wide quiet."),
                unit=Unit.PERCENT,
                width=8, height=7,
                max_value=100,
                threshold_lines=True,
                thresholds=(Threshold(0, Level.OK), Threshold(70, Level.WARNING),
                            Threshold(90, Level.CRITICAL)),
                queries=(Query(f"netrune_device_cpu_percent{selector}", "{{device}}"),),
            ),
            Panel(
                key="temperature",
                title="Temperature",
                description=("The warmest sensor each switch exposes. A climbing cabinet shows up "
                             "here days before it shows up as a port flapping."),
                unit=Unit.CELSIUS,
                width=8, height=7,
                queries=(Query(f"netrune_device_temperature_celsius{selector}", "{{device}}"),),
            ),
            Panel(
                key="memory",
                title="Memory in use",
                description="Against what the switch reports having.",
                unit=Unit.PERCENT,
                kind=PanelKind.BARGAUGE,
                width=8, height=7,
                max_value=100,
                thresholds=(Threshold(0, Level.OK), Threshold(75, Level.WARNING),
                            Threshold(90, Level.CRITICAL)),
                queries=(Query(
                    f"100 * netrune_device_memory_used_bytes{selector}"
                    f" / netrune_device_memory_bytes{selector}", "{{device}}"),),
            ),
            Panel(
                key="access",
                title="Rejected management access",
                description=("SNMP requests refused for a wrong community, and TCP connections "
                             "refused, per second. Both rise together when something is scanning "
                             "the management network. No standard MIB reports failed SSH logins -- "
                             "for those, read the switch's syslog. "
                             "Netrune's own first contact with a switch counts here too: the "
                             "SNMP helper tries each configured community until one answers, and "
                             "the ones that did not are rejections. It caches the winner, so a "
                             "steady baseline is somebody else's traffic."),
                unit=Unit.PACKETS_PER_SECOND,
                width=8, height=7,
                thresholds=(Threshold(0, Level.OK), Threshold(0.05, Level.WARNING)),
                queries=(
                    Query(f"rate(netrune_device_snmp_rejected_community_total{selector}[{RATE_WINDOW}])",
                          "{{device}} wrong community"),
                    Query(f"rate(netrune_device_snmp_bad_version_total{selector}[{RATE_WINDOW}])",
                          "{{device}} bad version"),
                    Query(f"rate(netrune_device_tcp_refused_total{selector}[{RATE_WINDOW}])",
                          "{{device}} refused TCP"),
                ),
            ),
            Panel(
                key="sessions",
                title="Sessions",
                description=("Logged-in sessions and open TCP connections. A session count that "
                             "does not fall back to its baseline is somebody still connected."),
                unit=Unit.COUNT,
                width=8, height=7,
                stepped=True,
                queries=(
                    Query(f"netrune_device_logged_in_users{selector}", "{{device}} logged in"),
                    Query(f"netrune_device_tcp_established{selector}", "{{device}} TCP open"),
                ),
            ),
        ),
    )


def _link_tiles(links: Sequence[ServiceLink]) -> List[Panel]:
    """One tile per purchased link, plus the total, reading down over up.

    Absolute bits per second rather than a share of the contract. A percentage
    answers "how close to full", which is worth knowing but is not the number
    an operator recites when someone asks what the line is doing -- and it goes
    wrong quietly when the recorded contract is wrong, where a rate in Mbps is
    just a rate in Mbps.

    Generated from the watchlist rather than fixed, because which links exist is
    a property of the estate and not of this file.
    """
    tiles: List[Panel] = []
    slots = len(links) + 1
    width = max(3, 16 // slots)
    for link in links:
        tiles.append(Panel(
            key=f"link_{_slug(link.name)}",
            title=link.name,
            description=(f"{link.name} right now: download over upload. Down is provider to "
                         "LAN, up is LAN to provider -- the same direction the switch's own "
                         "counters read. Averaged over a minute, so it settles quickly when "
                         "the link goes quiet."),
            unit=Unit.BITS_PER_SECOND,
            kind=PanelKind.STAT,
            width=width, height=6,
            color=link.color,
            spark=True,
            queries=(
                Query(_service_rate("down", only=link.name, window=TILE_RATE_WINDOW), "down"),
                Query(_service_rate("up", only=link.name, window=TILE_RATE_WINDOW), "up"),
            ),
        ))
    tiles.append(Panel(
        key="wan_total",
        title="WAN",
        description=("Every purchased link added together. This is the number that answers "
                     "\"what is the site pulling right now\"."),
        unit=Unit.BITS_PER_SECOND,
        kind=PanelKind.STAT,
        width=max(3, 16 - width * len(links)) if links else 8,
        height=6,
        color=SERIES_COLOR_WAN,
        spark=True,
        queries=(Query(_wan_total("down", window=TILE_RATE_WINDOW), "down"),
                 Query(_wan_total("up", window=TILE_RATE_WINDOW), "up")),
    ))
    return tiles


def _link_graphs(links: Sequence[ServiceLink]) -> List[Panel]:
    """One small chart per link rather than all of them on one axis.

    Overlaid, the links hide each other: a link running at 900 Mb/s and one at
    5 Mb/s share a scale on which the second is a flat line along zero, and the
    trend that matters on the quiet link is exactly the one the busy one erases.
    Side by side, each gets its own scale and its own shape.

    They are read as a row of shapes, not compared as numbers -- the tiles above
    carry the numbers -- so the scales differing between them is the point
    rather than a flaw.
    """
    if not links:
        return []
    width = max(6, 24 // len(links))
    # One scale across all of them, taken from the largest thing anybody here
    # is paying for. Given its own axis each link fills its panel and they all
    # look alike, which is the opposite of what a row of them is for: a link
    # carrying a tenth of another's traffic should look like it. Soft, so a
    # link that genuinely exceeds its subscription is still drawn whole.
    anchor = max([link.down_bps for link in links] + [link.up_bps for link in links]
                 + [LINK_CEILING_BPS])
    return [
        Panel(
            key=f"trend_{_slug(link.name)}",
            title=f"{link.name} trend",
            description=(f"{link.name} over the window: download above the line, upload below, "
                         "on an axis centred at zero. Every link on this row shares one scale, "
                         "so their heights are comparable -- a link carrying a tenth of another's "
                         "traffic looks like it, rather than filling its own panel and looking "
                         "the same. The scale is the largest link anybody here pays for."),
            unit=Unit.BITS_PER_SECOND,
            width=width, height=7,
            min_zero=False,
            centered_zero=True,
            soft_max=anchor,
            zero_line=True,
            queries=(
                Query(_service_rate("down", only=link.name), f"{link.name} download"),
                Query(f"-1 * ({_service_rate('up', only=link.name)})", f"{link.name} upload"),
            ),
        )
        for link in links
    ]


def _slug(text: str) -> str:
    return "".join(char.lower() if char.isalnum() else "_" for char in text)


def overview_dashboard(links: Sequence[ServiceLink] = ()) -> Dashboard:
    """One screen, read top to bottom as one argument.

    The first row is the question anyone actually asks: how full is the line we
    pay for. Utilisation against a port's line rate does not answer it -- a
    gigabit port carrying a 100M service reads 10% at the moment the service is
    full -- so the bars are drawn against what the link is sold at, recorded
    with 'netrune traffic subscribe'.

    The second row is what that traffic looks like over time and whether the
    network is reachable at all. The third is what is going wrong and where.
    The fourth is the switches underneath, which is where a wrong answer above
    usually comes from.

    Numbers are used where a number is the answer and drawn where a shape is.
    Charts are bounded with topk, because past a handful of lines a chart stops
    telling them apart.
    """
    return Dashboard(
        uid="netrune-overview",
        title="Netrune / Overview",
        description="What each purchased link is carrying, and what needs attention.",
        window="6h",
        # The tiles are read as a live number, so the board refreshes on the
        # order of the collection interval rather than the minute a dashboard
        # of daily trends would use.
        refresh="5s",
        panels=(
            # ---- row 1: the lines you pay for --------------------------------
            *_link_tiles(links),
            Panel(
                key="collection_age",
                title="Last reading",
                description=("Seconds since any interface was read. Read it before believing "
                             "anything else here: a stopped collector leaves gaps, and a gap is "
                             "not a quiet network."),
                unit=Unit.SECONDS,
                kind=PanelKind.STAT,
                width=4, height=6, spark=True,
                thresholds=(Threshold(0, Level.OK), Threshold(180, Level.WARNING),
                            Threshold(600, Level.CRITICAL)),
                queries=(Query("time() - max(netrune_interface_last_poll_timestamp_seconds)", "age"),),
            ),
            Panel(
                key="links_down",
                title="Links down",
                description=("Ports operationally down while administratively up. A port that was "
                             "shut deliberately is not counted. Kept small on purpose: when this "
                             "is zero it should not draw the eye."),
                unit=Unit.COUNT,
                kind=PanelKind.STAT,
                width=4, height=6, spark=True,
                thresholds=(Threshold(0, Level.OK), Threshold(1, Level.CRITICAL)),
                queries=(Query("sum(netrune_interface_up == 0 and netrune_interface_admin_up == 1)"
                               " or vector(0)", "down"),),
            ),

            # ---- row 2: each link's own shape --------------------------------
            *_link_graphs(links),

            # ---- row 3: everything together, and can we reach anything -------
            Panel(
                key="wan_traffic",
                title="Internet traffic, combined",
                description=("Every link on one axis, with the WAN total over the top. This is the "
                             "one to read when the question is how much the site is moving; the "
                             "row above is the one to read when the question is which link moved. "
                             "Download above the line, upload below, centred at zero so the same "
                             "number of bits is the same distance either way."),
                unit=Unit.BITS_PER_SECOND,
                width=14, height=9,
                min_zero=False,
                centered_zero=True,
                queries=(Query(_service_rate("down"), "{{name}} download"),
                         Query(f"-1 * ({_service_rate('up')})", "{{name}} upload"),
                         # The combined line over the top, so the per-link
                         # detail and the number that matters to the business
                         # are in one picture rather than two.
                         Query(_wan_total("down"), "WAN download"),
                         Query(f"-1 * {_wan_total('up')}", "WAN upload")),
            ),
            Panel(
                key="reachability",
                title="Reachability",
                description=("Latency, its variation, and loss, per probed address. Read loss "
                             "first: latency measured during loss is an average over the packets "
                             "that made it back, so a link dropping traffic can look fast. "
                             "Jitter well above latency means a congested or unstable path even "
                             "when nothing is lost."),
                unit=Unit.SECONDS,
                kind=PanelKind.TABLE,
                width=10, height=9,
                columns=("target",),
                join_by="target",
                sort_by="loss",
                thresholds=(Threshold(0, Level.OK),),
                queries=(
                    Query("netrune_icmp_rtt_seconds", "latency", unit=Unit.SECONDS),
                    Query("netrune_icmp_jitter_seconds", "jitter", unit=Unit.SECONDS),
                    Query("netrune_icmp_loss_ratio", "loss", unit=Unit.RATIO),
                    Query("netrune_icmp_up", "up", unit=Unit.COUNT),
                ),
            ),

            # ---- how full each of them is ------------------------------------
            *([Panel(
                key="against_subscription",
                title="Against the subscription",
                description=("Each link, and the total, as a share of what it is sold at. "
                             "Absolute rates are the row of tiles above; this is the question "
                             "those cannot answer -- 600 Mb/s means something different on a "
                             "gigabit service than on a 600 Mb one. Soft limits: a provider that "
                             "lets a link burst will read above 100 here, which is information "
                             "rather than an error."),
                unit=Unit.PERCENT,
                kind=PanelKind.BARGAUGE,
                width=24,
                # Two bars per link plus the two totals, and a bar that does not
                # fit is a bar nobody can read: the WAN pair was falling off the
                # bottom, which is the one row somebody scrolls to this panel
                # for.
                height=max(6, 1 + (len(links) * 2 + 2)),
                max_value=100,
                thresholds=(Threshold(0, Level.OK), Threshold(60, Level.WARNING),
                            Threshold(85, Level.CRITICAL)),
                queries=(Query(_service_share("down"), "{{name}} down"),
                         Query(_service_share("up"), "{{name}} up"),
                         Query(_wan_share("down"), "WAN down"),
                         Query(_wan_share("up"), "WAN up")),
            )] if links else []),

            # ---- row 3: what is going wrong -----------------------------------
            Panel(
                key="complaining",
                title="Links reporting errors",
                description=("Which port, and which counter, per second. The counter is most of "
                             "the diagnosis:\n"
                             "- input errors: the physical layer -- a cable, an optic, a dirty "
                             "connector, or a duplex mismatch. CRCs arrive damaged.\n"
                             "- output discards: congestion. The port had more to send than it "
                             "could, and the egress queue overflowed. The link is undersized or "
                             "something is bursting.\n"
                             "- input discards: the switch could not accept it -- an ingress "
                             "policer, a full queue, or no buffer.\n"
                             "- output errors: rare, and usually the port or its driver rather "
                             "than the cable.\n"
                             "Rows are the watched ports, worst first."),
                unit=Unit.PACKETS_PER_SECOND,
                kind=PanelKind.TABLE,
                width=14, height=8,
                columns=("link",),
                join_by="link",
                sort_by="total",
                thresholds=(Threshold(0, Level.OK), Threshold(0.01, Level.WARNING),
                            Threshold(1, Level.CRITICAL)),
                queries=(
                    Query(_named(f"topk(10, {_complaints()})"), "total"),
                    Query(_named(_rate("netrune_interface_receive_errors_total", "",
                                       MAX_PLAUSIBLE_PACKETS_PER_SECOND)), "input errors"),
                    Query(_named(_rate("netrune_interface_transmit_errors_total", "",
                                       MAX_PLAUSIBLE_PACKETS_PER_SECOND)), "output errors"),
                    Query(_named(_rate("netrune_interface_receive_drops_total", "",
                                       MAX_PLAUSIBLE_PACKETS_PER_SECOND)), "input discards"),
                    Query(_named(_rate("netrune_interface_transmit_drops_total", "",
                                       MAX_PLAUSIBLE_PACKETS_PER_SECOND)), "output discards"),
                ),
            ),
            Panel(
                key="busiest",
                title="Busiest links",
                description=("The five highest-throughput watched ports, in and out combined -- "
                             "every port, not only the paid ones. The axis starts at a full "
                             "gigabit so a quiet link is drawn quiet instead of auto-scaling its "
                             "own noise into something that looks like load."),
                unit=Unit.BITS_PER_SECOND,
                width=10, height=8,
                soft_max=LINK_CEILING_BPS,
                queries=(Query(_named(f"topk(5, {_throughput()})"), "{{device}} {{name}}"),),
            ),

            # ---- row 4: the switches underneath --------------------------------
            Panel(
                key="switch_uptime",
                title="Switch uptime",
                description=("Shortest first, because a switch that just restarted is the reason "
                             "to look. A restart zeroes that switch's interface counters, so a "
                             "throughput gap lining up with a short uptime here is the reboot "
                             "rather than a fault on the link."),
                unit=Unit.SECONDS,
                kind=PanelKind.BARGAUGE,
                width=8, height=6,
                thresholds=(Threshold(0, Level.CRITICAL), Threshold(3600, Level.WARNING),
                            Threshold(86400, Level.OK)),
                queries=(Query("bottomk(5, netrune_device_uptime_seconds)", "{{device}}"),),
            ),
            Panel(
                key="temperature",
                title="Switch temperature",
                description=("The warmest sensor each switch exposes. A cabinet losing its cooling "
                             "shows up here days before it shows up as a port flapping."),
                unit=Unit.CELSIUS,
                kind=PanelKind.BARGAUGE,
                width=8, height=6,
                thresholds=(Threshold(0, Level.OK), Threshold(45, Level.WARNING),
                            Threshold(60, Level.CRITICAL)),
                queries=(Query("netrune_device_temperature_celsius", "{{device}}"),),
            ),
            Panel(
                key="switch_load",
                title="Switch control plane",
                description=("CPU on the switches behind the watched ports. A pinned control plane "
                             "answers SNMP late, which makes every rate above come out low -- so "
                             "an estate-wide quiet is checked here first."),
                unit=Unit.PERCENT,
                width=8, height=6,
                max_value=100,
                threshold_lines=True,
                thresholds=(Threshold(0, Level.OK), Threshold(70, Level.WARNING),
                            Threshold(90, Level.CRITICAL)),
                queries=(Query("topk(5, netrune_device_cpu_percent)", "{{device}}"),),
            ),
        ),
    )


def all_dashboards(series_colors: Optional[Mapping[str, str]] = None,
                   links: Sequence[ServiceLink] = ()) -> List[Dashboard]:
    # Overview first: it is the one that says whether the others are worth opening.
    boards = [overview_dashboard(links), interface_dashboard(), device_dashboard(),
              reachability_dashboard(), collector_dashboard()]
    if not series_colors:
        return boards
    return [replace(board, series_colors=dict(series_colors)) for board in boards]

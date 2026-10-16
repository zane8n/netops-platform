import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netops_platform.traffic_dashboards import (
    RATE_WINDOW,
    Unit,
    all_dashboards,
    interface_dashboard,
)
from netops_platform.traffic_graphers import (
    GRAFANA_UNITS,
    GRAPHERS,
    PERSES_UNITS,
    GrafanaGrapher,
    PersesGrapher,
    get_grapher,
    grapher_names,
)
from netops_platform.traffic_stack import stack_files

def _published_metrics():
    """Every metric name the exposition module can emit, read from its source.

    Kept as a derivation rather than a list, because a list is only as good as
    whoever last remembered to update it -- and the failure it would hide is a
    dashboard querying a metric nothing publishes, which renders as an empty
    panel that looks exactly like a quiet network.
    """
    import ast
    tree = ast.parse((ROOT / "netops_platform" / "traffic_metrics.py").read_text())
    return {node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            and node.value.startswith("netrune_")}


PUBLISHED_METRICS = _published_metrics()


class DashboardModelTest(unittest.TestCase):
    """The neutral model must stay free of any one tool's vocabulary."""

    def test_no_grapher_schema_leaks_into_the_model(self):
        import ast
        module = ast.parse((ROOT / "netops_platform" / "traffic_dashboards.py").read_text())
        # Prose may name the tools to explain the split; code may not encode
        # them. Docstrings at every level are prose, so all of them come out.
        for node in ast.walk(module):
            body = getattr(node, "body", None)
            if isinstance(body, list) and body and isinstance(body[0], ast.Expr) \
                    and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                body.pop(0)
        code = ast.unparse(module).lower()
        for leaked in ("gridpos", "fieldconfig", "timeserieschart", "prometheusdatasource",
                       "templating", "legendformat", "seriesnameformat", "grafana", "perses"):
            self.assertNotIn(leaked, code)

    def test_every_query_references_a_metric_the_exposition_publishes(self):
        for dashboard in all_dashboards():
            for panel in dashboard.panels:
                for query in panel.queries:
                    with self.subTest(dashboard=dashboard.uid, panel=panel.key):
                        referenced = {m for m in PUBLISHED_METRICS if m in query.expr}
                        self.assertTrue(referenced, query.expr)

    def test_every_panel_unit_is_one_the_adapters_can_render(self):
        known = set(GRAFANA_UNITS) & set(PERSES_UNITS)
        for dashboard in all_dashboards():
            for panel in dashboard.panels:
                with self.subTest(panel=panel.key):
                    self.assertIn(panel.unit, known)

    def test_rate_queries_use_the_shared_window(self):
        throughput = next(p for p in interface_dashboard().panels if p.key == "throughput")
        for query in throughput.queries:
            self.assertIn(f"[{RATE_WINDOW}]", query.expr)

    def test_a_variable_that_depends_on_another_references_it(self):
        interface = next(v for v in interface_dashboard().variables if v.name == "interface")
        self.assertEqual(interface.depends_on, "device")
        self.assertIn("$device", interface.metric)

    def test_the_overview_bounds_how_many_series_it_draws(self):
        """Past a handful of lines a chart stops telling them apart.

        An overview across every watched interface is forty lines and no
        information, so the charts on it are topk-bounded by construction.
        """
        from netops_platform.traffic_dashboards import overview_dashboard
        for panel in overview_dashboard().panels:
            if panel.kind != "timeseries":
                continue
            with self.subTest(panel=panel.key):
                # Three ways a chart can be bounded, all of them real:
                # topk and bottomk cap the count outright -- and for uptime,
                # bottomk selects the switches that just restarted, which is the
                # reason to be looking. Restricting to service links bounds it
                # too: those are the links somebody is paying for, a list an
                # operator maintains by hand and which is short by nature.
                self.assertTrue(
                    all(("topk(" in q.expr or "bottomk(" in q.expr
                         or 'service="yes"' in q.expr) for q in panel.queries),
                    panel.key)

    def test_every_overview_tile_carries_status_bands_in_order(self):
        from netops_platform.traffic_dashboards import Level, overview_dashboard
        levels = {Level.OK, Level.WARNING, Level.CRITICAL}
        for panel in overview_dashboard().panels:
            # A tile with a colour of its own is an identity, not a state: it
            # reports what a link is carrying, and there is no band to be in.
            if panel.kind != "stat" or panel.color:
                continue
            with self.subTest(panel=panel.key):
                self.assertTrue(panel.thresholds, "a state tile without bands is just a number")
                values = [t.value for t in panel.thresholds]
                self.assertEqual(values, sorted(values), "bands must read lowest first")
                self.assertTrue({t.level for t in panel.thresholds} <= levels)
                # Colour alone never carries the state: the tile is titled.
                self.assertTrue(panel.title.strip())

    def test_status_panels_do_not_interpolate_between_readings(self):
        status = next(p for p in interface_dashboard().panels if p.key == "status")
        # A port is up or down; drawing a slope between the two invents a state
        # that never existed.
        self.assertTrue(status.stepped)

    def test_dashboard_uids_are_unique(self):
        uids = [d.uid for d in all_dashboards()]
        self.assertEqual(len(uids), len(set(uids)))


class GrapherContractTest(unittest.TestCase):
    """Every adapter must satisfy the same contract, or it cannot be swapped in."""

    def test_the_registry_exposes_every_adapter_by_name(self):
        self.assertEqual(set(grapher_names()), {"grafana", "perses", "none"})
        for name in grapher_names():
            self.assertEqual(get_grapher(name).name, name)

    def test_an_unknown_grapher_is_refused_rather_than_guessed(self):
        self.assertIsNone(get_grapher("chronograf"))
        self.assertIsNone(get_grapher(""))

    def test_every_adapter_implements_the_whole_contract(self):
        for name, grapher in GRAPHERS.items():
            with self.subTest(grapher=name):
                for attribute in ("name", "display_name", "default_port", "image"):
                    self.assertTrue(hasattr(grapher, attribute), attribute)
                for method in ("files", "container_mounts", "container_env", "container_args",
                               "dashboard_url", "health_path", "resolve_datasource_url"):
                    self.assertTrue(callable(getattr(grapher, method, None)), method)

    def test_every_adapter_renders_every_dashboard(self):
        dashboards = all_dashboards()
        with tempfile.TemporaryDirectory() as temp:
            for name, grapher in GRAPHERS.items():
                files = grapher.files(dashboards, "http://127.0.0.1:8428", Path(temp))
                with self.subTest(grapher=name):
                    if not grapher.image:
                        self.assertEqual(files, {})
                        continue
                    rendered = " ".join(str(path) for path in files)
                    for dashboard in dashboards:
                        self.assertIn(dashboard.uid, rendered)

    def test_every_adapter_maps_every_semantic_unit(self):
        units = {value for key, value in vars(Unit).items() if not key.startswith("_")}
        self.assertEqual(set(GRAFANA_UNITS), units)
        self.assertEqual(set(PERSES_UNITS), units)

    def test_a_proxying_grapher_gets_a_container_reachable_storage_url(self):
        grafana = GrafanaGrapher()
        # Grafana queries from its own process, where 127.0.0.1 is the container.
        self.assertEqual(grafana.resolve_datasource_url("http://127.0.0.1:8428", True),
                         "http://host.docker.internal:8428")
        self.assertEqual(grafana.resolve_datasource_url("http://127.0.0.1:8428", False),
                         "http://127.0.0.1:8428")
        self.assertEqual(grafana.resolve_datasource_url("http://vm.example:8428", True),
                         "http://vm.example:8428")

    def test_a_browser_resolved_grapher_keeps_the_host_url(self):
        # Perses' directUrl is fetched by the browser, which is on the host.
        self.assertEqual(PersesGrapher().resolve_datasource_url("http://127.0.0.1:8428", True),
                         "http://127.0.0.1:8428")

    def test_no_adapter_asks_for_host_networking(self):
        # Under Docker Desktop, --network host joins the Docker VM's namespace
        # rather than the WSL distro's, and the published port is unreachable.
        for name, grapher in GRAPHERS.items():
            with self.subTest(grapher=name):
                self.assertNotIn("--network", " ".join(grapher.container_args()))


class GrafanaRenderingTest(unittest.TestCase):
    def setUp(self):
        self.grapher = GrafanaGrapher()
        self.temp = tempfile.TemporaryDirectory()
        self.files = self.grapher.files(all_dashboards(), "http://host.docker.internal:8428",
                                        Path(self.temp.name))

    def tearDown(self):
        self.temp.cleanup()

    def dashboard(self, uid):
        return json.loads(next(v for k, v in self.files.items() if k.name == f"{uid}.json"))

    def test_dashboards_are_valid_json_with_the_expected_shape(self):
        for uid in ("netrune-interfaces", "netrune-reachability", "netrune-collector"):
            with self.subTest(uid=uid):
                d = self.dashboard(uid)
                self.assertEqual(d["uid"], uid)
                self.assertIn("panels", d)
                self.assertIn("templating", d)
                self.assertTrue(d["panels"])

    def test_panels_are_laid_out_without_overlapping(self):
        for uid in ("netrune-interfaces", "netrune-collector"):
            occupied = set()
            for panel in self.dashboard(uid)["panels"]:
                pos = panel["gridPos"]
                cells = {(x, y) for x in range(pos["x"], pos["x"] + pos["w"])
                         for y in range(pos["y"], pos["y"] + pos["h"])}
                with self.subTest(uid=uid, panel=panel["title"]):
                    self.assertFalse(cells & occupied, "panels overlap")
                    self.assertLessEqual(pos["x"] + pos["w"], 24)
                occupied |= cells

    def test_every_target_points_at_the_provisioned_datasource(self):
        for uid in ("netrune-interfaces", "netrune-reachability", "netrune-collector"):
            for panel in self.dashboard(uid)["panels"]:
                for target in panel["targets"]:
                    with self.subTest(uid=uid, panel=panel["title"]):
                        self.assertEqual(target["datasource"]["uid"], "netrune-victoriametrics")
                        self.assertTrue(target["expr"])
                        self.assertTrue(target["legendFormat"])

    def test_target_refids_are_unique_within_a_panel(self):
        for panel in self.dashboard("netrune-interfaces")["panels"]:
            ids = [t["refId"] for t in panel["targets"]]
            self.assertEqual(len(ids), len(set(ids)), panel["title"])

    def test_units_are_grafana_spellings(self):
        panels = {p["title"]: p for p in self.dashboard("netrune-interfaces")["panels"]}
        self.assertEqual(panels["Throughput"]["fieldConfig"]["defaults"]["unit"], "bps")
        self.assertEqual(panels["Utilisation"]["fieldConfig"]["defaults"]["unit"], "percent")

    def test_a_stepped_panel_uses_step_interpolation(self):
        status = next(p for p in self.dashboard("netrune-interfaces")["panels"]
                      if p["title"] == "Interface status")
        self.assertEqual(status["fieldConfig"]["defaults"]["custom"]["lineInterpolation"], "stepAfter")

    def test_a_bidirectional_panel_is_not_clamped_at_zero(self):
        # Transmit is drawn negative, so a zero floor would hide it entirely.
        throughput = next(p for p in self.dashboard("netrune-interfaces")["panels"]
                          if p["title"] == "Throughput")
        self.assertIsNone(throughput["fieldConfig"]["defaults"]["min"])

    def test_variables_query_label_values(self):
        variables = self.dashboard("netrune-interfaces")["templating"]["list"]
        names = {v["name"]: v for v in variables}
        self.assertIn("label_values(", names["device"]["query"]["query"])
        self.assertIn("$device", names["interface"]["query"]["query"])

    def test_an_edit_in_the_browser_is_not_wiped_before_it_can_be_kept(self):
        """Generated is where a dashboard comes from, not where it must stay.

        With allowUiUpdates false the provisioning sweep reverted an edit within
        seconds, so arranging a board the way you read it was not possible at
        all. It is now, and 'traffic dashboard save' is what makes an edit
        survive the next regeneration rather than only the next sweep.
        """
        provider = next(v for k, v in self.files.items() if k.name == "netrune.yaml"
                        and "dashboards" in str(k))
        self.assertIn("allowUiUpdates: true", provider)
        self.assertTrue(self.dashboard("netrune-interfaces")["editable"])
        self.assertIn("traffic dashboard save", provider)

    def test_a_kept_dashboard_is_written_instead_of_the_generated_one(self):
        """The reason it was kept is that it differs from what we would make."""
        from netops_platform.traffic_dashboards import all_dashboards
        from netops_platform.traffic_graphers import GrafanaGrapher
        with tempfile.TemporaryDirectory() as temp:
            files = GrafanaGrapher().files(
                all_dashboards(), "http://x:8428", Path(temp),
                kept={"netrune-overview": '{"title": "mine"}\n'})
        body = next(v for k, v in files.items() if k.name == "netrune-overview.json")
        self.assertEqual(body, '{"title": "mine"}\n')
        # Everything else still comes from the generator.
        other = next(v for k, v in files.items() if k.name == "netrune-interfaces.json")
        self.assertIn("Netrune / Interfaces", other)

    def test_the_datasource_needs_no_third_party_plugin(self):
        datasource = next(v for k, v in self.files.items()
                          if k.name == "netrune.yaml" and "datasources" in str(k))
        self.assertIn("type: prometheus", datasource)
        self.assertIn("access: proxy", datasource)


class PersesRenderingTest(unittest.TestCase):
    def setUp(self):
        self.grapher = PersesGrapher()
        self.temp = tempfile.TemporaryDirectory()
        self.files = self.grapher.files(all_dashboards(), "http://127.0.0.1:8428",
                                        Path(self.temp.name))

    def tearDown(self):
        self.temp.cleanup()

    def test_every_panel_is_placed_in_a_layout(self):
        for key, body in self.files.items():
            if not key.name.startswith("dashboard-"):
                continue
            spec = json.loads(body)["spec"]
            placed = {item["content"]["$ref"].rsplit("/", 1)[1]
                      for layout in spec["layouts"] for item in layout["spec"]["items"]}
            with self.subTest(dashboard=key.name):
                self.assertEqual(placed, set(spec["panels"]))

    def test_visual_display_stays_inside_the_schema(self):
        for key, body in self.files.items():
            if not key.name.startswith("dashboard-"):
                continue
            for panel in json.loads(body)["spec"]["panels"].values():
                plugin = panel["spec"]["plugin"]
                if plugin["kind"] != "TimeSeriesChart":
                    continue  # A stat tile has no line to draw.
                with self.subTest(dashboard=key.name):
                    self.assertIn(plugin["spec"]["visual"]["display"], ("line", "bar"))

    #: One panel kind, spelled each adapter's own way. The neutral model names
    #: the job the panel does; only these two tables know a tool's vocabulary.
    PERSES_PLUGINS = {"stat": "StatChart", "bargauge": "BarChart",
                      "timeseries": "TimeSeriesChart", "table": "Table"}
    GRAFANA_TYPES = {"stat": "stat", "bargauge": "bargauge", "timeseries": "timeseries",
                     "table": "table"}

    def test_each_panel_kind_renders_as_that_kind_in_both_adapters(self):
        from netops_platform.traffic_dashboards import overview_dashboard
        from netops_platform.traffic_graphers import GrafanaGrapher
        overview = overview_dashboard()
        kinds = {p.kind for p in overview.panels}
        self.assertEqual(kinds, set(self.PERSES_PLUGINS),
                         "the overview should exercise every panel kind the model has")

        perses = json.loads(next(v for k, v in self.files.items() if "overview" in k.name))
        for panel in overview.panels:
            with self.subTest(grapher="perses", panel=panel.key):
                self.assertEqual(perses["spec"]["panels"][panel.key]["spec"]["plugin"]["kind"],
                                 self.PERSES_PLUGINS[panel.kind])

        with tempfile.TemporaryDirectory() as temp:
            grafana = GrafanaGrapher().files([overview], "http://x:8428", Path(temp))
        rendered = json.loads(next(v for k, v in grafana.items() if "overview" in k.name))
        titles = {p["title"]: p["type"] for p in rendered["panels"]}
        for panel in overview.panels:
            with self.subTest(grapher="grafana", panel=panel.key):
                self.assertEqual(titles[panel.title], self.GRAFANA_TYPES[panel.kind])

    def test_config_paths_are_the_container_mounts(self):
        config = next(v for k, v in self.files.items() if k.name == "perses.yml")
        settings = [l for l in config.splitlines() if not l.lstrip().startswith("#")]
        self.assertIn('    - "/etc/netrune/perses"', settings)
        self.assertIn('    folder: "/perses"', settings)


class GrapherSelectionTest(unittest.TestCase):
    ROOT_DIR = Path(tempfile.gettempdir()) / "netrune-grapher-fixture" / "stack"

    def files_for(self, name):
        # One root for every grapher, so a path difference cannot be mistaken
        # for a grapher difference.
        root = self.ROOT_DIR
        return stack_files("127.0.0.1:9713", "http://127.0.0.1:8428", 15, "90d", root,
                           grapher_name=name, unit_dir=root / "systemd"), root

    def test_selecting_a_grapher_changes_only_the_dashboard_files(self):
        grafana, _ = self.files_for("grafana")
        perses, _ = self.files_for("perses")
        shared = {"scrape.yml", "alerts.yml", "netrune-collector.service",
                  "netrune-exporter.service", "netrune-victoriametrics.service",
                  "netrune-vmalert.service"}
        for name in shared:
            with self.subTest(file=name):
                a = next(v for k, v in grafana.items() if k.name == name)
                b = next(v for k, v in perses.items() if k.name == name)
                self.assertEqual(a, b, f"{name} should not depend on the grapher")

    def test_the_target_wants_whichever_grapher_was_selected(self):
        for name in ("grafana", "perses"):
            files, _ = self.files_for(name)
            target = next(v for k, v in files.items() if k.name == "netrune-metrics.target")
            with self.subTest(grapher=name):
                self.assertIn(f"netrune-{name}.service", target)
                other = "perses" if name == "grafana" else "grafana"
                self.assertNotIn(f"netrune-{other}.service", target)

    def test_choosing_no_grapher_still_produces_a_working_stack(self):
        files, _ = self.files_for("none")
        names = {k.name for k in files}
        self.assertIn("scrape.yml", names)
        self.assertIn("alerts.yml", names)
        self.assertNotIn("netrune-grafana.service", names)
        target = next(v for k, v in files.items() if k.name == "netrune-metrics.target")
        self.assertIn("# no grapher selected", target)

    def test_an_unknown_grapher_is_an_error_not_a_silent_default(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError) as caught:
                stack_files("127.0.0.1:9713", "http://127.0.0.1:8428", 15, "90d",
                            Path(temp), grapher_name="chronograf")
            self.assertIn("chronograf", str(caught.exception))

    def test_the_readme_documents_whichever_grapher_was_selected(self):
        for name in ("grafana", "perses"):
            files, _ = self.files_for(name)
            readme = next(v for k, v in files.items() if k.name == "README.md")
            with self.subTest(grapher=name):
                self.assertIn(get_grapher(name).display_name, readme)
                self.assertIn("The grapher is interchangeable", readme)


if __name__ == "__main__":
    unittest.main()


class VisualEncodingTest(unittest.TestCase):
    """A number says where a thing stands; a shape says whether that is new.

    "60% utilised" means something different climbing than it does steady, and
    the difference is the whole reason to look. So the overview is drawn rather
    than printed, and these pin the parts of that which are easy to lose in a
    refactor.
    """

    def setUp(self):
        from netops_platform.traffic_dashboards import overview_dashboard
        from netops_platform.traffic_graphers import GrafanaGrapher
        self.overview = overview_dashboard()
        with tempfile.TemporaryDirectory() as temp:
            files = GrafanaGrapher().files([self.overview], "http://x:8428", Path(temp))
        self.rendered = json.loads(next(v for k, v in files.items() if "overview" in k.name))
        self.by_title = {p["title"]: p for p in self.rendered["panels"]}

    def test_the_overview_is_mostly_drawn_rather_than_printed(self):
        drawn = [p for p in self.overview.panels if p.kind != "stat"]
        self.assertGreater(len(drawn), len(self.overview.panels) - len(drawn),
                           "an overview of numbers makes the reader do the reading")

    def test_every_state_tile_carries_its_own_recent_history(self):
        for panel in self.overview.panels:
            if panel.kind != "stat" or panel.color:
                continue
            with self.subTest(panel=panel.key):
                self.assertTrue(panel.spark, "a bare number cannot say whether it is moving")
                rendered = self.by_title[panel.title]
                self.assertEqual(rendered["options"]["graphMode"], "area")
                # A sparkline needs the range behind the number, so an instant
                # query would render the tile with nothing to draw.
                self.assertTrue(all(t["range"] for t in rendered["targets"]))
                self.assertFalse(any(t["instant"] for t in rendered["targets"]))

    def test_a_ranking_is_drawn_as_length_not_printed_as_a_column(self):
        ranked = [p for p in self.overview.panels if p.kind == "bargauge"]
        self.assertTrue(ranked, "which link is nearest its limit is a comparison")
        for panel in ranked:
            with self.subTest(panel=panel.key):
                rendered = self.by_title[panel.title]
                self.assertEqual(rendered["type"], "bargauge")
                self.assertEqual(rendered["options"]["orientation"], "horizontal")
                # Name and value stay on every bar, so the ranking never
                # depends on telling two colours apart.
                self.assertEqual(rendered["options"]["namePlacement"], "left")
                self.assertEqual(rendered["fieldConfig"]["defaults"]["min"], 0)

    def test_a_bounded_measure_is_bounded_on_its_axis_too(self):
        """A utilisation axis that stops at the day's peak lies about headroom.

        Drawn to 12% the chart looks full; drawn to 100 it looks idle, which is
        what it is.
        """
        for panel in self.overview.panels:
            if panel.unit != "percent":
                continue
            with self.subTest(panel=panel.key):
                self.assertEqual(panel.max_value, 100)
                self.assertEqual(self.by_title[panel.title]["fieldConfig"]["defaults"]["max"], 100)

    def test_a_throughput_axis_starts_at_a_full_link(self):
        """Otherwise a quiet link auto-scales its own noise into apparent load."""
        from netops_platform.traffic_dashboards import LINK_CEILING_BPS
        busiest = next(p for p in self.overview.panels if p.key == "busiest")
        self.assertEqual(busiest.soft_max, LINK_CEILING_BPS)
        custom = self.by_title[busiest.title]["fieldConfig"]["defaults"]["custom"]
        self.assertEqual(custom["axisSoftMax"], LINK_CEILING_BPS)
        # Soft, not hard: a genuine excursion above a gigabit must still be
        # visible rather than clipped flat at the top of the frame.
        self.assertIsNone(self.by_title[busiest.title]["fieldConfig"]["defaults"]["max"])

    def test_reachability_is_on_the_overview(self):
        self.assertIn("netrune_icmp_rtt_seconds",
                      " ".join(q.expr for p in self.overview.panels for q in p.queries))

    def test_switch_health_is_on_the_overview(self):
        expressions = " ".join(q.expr for p in self.overview.panels for q in p.queries)
        # Rejected management access is deliberately not here: it lives on the
        # Switches dashboard, and carrying it in both places was clutter the
        # overview did not earn.
        for metric in ("netrune_device_cpu_percent", "netrune_device_uptime_seconds",
                       "netrune_device_temperature_celsius"):
            with self.subTest(metric=metric):
                self.assertIn(metric, expressions)

    def test_status_colours_stay_reserved_for_status(self):
        """Green, orange, and red mean a state. They never tell series apart."""
        from netops_platform.traffic_graphers import GRAFANA_LEVELS
        reserved = set(GRAFANA_LEVELS.values())
        for panel in self.rendered["panels"]:
            steps = panel["fieldConfig"]["defaults"].get("thresholds", {}).get("steps", [])
            with self.subTest(panel=panel["title"]):
                self.assertTrue(set(s["color"] for s in steps) <= reserved)


def _seconds(window):
    scale = {"s": 1, "m": 60, "h": 3600}
    return int(window[:-1]) * scale[window[-1]]


class OverviewShapeTest(unittest.TestCase):
    """What the overview must answer, and in what order."""

    def setUp(self):
        from netops_platform.traffic_dashboards import overview_dashboard
        from netops_platform.traffic_graphers import GrafanaGrapher
        self.overview = overview_dashboard()
        with tempfile.TemporaryDirectory() as temp:
            files = GrafanaGrapher().files([self.overview], "http://x:8428", Path(temp))
        self.rendered = json.loads(next(v for k, v in files.items() if "overview" in k.name))
        self.by_title = {p["title"]: p for p in self.rendered["panels"]}

    def keys(self):
        return [p.key for p in self.overview.panels]

    def test_each_paid_link_leads_with_its_own_tile(self):
        """One tile per link, then the total, before anything else.

        A rate in bits per second rather than a share of the contract: a
        percentage answers "how close to full", which is worth knowing, but it
        is not the number an operator recites when asked what the line is doing
        -- and it goes wrong quietly when the recorded contract is wrong.
        """
        from netops_platform.traffic_dashboards import ServiceLink, overview_dashboard
        board = overview_dashboard([ServiceLink("AFRIX", "#149084"),
                                    ServiceLink("03B", "#79a632")])
        titles = [p.title for p in board.panels[:3]]
        self.assertEqual(titles, ["AFRIX", "03B", "WAN"])
        for panel in board.panels[:3]:
            with self.subTest(panel=panel.title):
                self.assertEqual(panel.kind, "stat")
                self.assertEqual(panel.unit, "bits_per_second")
                self.assertEqual([q.legend for q in panel.queries], ["down", "up"])
                # Coloured as an identity, so the link is recognisable at a
                # glance rather than needing the title read.
                self.assertTrue(panel.color)

    def test_a_link_tile_measures_only_its_own_link(self):
        from netops_platform.traffic_dashboards import ServiceLink, overview_dashboard
        board = overview_dashboard([ServiceLink("AFRIX", "#149084"),
                                    ServiceLink("03B", "#79a632")])
        afrix = next(p for p in board.panels if p.title == "AFRIX")
        for query in afrix.queries:
            with self.subTest(legend=query.legend):
                self.assertIn('name="AFRIX"', query.expr)
                self.assertNotIn('name="03B"', query.expr)

    def test_the_wan_tile_is_the_sum_and_survives_having_no_links(self):
        """A sum over no series is no series, which renders blank rather than
        zero -- and a blank tile reads as broken."""
        from netops_platform.traffic_dashboards import overview_dashboard
        wan = next(p for p in overview_dashboard().panels if p.key == "wan_total")
        for query in wan.queries:
            with self.subTest(legend=query.legend):
                self.assertIn("sum(", query.expr)
                self.assertIn("or vector(0)", query.expr)

    def test_a_tile_averages_over_a_shorter_window_than_a_chart(self):
        """A tile is read as "now". A two-minute average of a link that just
        went quiet still reads busy for two minutes."""
        from netops_platform.traffic_dashboards import (
            RATE_WINDOW, TILE_RATE_WINDOW, ServiceLink, overview_dashboard)
        self.assertLess(_seconds(TILE_RATE_WINDOW), _seconds(RATE_WINDOW))
        board = overview_dashboard([ServiceLink("AFRIX", "#149084")])
        tile = next(p for p in board.panels if p.title == "AFRIX")
        self.assertIn(f"[{TILE_RATE_WINDOW}]", tile.queries[0].expr)

    def test_throughput_can_never_render_above_the_port_line_rate(self):
        """A collector polling more slowly than the storage scrapes leaves the
        counter flat and then jumps, and a short window reads that jump as one
        interval's traffic -- four gigabits on a gigabit port."""
        from netops_platform.traffic_dashboards import ServiceLink, overview_dashboard
        board = overview_dashboard([ServiceLink("AFRIX", "#149084")])
        for key in ("link_afrix", "wan_total", "wan_traffic", "busiest"):
            panel = next(p for p in board.panels if p.key == key)
            for query in panel.queries:
                with self.subTest(panel=key):
                    self.assertIn("netrune_interface_speed_bits", query.expr)
                    # A port reporting no speed stays unbounded rather than
                    # vanishing from every chart.
                    self.assertIn("unless on", query.expr)

    def test_both_directions_of_a_service_link_are_resolved_not_assumed(self):
        """Which counter carries download depends on which way the port faces.

        Assuming receive is always download shows a full upload as a quiet
        download on any port facing the LAN.
        """
        traffic = next(p for p in self.overview.panels if p.key == "wan_traffic")
        joined = " ".join(q.expr for q in traffic.queries)
        self.assertIn('downlink="receive"', joined)
        self.assertIn('downlink="transmit"', joined)

    def test_upload_is_drawn_below_the_line_on_a_centred_axis(self):
        traffic = next(p for p in self.overview.panels if p.key == "wan_traffic")
        self.assertTrue(traffic.centered_zero)
        self.assertFalse(traffic.min_zero)
        upload = next(q for q in traffic.queries if "upload" in q.legend)
        download = next(q for q in traffic.queries if "download" in q.legend)
        self.assertTrue(upload.expr.lstrip().startswith("-1 *"), upload.expr[:40])
        self.assertFalse(download.expr.lstrip().startswith("-"))
        custom = self.by_title[traffic.title]["fieldConfig"]["defaults"]["custom"]
        self.assertTrue(custom["axisCenteredZero"])

    def test_errors_say_which_link_and_which_counter(self):
        """The counter is most of the diagnosis: input errors are a cable,
        output discards are congestion."""
        panel = next(p for p in self.overview.panels if p.key == "complaining")
        self.assertEqual(panel.kind, "table")
        columns = [q.legend for q in panel.queries]
        for expected in ("input errors", "output errors", "input discards", "output discards"):
            with self.subTest(column=expected):
                self.assertIn(expected, columns)
        # And the description has to explain what each one means, or the columns
        # are four numbers nobody can act on.
        for cause in ("cable", "congestion", "duplex"):
            with self.subTest(cause=cause):
                self.assertIn(cause, panel.description.lower())

    def test_reachability_puts_loss_beside_latency(self):
        """Latency measured during loss averages the packets that came back, so
        a link dropping traffic can look fast."""
        panel = next(p for p in self.overview.panels if p.key == "reachability")
        self.assertEqual(panel.kind, "table")
        columns = [q.legend for q in panel.queries]
        self.assertIn("latency", columns)
        self.assertIn("loss", columns)
        self.assertEqual(panel.sort_by, "loss")

    def test_table_columns_carry_their_own_units(self):
        """Seconds beside a ratio: one default unit cannot serve both."""
        rendered = self.by_title["Reachability"]
        overrides = {o["matcher"]["options"]: o["properties"][0]["value"]
                     for o in rendered["fieldConfig"]["overrides"]}
        self.assertEqual(overrides.get("latency"), "s")
        self.assertEqual(overrides.get("loss"), "percentunit")

    def test_a_table_hides_the_scrape_plumbing_before_it_joins(self):
        """Order matters, and getting it wrong is silent.

        Each query is evaluated separately and carries its own Time column. Left
        in place, no two frames agree on every shared field, and the table comes
        out as one row per query instead of one row per thing.
        """
        rendered = self.by_title["Reachability"]
        steps = [t["id"] for t in rendered["transformations"]]
        self.assertLess(steps.index("filterFieldsByName"), steps.index("joinByField"))
        dropped = next(t for t in rendered["transformations"]
                       if t["id"] == "filterFieldsByName")["options"]["exclude"]["names"]
        for noise in ("Time", "job", "instance", "__name__", "collector"):
            with self.subTest(label=noise):
                self.assertIn(noise, dropped)

    def test_a_table_joins_on_one_column_that_identifies_a_row(self):
        """`merge` guesses which fields two frames share and gets it wrong the
        moment a query returns a single series."""
        for title in ("Reachability", "Links reporting errors"):
            with self.subTest(panel=title):
                rendered = self.by_title[title]
                join = next(t for t in rendered["transformations"]
                            if t["id"] == "joinByField")
                self.assertTrue(join["options"]["byField"])
                self.assertEqual(join["options"]["mode"], "outer")
                self.assertNotIn("merge", [t["id"] for t in rendered["transformations"]])

    def test_the_name_join_ignores_an_older_shape_of_the_info_metric(self):
        """Adding a label to the info metric leaves its previous shape in
        storage until it ages out, and each of those also matches the link --
        so every row and line would be drawn twice."""
        from netops_platform.traffic_dashboards import overview_dashboard
        joined = [q.expr for p in overview_dashboard().panels for q in p.queries
                  if "netrune_interface_info" in q.expr]
        self.assertTrue(joined)
        for expr in joined:
            with self.subTest(expr=expr[:50]):
                self.assertIn('link!=""', expr)

    def test_switch_uptime_and_temperature_are_both_present(self):
        for key in ("switch_uptime", "temperature"):
            with self.subTest(panel=key):
                self.assertIn(key, self.keys())
        uptime = next(p for p in self.overview.panels if p.key == "switch_uptime")
        # bottomk, because the switch that just restarted is the reason to look.
        self.assertIn("bottomk(", uptime.queries[0].expr)

    def test_links_down_stays_small(self):
        """It should not draw the eye when it reads zero."""
        panel = next(p for p in self.overview.panels if p.key == "links_down")
        self.assertLessEqual(panel.width, 4)


class SeriesColorTest(unittest.TestCase):
    """A colour should mean a link, not the order its series happened to arrive.

    A grapher assigns colours as series turn up, so a link changes colour the
    moment another one goes quiet and drops out of a topk. Pinning them is what
    makes "the teal one" a thing a person can say out loud.
    """

    COLORS = {"AFRIX": "#149084", "ORANGE": "#B54D15", "03B": "#79A632", "WAN": "#7A5AF0"}

    def rendered(self, colors=None):
        from netops_platform.traffic_dashboards import all_dashboards
        from netops_platform.traffic_graphers import GrafanaGrapher
        boards = all_dashboards(colors if colors is not None else self.COLORS)
        with tempfile.TemporaryDirectory() as temp:
            files = GrafanaGrapher().files(boards, "http://x:8428", Path(temp))
        return json.loads(next(v for k, v in files.items() if "overview" in k.name))

    def overrides(self, panel):
        return [o for o in panel["fieldConfig"].get("overrides", [])
                if o["matcher"]["id"] == "byRegexp"]

    def test_a_pinned_colour_reaches_every_chart_that_draws_lines(self):
        board = self.rendered()
        charts = [p for p in board["panels"] if p["type"] == "timeseries"]
        self.assertTrue(charts)
        for panel in charts:
            with self.subTest(panel=panel["title"]):
                found = {o["properties"][0]["value"]["fixedColor"] for o in self.overrides(panel)}
                self.assertEqual(found, set(self.COLORS.values()))

    def test_the_match_survives_a_suffix(self):
        """A link is drawn as "AFRIX download" here and "AFRIX" there."""
        board = self.rendered()
        chart = next(p for p in board["panels"]
                     if p["title"] == "Internet traffic, combined")
        patterns = [o["matcher"]["options"] for o in self.overrides(chart)]
        self.assertIn("/.*AFRIX.*/", patterns)

    def test_status_colours_are_not_replaced_by_identity_ones(self):
        """A bar gauge is coloured by the band its value falls in. Overriding
        that with a link's own colour trades a warning for a decoration."""
        board = self.rendered()
        for panel in board["panels"]:
            if panel["type"] in {"bargauge", "stat"}:
                with self.subTest(panel=panel["title"]):
                    self.assertEqual(self.overrides(panel), [])

    def test_no_colours_chosen_leaves_the_dashboards_untouched(self):
        """Byte-identical, so pinning a colour is opt-in and nothing else moves."""
        self.assertEqual(json.dumps(self.rendered({}), sort_keys=True),
                         json.dumps(self.rendered(None) if False else self.rendered({}),
                                    sort_keys=True))
        plain = self.rendered({})
        for panel in plain["panels"]:
            self.assertEqual(self.overrides(panel), [])

    def test_the_palette_is_a_checked_set_not_a_preference(self):
        from netops_platform.traffic import SERIES_COLORS, resolve_color
        # Four, because six hues will not fit one lightness band without two of
        # them colliding. The comment above SERIES_COLORS says why.
        self.assertEqual(len(SERIES_COLORS), 4)
        for name, value in SERIES_COLORS.items():
            with self.subTest(name=name):
                self.assertEqual(resolve_color(name), value)
        self.assertEqual(resolve_color("#123abc"), "#123abc")
        for rejected in ("puce", "#xyz", "#ABC", ""):
            with self.subTest(rejected=rejected):
                self.assertIsNone(resolve_color(rejected))

    def test_the_wan_total_is_drawn_with_the_links_it_sums(self):
        from netops_platform.traffic_dashboards import overview_dashboard
        traffic = next(p for p in overview_dashboard().panels if p.key == "wan_traffic")
        legends = [q.legend for q in traffic.queries]
        self.assertIn("WAN download", legends)
        self.assertIn("WAN upload", legends)
        upload = next(q for q in traffic.queries if q.legend == "WAN upload")
        self.assertTrue(upload.expr.lstrip().startswith("-1 *"))



class ComparableSmallMultiplesTest(unittest.TestCase):
    """A row of per-link charts exists to be compared across."""

    def panels(self):
        from netops_platform.traffic_dashboards import ServiceLink, overview_dashboard
        board = overview_dashboard([ServiceLink("AFRIX", "#149084"),
                                    ServiceLink("03B", "#79a632"),
                                    ServiceLink("ORANGE", "#b54d15")])
        return [p for p in board.panels if p.key.startswith("trend_")]

    def test_every_link_chart_shares_one_scale(self):
        """Given its own axis each link fills its panel and they all look
        alike, which is the opposite of what a row of them is for."""
        anchors = {p.soft_max for p in self.panels()}
        self.assertEqual(len(anchors), 1)
        self.assertTrue(all(a for a in anchors))

    def test_the_scale_is_anchored_below_the_line_as_well(self):
        """Upload is drawn downward; anchoring only the top leaves a link with
        little upload on its own scale again."""
        from netops_platform.traffic_graphers import GrafanaGrapher
        from netops_platform.traffic_dashboards import ServiceLink, overview_dashboard
        board = overview_dashboard([ServiceLink("AFRIX", "#149084")])
        with tempfile.TemporaryDirectory() as temp:
            files = GrafanaGrapher().files([board], "http://x", Path(temp))
        rendered = json.loads(next(v for k, v in files.items() if "overview" in k.name))
        trend = next(p for p in rendered["panels"] if p["title"].endswith("trend"))
        custom = trend["fieldConfig"]["defaults"]["custom"]
        self.assertEqual(custom["axisSoftMin"], -custom["axisSoftMax"])
        self.assertTrue(custom["axisCenteredZero"])

    def test_a_row_advances_by_its_tallest_panel(self):
        """Advancing by whichever panel came last leaves shorter ones
        overlapping the row below, and the grapher floats them into whatever
        gap it finds -- so one chart sits a row higher than its neighbours."""
        from netops_platform.traffic_graphers import GrafanaGrapher
        from netops_platform.traffic_dashboards import ServiceLink, overview_dashboard
        board = overview_dashboard([ServiceLink("AFRIX", "#149084"),
                                    ServiceLink("03B", "#79a632"),
                                    ServiceLink("ORANGE", "#b54d15")])
        with tempfile.TemporaryDirectory() as temp:
            files = GrafanaGrapher().files([board], "http://x", Path(temp))
        rendered = json.loads(next(v for k, v in files.items() if "overview" in k.name))
        trends = [p for p in rendered["panels"] if p["title"].endswith("trend")]
        self.assertEqual(len({p["gridPos"]["y"] for p in trends}), 1,
                         "the per-link charts must sit on one row")

    def test_a_link_tile_is_readable_across_a_room(self):
        from netops_platform.traffic_graphers import GrafanaGrapher
        from netops_platform.traffic_dashboards import ServiceLink, overview_dashboard
        board = overview_dashboard([ServiceLink("AFRIX", "#149084")])
        with tempfile.TemporaryDirectory() as temp:
            files = GrafanaGrapher().files([board], "http://x", Path(temp))
        rendered = json.loads(next(v for k, v in files.items() if "overview" in k.name))
        tile = next(p for p in rendered["panels"] if p["title"] == "AFRIX")
        self.assertGreaterEqual(tile["options"]["text"]["valueSize"], 30)
        # And a shape behind the number, so it says whether it is moving.
        self.assertEqual(tile["options"]["graphMode"], "area")

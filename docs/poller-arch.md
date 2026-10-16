# Setting up a poller by hand (Arch Linux)

A poller exists because SNMP and ICMP have to originate from the monitored
network. It runs a stock netrune install in its own profile and does one thing:
collect. It stores nothing long-term, serves nothing, and draws nothing. Your
laptop reaches it over SSH, pulls the readings, and keeps them.

That means **nothing new listens on the management network**. SSH was already
the way in, and the pull rides it.

`scripts/poller-install.sh` does all of this in one go and is safe to run twice.
If you cannot run a script, every command it would run is below, in order, with
what it is for. Nothing here is netrune-specific magic — it is packages, a
virtualenv, and two systemd user units.

Commands marked **`poller`** run on the poller. Commands marked **`laptop`** run
on your machine.

---

## The short way

Three facts differ between two installs: the SNMP community, what the machine is
for, and what it should watch. Everything else is mechanism, and one command
does it:

```bash
sudo pacman -S --needed python net-snmp iputils openssh
python3 -m venv ~/.local/share/netrune-poller/venv
~/.local/share/netrune-poller/venv/bin/pip install ~/netrune-*.whl
ln -sf ~/.local/share/netrune-poller/venv/bin/netrune ~/.local/bin/netrune

netrune setup poller --community YOUR_COMMUNITY \
    --collector-id site-a-poller \
    --watch 198.51.100.11:Gi1/0/16
```

That creates the profile, sets the identity, writes the community where the SNMP
helpers read it, generates and starts the collector, starts watching, and tells
you whether it will survive a reboot. It prints a step list; anything not `ok` is
a thing left to do, and the only one it cannot do for you is:

```bash
sudo loginctl enable-linger "$USER"
```

Add `--dry-run` to see what it would do first. Everything below is the same
install written out step by step, for when something goes wrong or you would
rather not hand a script your community.

---

## 1. Packages · `poller`

```bash
sudo pacman -S --needed python net-snmp iputils openssh
```

| Package | Why |
|---|---|
| `python` | netrune itself, and `venv` |
| `net-snmp` | `snmpget` and `snmpwalk`, which the collector shells out to |
| `iputils` | `ping`, for ICMP watches |
| `openssh` | how the laptop reaches this machine |

Confirm the three binaries the collector cannot work without:

```bash
command -v snmpget snmpwalk ping
```

If any is missing, stop here — everything below will install cleanly and then
collect nothing.

## 2. SSH · `poller`

```bash
sudo systemctl enable --now sshd
```

On Arch the unit is `sshd`, not `ssh`. Enabling it now means it also comes back
after a reboot.

## 3. netrune in a virtualenv · `poller`

Copy the wheel across first — from your laptop:

```bash
# laptop
cd /path/to/Netops
python3 -m pip wheel --no-deps -w dist .
scp dist/netrune-*.whl <you>@<poller>:~/
```

`pip wheel` rather than `python3 -m build`: both drive the same setuptools
backend, but `build` is a separate package that is often not installed, and pip
already is. If you have it, `python3 -m build --wheel` produces the same file.

Then on the poller:

```bash
python3 -m venv ~/.local/share/netrune-poller/venv
~/.local/share/netrune-poller/venv/bin/pip install --upgrade pip
~/.local/share/netrune-poller/venv/bin/pip install ~/netrune-*.whl
mkdir -p ~/.local/bin
ln -sf ~/.local/share/netrune-poller/venv/bin/netrune ~/.local/bin/netrune
```

Check `~/.local/bin` is on your `PATH`:

```bash
command -v netrune && netrune --version
```

A virtualenv rather than `pacman -S` or `pip install --user`: the poller's
netrune is upgraded on its own schedule and must not be entangled with anything
else Python on the machine.

## 4. Profile and identity · `poller`

```bash
netrune profile create poller
netrune profile use poller
netrune --profile poller config set traffic_collector_id site-a-poller
netrune --profile poller config set traffic_retention_days 365
netrune --profile poller db migrate
```

**The collector id matters.** It is stamped on every reading and is what keeps
this machine's measurements distinguishable from the laptop's after they are
merged. A pull refuses outright if the two ids match, because two collectors
called the same thing produce one series that is neither.

Retention is a soft ceiling on how long the poller keeps readings. It is the
buffer between pulls, so it should comfortably outlast the longest gap you
expect — a year costs very little disk at these sample rates.

## 5. SNMP credentials · `poller`

The poller reads the switches, so it needs the community. Netrune reads it from
the profile's `.env`:

```bash
install -m 700 -d ~/.config/netrune/profiles/poller
umask 077
cat > ~/.config/netrune/profiles/poller/.env <<'EOF'
communities="YOUR_COMMUNITY"
snmp_version="v2c"
EOF
```

`snmp_version="v2c"` is stated rather than discovered. Where v3 is blocked by an
ACL, leaving it unset makes every first contact with a device pay a v3 timeout
before falling back.

Confirm it works before going further:

```bash
snmpget -v2c -c YOUR_COMMUNITY -Oqv <switch-address> sysName.0
```

**This is the only credential a poller needs.** It does not need subnets, an
inventory scan, ingest channels, or SSH credentials to the switches: those
belong to the machine that explores and configures the estate, and a poller does
neither. It reads counters over SNMP and answers SSH so the laptop can pull. If
something asks you for more than this, it is a bug -- say so.

## 6. The collector unit · `poller`

```bash
netrune --profile poller traffic stack init --role collector
netrune --profile poller traffic stack up
```

`--role collector` generates the collector and a nightly prune timer, and
nothing else — no exposition, no VictoriaMetrics, no dashboards. What it wrote:

```bash
ls ~/.local/state/netrune/profiles/poller/metrics-stack/systemd/
# netrune-collector.service  netrune-metrics.target
# netrune-prune.service      netrune-prune.timer
```

`stack up` copies those into `~/.config/systemd/user/`, reloads, and enables
them. By hand that is:

```bash
cp ~/.local/state/netrune/profiles/poller/metrics-stack/systemd/* ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now netrune-metrics.target netrune-collector.service netrune-prune.timer
```

## 7. Linger · `poller`

```bash
sudo loginctl enable-linger "$USER"
```

**This is the step that decides whether the poller actually works.**

`systemd --user` units live in a user manager that starts at login and stops
when your last session closes. A poller has no session — nobody logs in after a
reboot. Without linger the units are enabled, every file on disk looks correct,
`systemctl --user is-enabled` says `enabled`, and they simply never run.

The difference is invisible until the machine reboots unattended and the
readings stop. Verify:

```bash
loginctl show-user "$USER" -p Linger --value    # must print: yes
```

## 8. Check it · `poller`

```bash
netrune --profile poller traffic stack status
netrune --profile poller traffic verify
```

`verify` on a collector reports `collector only` and stops there. That is
correct: there is no exposition, storage, or dashboard on this machine to check.

## 9a. Pushing straight into storage · both

The tidiest arrangement where the poller can reach the laptop but not the other
way round. The poller sends its readings to the laptop's storage on a timer;
they arrive as the counters they are, carrying the poller's collector id, and
every dashboard reads them unchanged.

```bash
# laptop: storage binds to loopback until told otherwise
netrune setup local --community YOUR_COMMUNITY --accept-push --confirm

# poller
netrune setup poller --community YOUR_COMMUNITY \
    --push-to http://<laptop-address>:8428
```

`--accept-push` is separate from `--publish` on purpose. Publishing dashboards
is read-only exposure; accepting a push lets anything that can reach that
address write readings into the store, and there is no authentication in front
of it. Put it on a management network or nothing.

Note what this replaces. `traffic pull` merges a poller's readings into the
laptop's database, where `traffic show` and `traffic report` read them -- but
**not** into storage, because the exposition deliberately publishes only what
this collector owns. Republishing a poller's counters under the laptop's own
scrape would hold them still between pulls, and a counter held still has a rate
of zero, which reads as a quiet link rather than as one nobody is measuring. So
if the readings need to appear on the dashboards, they have to reach storage as
themselves: push does that, pull does not.

### Coming back after being offline

The poller keeps polling whether or not anything is listening. When storage
comes back, the next push sends **what was missed**, not just what is true now:
each reading carries the time it was actually taken, so the outage is drawn as
the traffic that happened rather than as a hole followed by a vertical wall.

Nothing to configure. `traffic push` remembers where it got to and resumes from
there; the timer means a laptop switched on at nine has the night filled in
within a minute. `--since 24h` forces a wider replay if you need one.

The replay comes from a log the collector keeps of its own raw counters, at one
reading a minute regardless of how often it polls -- a rate is derived over
minutes, so logging every ten-second poll would multiply rows for resolution
nothing reads. It is kept for seven days by default
(`traffic_counter_log_retention_days`), which is a catch-up window rather than a
history: the samples themselves are kept for a year.

## 9b. If neither machine can reach the other · both

SSH is the tidiest way to fetch readings and needs nothing standing between the
two machines, but plenty of networks only permit it from specific subnets. That
is a routing policy, not a reason to be unable to read your own data.

An export is a file. Anything that can move a file will do -- a share both can
see, a USB stick, an allowed rsync, whatever already works:

```bash
# poller, on a timer or by hand
netrune --profile poller traffic export --since 24h > /srv/share/poller.jsonl

# laptop, whenever the file is reachable
netrune traffic pull --file /srv/share/poller.jsonl
```

Merging is idempotent, so carrying the same file across twice adds nothing and
overlapping windows cost only the time to read them. `--file -` reads standard
input, so any pipe works too. The readings still carry the poller's collector id
and stay owned by it, exactly as an SSH pull would leave them.

Before falling back to this, check whether *any* port between the two is
permitted. `sshd` is not obliged to listen on 22:

```bash
# poller: /etc/ssh/sshd_config
Port 2222
# laptop
netrune traffic remote add site-a-poller --host <address> --ssh-user <user> \
    --ssh-port 2222 --profile-name poller
```

## 9. Register it · `laptop`

```bash
ssh-copy-id <poller-user>@<poller-address>
netrune traffic remote add site-a-poller \
    --host <poller-address> --ssh-user <poller-user> --profile-name poller
```

## 10. Give it work, and pull · `laptop`

```bash
netrune traffic remote site-a-poller interfaces 198.51.100.11
netrune traffic remote site-a-poller watch 198.51.100.11 Gi1/0/16 --interval 30
netrune traffic pull --remote site-a-poller
netrune traffic list
```

Name the switch by **address**, not by hostname. The command is forwarded to the
poller verbatim, and the poller has no inventory to look a name up in -- by
design. It reads the switch's own name over SNMP and labels the watch with it,
so the address is only how you say which switch, never how it is displayed.

Watches created through `remote` belong to the poller: they carry its collector
id as their owner, so your laptop never tries to poll a switch only the poller
can reach. Pulling is idempotent -- a repeated pull merges nothing twice, so it
is safe to retry after a dropped connection.

Watches created through `remote` belong to the poller: they carry its collector
id as their owner, so your laptop never tries to poll a switch only the poller
can reach. Pulling is idempotent — a repeated pull merges nothing twice, so it
is safe to retry after a dropped connection.

---

## Confirming it survives a reboot

The one failure worth testing, because it is silent:

```bash
# poller
sudo reboot
```

Wait a minute, then from the laptop:

```bash
netrune traffic pull --remote site-a-poller
netrune traffic list
```

If the sample count went up, linger is doing its job. If it did not, go back to
step 7.

## When something is wrong

```bash
systemctl --user status netrune-collector.service
journalctl --user -u netrune-collector.service -n 50
netrune --profile poller traffic poll          # one round, in the foreground
```

| Symptom | Usually |
|---|---|
| It asks for subnets, a scan, or SSH credentials | A bug. A poller needs a community and nothing else |
| SSH to the poller is refused or times out | Policy, not configuration. Try another port, or hand the export over as a file -- step 9a |
| Units enabled, nothing running after reboot | Linger is off — step 7 |
| `no SNMP credentials are configured` | No `.env`, or the wrong profile — step 5 |
| SNMP returns no interface list | Community is wrong, or this host is not in the switch's SNMP ACL |
| Pull refuses: "the remote calls itself…" | Poller and laptop share a collector id — step 4 |
| `snmpget: command not found` in the journal | `net-snmp` missing — step 1 |

## Both at once

Push and pull are not alternatives. Configure either, or both:

```bash
netrune setup poller --community <c> \
    --push-to http://<laptop>:8428 \
    --export-to /srv/share/poller.jsonl
```

Push puts the readings on the dashboards. The export file is a record that
survives the laptop being rebuilt, and the way in if the push path ever closes.
Merging is idempotent, so carrying the same readings by both routes costs
nothing.

## Upgrading

```bash
# laptop
python3 -m pip wheel --no-deps -w dist .
scp dist/netrune-*.whl <you>@<poller>:~/
# poller
~/.local/share/netrune-poller/venv/bin/pip install --upgrade --force-reinstall ~/netrune-*.whl
netrune --profile poller db migrate
netrune --profile poller traffic stack init --role collector
netrune --profile poller traffic stack restart
```

Nothing in that sequence touches your data. The wheel replaces code only: the
profile (identity, community, retention, push and export settings) lives in
`~/.config/netrune/profiles/<name>/`, and the readings live in
`~/.local/state/netrune/profiles/<name>/`. `db migrate` adds whatever the new
version needs without discarding rows, and `stack init` regenerates units from
the same settings. Watches, names, colours, subscriptions and collected history
all carry across.

If you want a copy first, the whole of it is two directories -- `cp -a` them
somewhere before you start.

`--force-reinstall` matters, and so does `stack restart`.

The version string does not change between development builds, so
`pip install --upgrade` compares the new wheel against the installed one, finds
the same version, and does nothing at all -- reporting success while leaving the
old code in place. `--force-reinstall` replaces it regardless.

`stack up` will not restart a service that is already running, so even after a
successful reinstall the collector keeps executing the old code until something
restarts it.

If you are not sure which you are running, the error messages are the tell: run
a command you know changed. `netrune traffic watch <address> <port>` on a poller
with no inventory should accept the address; if it says the address "did not
resolve to one device", the reinstall did not take.

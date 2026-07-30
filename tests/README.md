# tests

```
./scripts/test            # or:  .venv/bin/python -m unittest discover -s tests -t .
```

550 Tests, rund 7,5 Sekunden (die Passwort-Tests warten auf echte Kindprozesse). Keine neuen Abhängigkeiten: `unittest` aus
der Standardbibliothek, weil im `.venv` kein Test-Runner liegt und einer die
Offline-Zusage aus `pyproject.toml` brechen würde (jedes Wheel muss
`py3-none-any` bleiben). Nichts hier fasst SSH, vCenter oder einen Cluster an.

## Warum genau diese Prüfungen

Sie existierten alle schon als Wissen, bevor sie als Code existierten — jede ist
ein Defekt aus dem Review vom 28./29. Juli (`docs/08-review-2026-07-28.md`).
Zwei Review-Runden fanden zehn Defekte *in den Fixes selbst*, zweimal nach dem
Muster **„an einer Stelle repariert, an den anderen nicht"**. Genau das fängt
eine Suite und ein erneutes Lesen nicht.

| Datei | Sichert ab |
|---|---|
| `test_redact.py` | A15 — die drei geschlossenen Lecks **und** die drei Bewahrungen. Zuviel maskieren ist ein eigener Fehlschlag: ein Access-Dienst heißt `token`, und `"token": "READY"` zu schlucken macht den Readiness-Bericht blind. |
| `test_collect_compare.py` | B8 — ein Wert, den der Knoten **nicht** meldet, ist ein Problem, kein Bestehen; `access` darf nicht auf `access2` passen. |
| `test_context_logs.py` | A13 — `last_segment` liefert nur den neuesten Lauf, damit nie ein abgelaufener Admin-Reset-Link als aktueller erscheint. B3 — `probe_alive` trennt „der Prozess ist weg" von „wir konnten nicht fragen". |
| `test_health.py` | A2/A9 — `include_services=False` verengt die Frage von Phase 60, ohne sie zu schwächen; eine unlesbare Antwort ist eine eigene Diagnose, nicht zwanzig fehlende Dienste. |
| `test_p70_acceptance.py` | A7/A8 — Blocker tragen ihre **Art**, damit `missing → not_ready` als der Fortschritt gelesen wird, der es ist. |
| `test_validate.py` | A11 — `nfs_path` mit führendem Doppelpunkt, auf dem Feld-Pfad **und** auf dem Datei-Pfad. |
| `test_call_sites.py` | A2/A14 an der **Aufrufstelle**: dass Phase 60 `include_services=False` tatsächlich benutzt, und dass `report_log` tatsächlich redigiert. |
| `test_kill_patterns.py` | B4 — was aXs als root erschießt, und was bewusst **nicht** verengt wurde. Hält auch fest, was an B4 offen bleibt. |
| `test_write_file.py` | B2 — Dateiinhalte über stdin statt über die Kommandozeile, und der Fallback nur bei echtem Auth-Fehler. Führt das erzeugte Kommando von `/bin/sh` aus, statt es als String zu betrachten. |
| `test_power_states.py` | Phase 10s Done-Probe scoped auf Datacenter UND Ordner. Eine gleichnamige Alt-VM in einem anderen Ordner meldete die Phase sonst als fertig, der Knoten wurde nie gebaut. Prueft die erzeugten Query-Parameter und die Aufrufstelle, nicht nur den Helfer. |
| `test_cert_check.py` | `certs.validate_cluster`, der Zertifikats-Cross-Check des Wizards (vier Aufrufstellen, vorher ohne Tests). Der CN zählt nur ohne SAN — sonst wäre der Check freundlicher als jeder Browser; plus die no-SAN- und Ablaufwarnung. |
| `test_hostile_config.py` | Eine handeditierte `config.yml` darf nichts zum Absturz bringen — **und nicht an einer Stelle von fünf**. Zehn plausible Fehlformen des `logging`-Blocks gegen elf Aufrufstellen, als Tabelle: eine Tabelle lässt sich nicht in drei von fünf Fällen reparieren. |
| `test_pending_rollout.py` | B1 Vollentwurf — aus erkannter Drift wird eine ausgerollte. Marker vor dem Patch, Phase 60 sieht ihn, Reprobe in der Engine. Enthält eine Klasse, die die generierten Shell-Kommandos durch echte `/bin/sh` gegen echte Dateien laufen lässt. |
| `test_password_expiry.py` | B10 — die 60-Tage-Frist des configuser-Passworts wird ausgewertet, nicht nur angezeigt. Drei Zustände, inklusive „konnte nicht feststellen". |
| `test_lb_dns.py` | B6 — DNS wird vom Bootstrap gefragt, nicht vom Mac. Trennt „nicht erreichbar" von „Login abgelehnt" und vermeidet die IPv6-Falle von `getent hosts`. |
| `test_nfscheck_where.py` | B8 — das Backup-Ziel wird dort geprüft, wo es wirklich gemountet wird. Und „konnte nicht fragen" wird nicht als „geht nicht" gemeldet. |
| `test_password_prompts.py` | Der Passwort-Pfad darf nie ewig warten — zweite Abfrage heißt abgelehnt, und es gibt ein Schweige-Limit. Im Feld gefunden. |
| `test_healthcheck_noise.py` | Rauschen um wsos Antwort herum darf sie nicht verstecken — und „unlesbar" muss sagen, *was* kam. Am echten Cluster gefunden. |
| `test_disk_space.py` | B10 — ein 13,5-GB-Upload, der nicht landen kann, wird vorher verweigert; die Schätzung für alles danach warnt nur. |
| `test_ovftool_children.py` | B9 — kein ovftool überlebt das Werkzeug, das es gestartet hat. Startet echte Kindprozesse, weil es um echte Prozesslebensdauer geht. |
| `test_p80_tenant.py` | B5 — der Mandant wird am Cluster belegt, nicht am Loadbalancer. Führt die Log-Abfrage von `/bin/sh` aus. |
| `test_warning_delivery.py` | Dass `Probe.warning` von **jeder** Stelle ausgegeben wird, die eine Phase als erledigt markiert. Strukturell, und sagt das auch. |
| `test_config_write.py` | B10 — `config.yml` wird ganz geschrieben oder gar nicht. Bricht den Schreibvorgang **während** der Bytes ab, nicht davor. |
| `test_profile_drift.py` | B1 — der semantische Vergleich: blind für Formatierung und wsos eigene Schlüssel, blind für Secrets, und sicher gegen handeditierte Dateien. |

Warum `test_call_sites.py` separat: Ein Test der geteilten Funktion beweist die
Funktion, nicht dass der Code, der kaputt war, sie auch benutzt. Beide
Regressionen — `include_services=True` in Phase 60, `redact()` aus `report_log`
entfernt — überleben eine Suite, die nur `health.py` und `context.redact` prüft.

`test_validate.py` prüft zuerst, dass die eigene Basis-Config sauber validiert.
„Diese Eingabe wird abgelehnt" heißt nichts, wenn alles abgelehnt wird.

## Mutationsgeprüft

Nicht behauptet, sondern nachgemessen. Jede dieser Rückdrehungen in
`src/ws1access` lässt die Suite rot werden (danach revertiert):

| Rückdrehung | Fängt |
|---|---|
| `include_services=True` in `p60_platform` | `test_call_sites` (2) |
| `redact()` aus `context.report_log` | `test_call_sites` (2) |
| `[:400]` am `detail` in `p70_services` | `test_p70_acceptance` (1) |
| `sorted()` in `parse_readiness` + `p70` | `test_p70_acceptance` (1) |
| `startswith` zurück in `collect.compare` | `test_collect_compare` (1) |
| Blocker-Tupel auf nackte Namen kollabiert | `test_p70_acceptance` (4) |
| `_CP_PREFIX` aus `_SECRET_COLON` entfernt | `test_redact` + `test_p70_acceptance` (2) |
| `_VI_CRED` wieder ohne `@` im Benutzer | `test_redact` (1) |
| `_VI_CRED`-Passwort ohne `/`-Stopp | `test_redact` (1) |
| `[\s{,]*` zurück zu `\s*[{,]?\s*` | `test_redact` (2, in 5,8 s statt Hänger) |
| `_WRAPPER`/`_WORKER` wieder breit | `test_kill_patterns` (1 bzw. 2) |
| nur `_KILL` verengt, `_ALIVE` nicht | `test_kill_patterns` (2) |
| Selbstmatch-Klammer `[w]`/`[p]` entfernt | `test_kill_patterns` (1) |
| `\|\|` → `&&` in `_ALIVE` | `test_kill_patterns` (1) |
| Secrets exakt statt per Substring | `test_profile_drift` (1) |
| verschachtelte dicts nicht verworfen | `test_profile_drift` (1) |
| `_scalar` ohne int-Normalisierung | `test_profile_drift` (1) |
| `_flatten_logging` ohne Shape-Wachen | `test_profile_drift` (2) |
| Drift-Warnung zurück in `detail` | `test_call_sites` (5) |
| `is_done` ruft den Vergleich nicht auf | `test_call_sites` (2) |
| Inhalt zurück in argv | `test_write_file` (7) |
| `input=stdin` aus `run_with_key` | `test_write_file` (1) |
| Fallback-Gate nicht auf Auth beschränkt | `test_write_file` (4) |
| Gate nur auf rc 255 statt auf den Grund | `test_write_file` (1) |
| `trap` wieder doppelt gequotet | `test_write_file` (3) |
| Größenprüfung vor `mv` entfernt | `test_write_file` (2) |
| `umask 077` entfernt | `test_write_file` (2) |
| Passwort-Fallback ohne Temp-Datei | `test_write_file` (1) |
| `config.yml` zurück auf `write_text` | `test_config_write` (9) |
| Tempdatei in `/tmp` statt Zielordner | `test_config_write` (1) |
| `fsync`/`flush` entfernt | `test_config_write` (1 bzw. 1) |
| `except Exception` statt `BaseException` | `test_config_write` (1) |
| fd-Leck bei fehlgeschlagenem `fdopen` | `test_config_write` (1) |
| Phase 80 zurück auf reines HTTP 200 | `test_p80_tenant` (10) |
| Log nur letztes Segment statt ganz | `test_p80_tenant` (1) |
| Negations-Wache im `grep` entfernt | `test_p80_tenant` (1) |
| Warntext behauptet wieder Existenz | `test_p80_tenant` (1) |
| Warnung im TUI-Resume verworfen | `test_warning_delivery` (2) |
| Warnung nach dem Lauf verworfen (TUI/CLI) | `test_warning_delivery` (2 bzw. 1) |
| `atexit`-Registrierung entfernt | `test_ovftool_children` (1) |
| Kind gar nicht registriert | `test_ovftool_children` (1) |
| laufendes Kind nur abgemeldet, nicht gestoppt | `test_ovftool_children` (1) |
| SIGKILL ohne vorheriges SIGTERM | `test_ovftool_children` (1) |
| SIGKILL-Eskalation entfernt | `test_ovftool_children` (1) |
| Ausgabe-Pipe nicht geschlossen | `test_ovftool_children` (1) |
| Plattenplatz-Check aus `stage_bundle` entfernt | `test_disk_space` (1) |
| „unbekannt" zählt als „genug" | `test_disk_space` (2) |
| nur Staging geprüft, nicht das Cluster-Verzeichnis | `test_disk_space` (2) |
| `df -k` statt `df -Pk` | `test_disk_space` (1) |
| Prüfung vor das `mkdir` verschoben | `test_disk_space` (1) |
| letzte Zeile statt Rückwärtssuche im `df` | `test_disk_space` (1) |
| zurück zu `json.loads` ab erster `{` | `test_healthcheck_noise` (5) |
| nur die erste `{` probiert | `test_healthcheck_noise` (1) |
| Trunkierungs-Wache entfernt | `test_healthcheck_noise` (7) |
| `RecursionError` nicht gefangen | `test_healthcheck_noise` (1) |
| ssh-Exit-Code aus der Meldung | `test_healthcheck_noise` (2) |
| p60/p70/`_confirm_health` erklären nicht | `test_healthcheck_noise` (je 1) |
| `redact` aus der Meldung entfernt | `test_healthcheck_noise` (2) |
| nur eine Abfrage beantworten, dann schweigen | `test_password_prompts` (3) |
| zweite Abfrage beantworten statt abbrechen | `test_password_prompts` (3) |
| Auth-Fenster entfernt | `test_password_prompts` (1) |
| Schweige-Limit → Gesamtlimit | `test_password_prompts` (1) |
| Limit ganz entfernt | `test_password_prompts` (1) |
| Sentinel-Wrap (`printf`) entfernt (`remote = command`) | `test_password_prompts` (1) |
| authed-Skip aus der Leseschleife entfernt | `test_password_prompts` (1) |
| Output-Split am Sentinel deaktiviert (globaler Filter) | `test_password_prompts` (2) |
| Sentinel-Tail akkumuliert nicht (`hay = data`) | `test_password_prompts` (2) |
| nur den Bootstrap prüfen | `test_nfscheck_where` (5) |
| Bootstrap aus der Liste | `test_nfscheck_where` (3) |
| Root-Prüfung entfernt | `test_nfscheck_where` (3) |
| „nicht getestet" als Fehlschlag zählen | `test_nfscheck_where` (3) |
| ACL-Hinweis ohne Stufen-Prüfung | `test_nfscheck_where` (1) |
| Maschinenname fest auf „bootstrap" | `test_nfscheck_where` (1) |
| DR-Satz auch bei reinem Bootstrap-Fehler | `test_nfscheck_where` (1) |
| Advisory-Antwort entscheidet `done` | `test_lb_dns` (3) |
| TCP-Vorprüfung entfernt | `test_lb_dns` (4) |
| echtes „not found" wird zu „konnte nicht fragen" | `test_lb_dns` (1) |
| `run()` wartet nicht, bricht sofort ab | `test_lb_dns` (1+2) |
| Auth-Fehler wird zu SSH-Fehler pauschalisiert | `test_lb_dns` (1) |
| falscher Host gefragt | `test_lb_dns` (1) |
| `getent hosts` statt `ahostsv4` (IPv6-Falle zurück) | `test_lb_dns` (2) |
| Auth-Ablehnung wieder als „nicht erreichbar" gemeldet | `test_lb_dns` (3) |
| Quoting der FQDN entfernt | `test_lb_dns` (1) |
| Drift macht Phase 50 nicht mehr rot | `test_pending_rollout`, `test_call_sites` (2) |
| Marker nach statt vor dem Patch geschrieben | `test_pending_rollout` (2) |
| Marker gar nicht gesetzt | `test_pending_rollout` (2) |
| Read-back-Verifikation entfernt | `test_pending_rollout` (1) |
| `logging` gilt als nachrüstbar | `test_pending_rollout`, `test_call_sites` (3) |
| Phase 60 ignoriert den Marker | `test_pending_rollout` (2) |
| Marker nach dem Rollout nicht gelöscht | `test_pending_rollout` (2) |
| `AXS_PENDING_END`/`_NONE` vertauscht | `test_pending_rollout` (7) |
| unlesbarer Marker liest sich als „clean" | `test_pending_rollout` (1) |
| `rm -f` statt `rm -rf` (Verzeichnis bleibt) | `test_pending_rollout` (4) |
| Marker global statt pro Cluster | `test_pending_rollout` u. a. (11) |
| `cd`-Wrapper wieder aktiv (schluckt die Antwort) | `test_pending_rollout` (je 1) |
| Abhängige Phasen nicht als veraltet markiert | `test_pending_rollout` (2) |
| veraltete Phasen gelaufen statt neu geprüft | `test_pending_rollout` (1) |
| `dependents` nur direkt, nicht transitiv | `test_pending_rollout` (1) |
| rotes Urteil wieder aus `drift_keys` (entfernte Einstellung) | `test_pending_rollout` (1) |
| spätere Duplikat-Zeile nicht mehr überschrieben | `test_pending_rollout` (2) |
| kommentierte Duplikate mitgelöscht | `test_pending_rollout` (1) |
| Syslog-Index-Skew wieder eingebaut | `test_pending_rollout` (3) |
| Syslog-Eintrag ohne Mapping stürzt (3 Stellen) | `test_pending_rollout` (je 1) |
| Zertifikat-CN bedingungslos vertraut | `test_cert_check` (2) |
| no-SAN- / Ablaufwarnung nicht gezeigt | `test_cert_check` (je 1) |
| Ordner-Scoping in Phase 10 entfernt | `test_power_states` (3) |
| Phase 10 reicht den Ordner nicht durch | `test_power_states` (1) |
| fehlender Ordner sucht weiter statt leer | `test_power_states` (2) |
| Phase 10 run() scoped nicht auf den Ordner | `test_power_states` (1) |
| gleichnamige Ordner nicht als mehrdeutig erkannt | `test_power_states` (1) |
| raisender Reprobe nicht gefangen | `test_pending_rollout` (1) |
| Probe-Guard nur an einer von vier Stellen | `test_pending_rollout` (je 1) |
| unparsebares YAML wird doch geschrieben | `test_pending_rollout` (2) |
| `_set_scalar` fasst eingerückte Zeilen an (löscht verschachtelte Keys) | `test_hostile_config` (3) |
| Syslog-Container-Guard entfernt (`{host: x}` statt Liste) | `test_hostile_config` u. a. (162) |
| Syslog-Eintrags-Guard entfernt (String statt Mapping) | `test_hostile_config` u. a. (25) |
| `mapping()` lässt Nicht-Dicts durch (`logging: enabled`) | `test_hostile_config` u. a. (54) |
| Validator benennt Container-Fehlform nicht mehr | `test_hostile_config` (2–3) |
| Whitespace-Host akzeptiert / an wso geschrieben | `test_hostile_config` (je 1) |
| TUI liest gecrashte Probe wieder als „not done" | `test_pending_rollout` (1) |
| „unbekannt" wird zu „never" (still gesund) | `test_password_expiry` (2) |
| leerer Wert gilt als „never" | `test_password_expiry` (1) |
| `LC_ALL=C` von einem `chage`-Zweig entfernt | `test_password_expiry` (je 1) |
| „abgelaufen" nicht von „läuft ab" unterschieden | `test_password_expiry` (3) |
| Warnschwelle auf 0 (warnt nie vorher) | `test_password_expiry` (5) |
| Warnung nicht an `Probe` übergeben | `test_password_expiry` (2) |
| „konnte nicht feststellen" verschwiegen | `test_password_expiry` (1) |

## Zwei Lücken, beim Schreiben der Suite gefunden

Beide wurden zuerst als `expectedFailure` festgehalten — als scheiternde
Erwartung statt als Behauptung, das Fehlverhalten sei richtig. Beide sind
inzwischen behoben und stehen jetzt als normale Assertions in
`test_redact.py::TestRedactBehindAPrefix`.

1. **Secret hinter einem Log-Präfix.** Die weitere von beiden. Die
   Doppelpunkt-Regel verankert den Schlüssel am Zeilenanfang — mit Absicht,
   damit Prosa wie `could not read password: permission denied` ihren Grund
   behält. wsos `cp_logger` stellt aber jeder Zeile einen Zeitstempel voran.
   `p60_platform.py` gibt einen **rohen** `tail -n 40` von `control_plane.log`
   an einen `RemoteError`; `tui_deploy` schreibt das nach
   `clusters/<name>/deploy.log`. Eine präfixierte `vault_token:`-Zeile landete
   so **auf Platte**, nicht nur auf dem Schirm. Behoben, indem genau **eine
   gemessene** Präfixform erlaubt wird (`_CP_PREFIX`, dieselbe, die
   `clean_tail` schon strippt) — nicht „irgendwas vor dem Schlüssel", das
   würde das Prosa-Loch wieder aufreißen. Vier Tests halten beide Richtungen.

2. **`vi://`-URL mit unkodiertem `@` im Benutzer.** `administrator@vsphere.local`
   ist *das* Standard-vCenter-SSO-Konto. aXs' eigene Ziele waren nur zufällig
   gedeckt, weil `VCenter.locator` den Benutzer URL-kodiert; ein handgetipptes
   Ziel oder ein Hersteller-Fehlertail war es nicht. Behoben.

Der Review **dieser beiden Fixes** fand dann zwei Folgefehler in ihnen — dasselbe
Muster wie am Review-Tag, weshalb der Schritt überhaupt stattfindet:

- **Katastrophales Backtracking.** Der optionale Präfix landete vor
  `\s*[{,]?\s*` — zwei Whitespace-Läufe um ein optionales Zeichen. Die Engine
  probierte jede Aufteilung eines Space-Laufs zwischen ihnen. Gemessen: **1,66 s
  für einen `tail -n 40`**, dessen Zeilen Whitespace enthalten, gegen 0,002 s.
  `re.M` zahlt das pro Zeilenanfang. Das wäre auf dem UI-Thread gelandet, im
  Fehlerpfad — also genau dann, wenn der Operator hinschaut. Behoben durch
  **eine** Zeichenklasse `[\s{,]*`, die sich nicht aufteilen lässt.
- **Neuer Fehlalarm bei `vi://`.** Das Passwort durfte über `/` hinweg matchen,
  also fraß `vi://admin@vc.local:443/dc/host@cluster` Port und Pfad. Behoben,
  indem das Passwort bei `/` stoppt — so wie `ovftool._VI_CRED` es längst tat.

`TestRedactStaysLinear` pinnt das Laufzeitverhalten mit gemessenen Größen. Die
Kommentare dort nennen die Zahlen und auch die Grenze: bei einer *doppelten*
Rückdrehung würde der Test hängen statt zu scheitern.

### Eine bekannte äquivalente Mutation

`p50._apply_profile` prüft nach dem Schreiben nur die Keys, die es zu schreiben
versprochen hat (`apply_now`), nicht jede Abweichung. Ersetzt man das durch
„jede Abweichung", bleibt die Suite **grün** — und das ist korrekt so: die eine
Form, die diesen Unterschied erreichbar machte (ein Syslog-Eintrag ohne Host,
der die Indizes auf nur einer Vergleichsseite verschob), ist an der Quelle
behoben, und keine der neun geprüften feindlichen `logging`-Formen lässt danach
noch etwas übrig. Die Verengung bleibt trotzdem: der Vertrag ist „prüfe, was du
zugesagt hast", und ein Key, der künftig in den Vergleich aber nicht in den
Schreiber wanderte, würde die Phase sonst wieder dauerhaft rot machen. Hier
festgehalten, damit niemand sie später als Lücke missversteht.

### Zwei bewusst schwächere Prüfungen

`test_neither_page_drops_the_notes` (in `test_cert_check.py`) prüft **Quelltext**:
die beiden Render-Schleifen für die Zertifikats-Notes liegen in
Textual-Worker-Methoden, es gibt nichts Importierbares zum Aufrufen. Sie sichert
nur den vom Review benannten Defekt ab — eine Warnung auf einer der zwei Seiten
gezeigt, auf der anderen nicht. Die Urteilslogik selbst ist darüber
verhaltensgeprüft (`validate_cluster` direkt), nur das Rendern nicht.

### Eine weitere bewusst schwächere Prüfung

`test_the_tui_does_not_read_a_crashed_probe_as_not_done` prüft **Quelltext**,
nicht Verhalten. Beide Hälften des Fixes liegen in Closures innerhalb einer
Textual-Worker-Methode, es gibt also nichts Importierbares zum Aufrufen. Eine
Mutation, die die Prüfung aushebelt und den Text stehen lässt, würde sie
überleben — genau die Schwäche, die in derselben Änderung schon einmal
`(True, '')  # pending.clear(ctx)` durchgelassen hat. Die Entsprechungen auf dem
einfachen Pfad sind dagegen über echtes Verhalten geprüft. Hier benannt, damit
niemand sie für gleichwertig hält.

## Was diese Suite nicht abdeckt

Damit die Tabelle oben nicht mehr verspricht, als sie hält:

- **A4, die Stillstandserkennung.** Der verifizierte Kill (SIGTERM → SIGKILL →
  Todesprüfung) und das 20-Minuten-Fenster in `wait_while_running` haben keinen
  Test. Getestet ist nur `probe_alive`, das darunterliegt.
- **A7 zu zwei Dritteln.** Die Blocker-Art ist gepinnt; das Wartefenster und die
  Benennung des Verdächtigen in `_deploy_services` nicht — die Wiederholschleife
  selbst ist ungetestet.
- **Die `unknown`→raise-Wachen** in `start_detached_once` und `p70.run`.
- **`onboarding_info` in Phase 80**, die zweite Hälfte von A13.
- **Dass Bootstrap und die anderen fünf Knoten identisch auflösen.** Belegt ist
  nur: gleiches Subnetz, gleiche `network.dns`-Konfiguration. `docs/04` hält
  fest, dass der Bootstrap direkt gegen den Nameserver auflöst, die anderen
  Knoten über den `systemd-resolved`-Stub mit eigenem Cache — ein frisch
  angelegter DNS-Eintrag könnte auf dem Bootstrap schon sichtbar sein, im
  Stub-Cache der anderen Knoten noch nicht. Zeitlich begrenzt, aber real.
- **Die Access-Knoten beim NFS-Test.** Geprüft werden Bootstrap und die drei
  Platform-Knoten. `docs/08` C1 sagt aber „generisch jeder weitere Dienst" —
  trüge je ein Access-Dienst das NFS-Volume, wäre B8 dort wieder offen.
- **`node_root_run` selbst.** Die Attrappe ersetzt es; das echte
  `sudo -n bash -lc` mit dem gequoteten Probe-Skript ist ungetestet.
- **Warum die Antwort am 29.07. sporadisch unlesbar war.** Der Banner-Defekt
  ist bewiesen, erklärt aber nur den Schlüssel-Pfad; der Vorfall lief über das
  Pty, wo das Banner zuerst kommt. Die Ursache bleibt offen — die neue Meldung
  ist das Instrument, das sie beim nächsten Mal zeigt.
- **Wieviel Phase 40 wirklich braucht.** Die 26 GB stammen aus dem eigenen
  Fehlertext der Phase — und zwar aus dem Zweig für `wso configure`, nicht fürs
  Entpacken. Ob die Zahl das Archiv oder den Docker-Speicher einschließt, steht
  nirgends. Deshalb warnt dieser Teil nur, statt zu verweigern.
- **Was `atexit` nicht sieht.** B9 deckt den Exit-Knopf, Ctrl-C und ein
  normales Programmende. Nicht abgedeckt: SIGKILL, ein harter Absturz, und —
  weil es gedeckt *aussieht* — ein `kill <pid>` oder SIGHUP auf Python allein.
  Steht so im Code, ist aber nicht testbar.
- **Verzeichnis-`fsync` nach dem Umbenennen.** Nach einem Stromausfall kann das
  Umbenennen selbst verloren gehen und die alte Datei wieder auftauchen. Immer
  alt oder neu, nie halb — für den behobenen Defekt reicht das, eine
  Haltbarkeitslücke bleibt es trotzdem.
- **Dass eine Oberfläche die Warnung wirklich malt.** `test_warning_delivery.py`
  sichert strukturell, dass keine Stelle eine Phase als erledigt markiert, ohne
  `Probe.warning` weiterzureichen — das ist die Eigenschaft, die zweimal
  gebrochen ist. Ob das Textual-Widget den Text dann anzeigt, hängt an einem
  Terminal und einem Cluster und bleibt nachgelesen.
- **B4 zur Hälfte.** Die Handreparatur `wso services deploy -s <dienst>` wird
  nicht mehr über den *Wrapper* getroffen. Ob sie denselben
  `/scripts/deploy_services.py` startet — und damit über das *Worker*-Muster
  weiterhin getroffen wird — ist ungemessen; die Schwesterfrage für
  `cp deploy` steht als docs/08 D5 offen. `test_kill_patterns` hält den
  Zustand fest, statt ihn als behoben zu buchen.

Und die grundsätzliche Grenze: Jede entscheidende Erkenntnis des 28. Juli kam
aus Live-Inspektion — der Doppelpunkt aus einer Nomad-Job-Definition, das
`chown` aus einer Allocation-Fehlermeldung, das `mkdir` aus wsos eigenem
`cps.py`. Ein Test des eigenen Codes findet Widersprüche *innerhalb* von aXs;
er findet nie „aXs nimmt X an, der Cluster tut Y".

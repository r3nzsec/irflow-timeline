---
description: The column templates IRFlow Timeline uses to recognize every CSV that Hayabusa writes, their timestamp columns, Hayabusa's level colors and its timestamp formats.
---

# Hayabusa Templates

IRFlow Timeline recognizes every CSV that [Hayabusa](https://github.com/Yamato-Security/hayabusa) 4.3.1 writes: each `dfir-timeline` profile, and the `search`, `logon-summary`, `eid-metrics`, `computer-metrics`, `log-metrics` and `extract-base64` outputs. As with [Juntei Templates](/reference/juntei-templates), each output has a template listing its columns and, explicitly, which of them are timestamps.

When you open a Hayabusa CSV:

- The status bar shows the format, for example **Hayabusa standard** or **Hayabusa logon-summary (failed)**.
- **Only the template's timestamp columns are timestamps**, in any of Hayabusa's timestamp formats (below).
- **Timelines are colored by rule level**: white, green, yellow, orange and red rows.

## Level colors

Every `dfir-timeline` profile colors each row by its `Level`, with black text. The colors are the same in every color scheme:

| Level | Written as | Background | Text |
|---|---|---|---|
| emergency | `emer`, `emergency` | <span style="display:inline-block;width:0.9em;height:0.9em;border:1px solid #8888;border-radius:2px;vertical-align:middle;background:#ff0000"></span> `#ff0000` red | <span style="display:inline-block;width:0.9em;height:0.9em;border:1px solid #8888;border-radius:2px;vertical-align:middle;background:#000000"></span> `#000000` black |
| critical | `crit`, `critical` | <span style="display:inline-block;width:0.9em;height:0.9em;border:1px solid #8888;border-radius:2px;vertical-align:middle;background:#ff0000"></span> `#ff0000` red | <span style="display:inline-block;width:0.9em;height:0.9em;border:1px solid #8888;border-radius:2px;vertical-align:middle;background:#000000"></span> `#000000` black |
| high | `high` | <span style="display:inline-block;width:0.9em;height:0.9em;border:1px solid #8888;border-radius:2px;vertical-align:middle;background:#ffc100"></span> `#ffc100` orange | <span style="display:inline-block;width:0.9em;height:0.9em;border:1px solid #8888;border-radius:2px;vertical-align:middle;background:#000000"></span> `#000000` black |
| medium | `med`, `medium` | <span style="display:inline-block;width:0.9em;height:0.9em;border:1px solid #8888;border-radius:2px;vertical-align:middle;background:#ffff00"></span> `#ffff00` yellow | <span style="display:inline-block;width:0.9em;height:0.9em;border:1px solid #8888;border-radius:2px;vertical-align:middle;background:#000000"></span> `#000000` black |
| low | `low` | <span style="display:inline-block;width:0.9em;height:0.9em;border:1px solid #8888;border-radius:2px;vertical-align:middle;background:#00ff00"></span> `#00ff00` green | <span style="display:inline-block;width:0.9em;height:0.9em;border:1px solid #8888;border-radius:2px;vertical-align:middle;background:#000000"></span> `#000000` black |
| informational | `info`, `informational` | <span style="display:inline-block;width:0.9em;height:0.9em;border:1px solid #8888;border-radius:2px;vertical-align:middle;background:#ffffff"></span> `#ffffff` white | <span style="display:inline-block;width:0.9em;height:0.9em;border:1px solid #8888;border-radius:2px;vertical-align:middle;background:#000000"></span> `#000000` black |

The red, orange, yellow and green are the colors Hayabusa uses for these levels in its terminal output (`config/level_color.txt`). Both the abbreviated levels and the full names that `-b` (`--disable-abbreviations`) writes are colored. The colors are ordinary color rules, so you can edit or remove them in **Color Rules**. A CSV from a custom profile gets the same colors when it matches the **Hayabusa (Standard)** or **Hayabusa (Verbose)** [KAPE profile](/reference/kape-profiles#hayabusa-standard).

## Timestamp formats

Every time format option gives the same instants, so a timeline displays, sorts, filters by date and draws its histogram the same way in any format:

| Option | Example | Read as |
|---|---|---|
| default (local time) | `2017-08-31 04:13:38.198 +09:00` | 2017-08-30 19:13:38.198 UTC |
| `-U`, `--utc` | `2017-08-30 19:13:38.198 +00:00` | the same |
| `-Z`, `--timezone -06:00` | `2017-08-30 13:13:38.198 -06:00` | the same |
| `-O`, `--iso-8601` | `2017-08-30T19:13:38.198482Z` | the same |
| `--rfc-3339` | `2017-08-31 04:13:38.198482+09:00` | the same |
| `--rfc-2822` | `Thu, 31 Aug 2017 04:13:38 +09:00` | the same (whole seconds) |
| `--us-time` | `08-31-2017 04:13:38.198 AM +09:00` | the same; `PM` adds 12 hours |
| `--us-military-time` | `08-31-2017 04:13:38.198 +09:00` | the same |
| `--european-time` | `31-08-2017 04:13:38.198 +09:00` | the same: day first |

The US formats used to lose their UTC offset, fractional seconds and `PM`. The European format used to be read month first, which made `03-08-2017` (3 August) into 8 March.

**European dates:** `--european-time` and `--us-military-time` look alike, so IRFlow decides per column, over all its rows, when the file is imported. A column is read day first when some of its dates can only be day first (`31-08-2017`) and none can only be month first (`08-31-2017`). The decision applies to the grid, the Timestamp Converter, sorting, date-range filters and the histogram. If every date in a column has a day of 12 or less, the column can't be told apart and is read month first.

This applies to any timestamp column in any file, not only Hayabusa's.

## How a file is matched

A CSV is a template's output when its header row has every column of the template and no other column, in any order. `-G` (`--geo-ip`) adds columns, which the templates accept:

- **Timeline profiles:** `SrcASN`, `SrcCountry`, `SrcCity`, `TgtASN`, `TgtCountry` and `TgtCity`.
- **Logon summary:** `Source ASN`, `Source Country` and `Source City`.

Options that only change values, such as `-b`, `-M`, `-S`, `-R`, `-X`, `-s` or a time format, keep the template. A sorted CSV from `hayabusa sort-csv` keeps its profile's template. A CSV from a custom profile isn't matched; IRFlow then guesses timestamp columns from their names. Hayabusa's JSON and JSONL outputs aren't covered, because IRFlow opens the CSV outputs.

## Columns that are not timestamps

| Columns | Format | Why |
|---|---|---|
| `RuleCreationDate`, `RuleModifiedDate` | super-verbose | When the rule was written or changed, not when the event happened. |
| `timestamp_desc` | timesketch profiles | Always `hayabusa`. |
| `UpTime`, `Timezone` | computer-metrics | A duration (`0Y 0M 0d 14h 33m 32s`) and a time zone name. |

## Templates

| Format (status bar) | Written by | Timestamp columns | Level colors |
|---|---|---|---|
| Hayabusa minimal | `hayabusa dfir-timeline -p minimal` | `Timestamp` | Yes |
| Hayabusa standard | `hayabusa dfir-timeline -p standard` (the default profile) | `Timestamp` | Yes |
| Hayabusa verbose | `hayabusa dfir-timeline -p verbose` | `Timestamp` | Yes |
| Hayabusa all-field-info | `hayabusa dfir-timeline -p all-field-info` | `Timestamp` | Yes |
| Hayabusa all-field-info-verbose | `hayabusa dfir-timeline -p all-field-info-verbose` | `Timestamp` | Yes |
| Hayabusa super-verbose | `hayabusa dfir-timeline -p super-verbose` | `Timestamp` | Yes |
| Hayabusa timesketch-minimal | `hayabusa dfir-timeline -p timesketch-minimal` | `datetime` | Yes |
| Hayabusa timesketch-verbose | `hayabusa dfir-timeline -p timesketch-verbose` | `datetime` | Yes |
| Hayabusa search | `hayabusa search -o` | `Timestamp` | No |
| Hayabusa logon-summary (successful) | `hayabusa logon-summary -o <prefix>` → `<prefix>-successful.csv` | `First Logon`, `Last Logon` | No |
| Hayabusa logon-summary (failed) | `hayabusa logon-summary -o <prefix>` → `<prefix>-failed.csv` | `First Attempt`, `Last Attempt` | No |
| Hayabusa eid-metrics | `hayabusa eid-metrics -o` | none | No |
| Hayabusa computer-metrics | `hayabusa computer-metrics -o` | none | No |
| Hayabusa log-metrics | `hayabusa log-metrics -o` | `First Timestamp`, `Last Timestamp` | No |
| Hayabusa extract-base64 | `hayabusa extract-base64 -o` | `Timestamp` | No |

The templates are in [`electron/hayabusa-templates.json`](https://github.com/r3nzsec/irflow-timeline/blob/main/electron/hayabusa-templates.json).

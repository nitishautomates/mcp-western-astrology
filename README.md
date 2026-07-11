# Divine API - Western Astrology MCP Server

Official MCP server by Divine API for Western Astrology services. Exposes 57 tools covering natal charts, synastry, transits, composite charts, progressions, planetary returns, prenatal analysis, and advanced natal techniques, backed by the live Divine API (astroapi-4 and astroapi-8 hosts).

## Setup

1. Get your API key and auth token from https://divineapi.com/api-keys
2. Set environment variables: `DIVINE_API_KEY` and `DIVINE_AUTH_TOKEN`
3. Add to your MCP client configuration (Claude Desktop, Cursor, etc.)

## Tool groups (57 tools)

| Group | Tools | Host |
|-------|-------|------|
| Natal | 10 | astroapi-4 (wheel chart on astroapi-8) |
| Synastry | 13 | astroapi-4 (wheel/aspect-table on astroapi-8) |
| Transit | 12 | astroapi-4 and astroapi-8 |
| Composite | 4 | astroapi-8 |
| Advanced natal | 11 | astroapi-8 |
| Progressions and returns | 5 | astroapi-8 |
| Prenatal | 2 | astroapi-8 |

## Notable input details

- `house_system` accepts friendly names (placidus, koch, porphyry, regiomontanus, campanus, equal, whole-sign, morinus, alcabitius) or the Swiss Ephemeris single-letter codes (B, C, E, K, M, O, P, R, W). Names are mapped to letter codes before the API call; invalid values fail client-side with the list of accepted names.
- `divine_western_dominants` requires `method` (`TRADITIONAL` or `MODERN`).
- `divine_western_fixed_stars_details` requires `star_list`; get valid names from `divine_western_fixed_stars_list` (which needs no input).
- Detail endpoints are two-step: `divine_western_planet_return_details` takes a `return_key` from `divine_western_planet_returns_list`, and `divine_western_prenatal_details` takes a `prenatal_key` from `divine_western_prenatal_list`.
- Transit tools require the transit moment: `transit_day`/`transit_month`/`transit_year` (plus time and location fields where the endpoint needs them) and, for weekly/monthly/full reports, a `transit_planet`.
- `divine_western_custom_transit` computes transits at a fully specified transit moment and place: it takes the natal birth block plus all ten transit-moment fields as required inputs (`transit_day`/`transit_month`/`transit_year`/`transit_hour`/`transit_min`/`transit_sec` and `transit_place`/`transit_lat`/`transit_lon`/`transit_tzone`). Unlike `divine_western_transit_basic`, it also accepts the transit place, latitude, longitude, and timezone.
- API failures raise MCP tool errors (`isError: true`); plain `Error: ...` strings are returned only for client-side validation of enum-style inputs.

See CHANGELOG.md for the full history, including the fixes that made 38 previously failing tools work.

Documentation: https://developers.divineapi.com/western-api

# Changelog

## [1.4.2] - 2026-07-08

### Added

Add server-level instructions (how-to-use note read at connect: conventions, house_system values, list/details chaining).

## [1.4.1] - 2026-07-08

### Fixed

**OAuth: clients registered without a scope are no longer rejected when they
request one.** The metadata advertises scope "astrology", so spec-following
connectors (e.g. ChatGPT) may request it even when their dynamic client
registration omitted it; registration now defaults the client scope to
"astrology" (default_scopes). Verified against the full simulated connector
flow: discovery, registration, PKCE authorize, login, token exchange.

## [1.4.0] - 2026-07-08

### Added

**Single-token authentication: `Authorization: Bearer <api_key>:<auth_token>`.**
For platforms that can send only one credential field and no custom headers
(e.g. the Claude Messages API MCP connector). The middleware splits the value
on the first colon and converts it to the internal JWT, exactly like the
X-Divine header pair. Real OAuth JWTs never contain a colon and pass through
untouched. Existing auth methods are unchanged.

## 1.3.0 (2026-07-08): param parity fixes from the live-API audit

Based on the 2026-07-08 param parity audit (collection + live-API curl verification, see PARAM-PARITY-AUDIT-WESTERN.md in the computer-use project). Before these fixes, 38 of 56 tools failed on every call made with default inputs. All changes below were verified against the live API (34/34 functional scenarios passing, including invalid-input cases).

### Fixed: house_system was invalid on every astroapi-4 call (27 tools)

The schema default `"placidus"` (and every friendly name the docstrings advertised) is not a value the live API accepts: astroapi-4 rejects it with "Please enter valid house system" and astroapi-8 silently ignores it. Added a module-level mapping from friendly names to the Swiss Ephemeris single-letter codes the API accepts:

placidus:P, koch:K, porphyry:O, regiomontanus:R, campanus:C, equal:E, whole-sign:W (also whole_sign/wholesign), morinus:M, alcabitius:B

- Friendly names are accepted case-insensitively; already-valid single letters pass through.
- Mapping is applied in every payload that includes house_system (natal model, synastry model, and the general sign/house report keyword argument).
- Invalid values fail client-side with a validation error listing the accepted names.
- The schema default stays `"placidus"` (now mapped to P), so existing callers keep working, and the 27 previously broken astroapi-4 tools now succeed with defaults.

### Fixed: tools that failed on EVERY call due to missing required parameters

These tools never sent parameters the live API validates as required, so every invocation returned a validation error. Each now declares them (schema change: new required fields).

| Tool | Added required params | Added optional params |
|------|----------------------|----------------------|
| divine_western_transit_basic | transit_day, transit_month, transit_year, transit_hour, transit_min, transit_sec | |
| divine_western_transit_weekly | transit_planet | |
| divine_western_transit_house | now uses the full-transit input model (natal + transit date/time/location) | |
| divine_western_transit_monthly | transit_planet, transit_month, transit_year, transit_lat, transit_lon, transit_tzone, transit_place | aspects_type, aspect_orbs_type, aspect_orbs_value |
| divine_western_full_transit | now uses the full-transit input model, plus transit_planet | aspects_type, aspect_orbs_type, aspect_orbs_value |
| divine_western_fixed_stars_details | star_list (comma-separated names from divine_western_fixed_stars_list) | |
| divine_western_dominants | method (TRADITIONAL or MODERN, validated client-side; the two produce different rankings) | |
| divine_western_planet_returns_list | planet, return_year, return_lat, return_lon, return_tzone, return_place | |
| divine_western_planet_return_details | planet, return_key (from returns list), return_year, return_lat, return_lon, return_tzone, return_place | |
| divine_western_progressed_lunar_events | prenatal_type (e.g. SYZYGY) | |
| divine_western_planetary_arc_directions | planet, progressed_day, progressed_month, progressed_year | |
| divine_western_secondary_progressions | progressed_day, progressed_month, progressed_year, progressed_hour, progressed_min, progressed_sec, progressed_type (e.g. ARMC1_NAIBOD) | planet |
| divine_western_prenatal_list | prenatal_type (e.g. SYZYGY) | |
| divine_western_prenatal_details | prenatal_key (from prenatal list) | |

### Fixed: tools that demanded input the API ignores (schema change)

- divine_western_moon_phase_calendar: the endpoint is month-scoped and needs only month, year, place, lat, lon, tzone, lan. New slim input model; the old birth-data fields (full_name, day, hour, min, sec, gender, house_system) are still accepted as deprecated optional fields for backward compatibility but are no longer sent to the API.
- divine_western_fixed_stars_list: the endpoint needs no parameters at all (it returns the star-name catalog). The params object is now optional; all old fields are accepted as deprecated optional fields and not sent.

### Changed: error handling

- API failures (non-2xx, network errors, and error envelopes returned with HTTP 200 such as `{"success": 2, ...}` or `{"status": "error", ...}`) now raise MCP ToolError so clients see isError: true. Plain `Error: ...` string returns remain only for client-side validation of enum-style inputs (house_system, method).

### Docs

- Corrected the advertised house-system options in field descriptions (added porphyry/alcabitius spellings that the API actually supports via letter codes; removed none).
- Header now states the accurate tool count (56).
- README rewritten with tool-group table and input notes.

## 1.2.0 (imported 2026-07-08 from PyPI/production)

This version was released to PyPI and deployed to production but its source was never committed to this repository. The repository file was replaced with the extracted PyPI 1.2.0 source (verified byte-identical to the running container) before applying the fixes above. Changes 1.2.0 introduced relative to 1.0.0:

- Migrated natal wheel chart to /western-api/v2/natal-wheel-chart on astroapi-8 (was v1 on astroapi-4).
- Migrated synastry natal wheel chart to /western-api/v2/synastry/natal-wheel-chart on astroapi-8.
- Migrated synastry aspect tool to /western-api/v2/synastry/aspect-table on astroapi-8 (was v1/synastry/aspect on astroapi-4).
- Migrated monthly transit to /western-api/v2/transit/monthly (still lacked the required transit params until the fixes above).
- Added 3 tools: divine_western_transit_wheel_chart, divine_western_transit_planetary_positions (both with a new full-transit input model), divine_western_planetary_ingress.
- Added ApiKeyToJwtMiddleware: converts X-Divine-Api-Key/X-Divine-Auth-Token headers into a JWT Bearer token for HTTP deployments.

## 1.0.0

Initial release: 53 tools across natal, synastry, transit, composite, advanced natal, progressions/returns, and prenatal groups.

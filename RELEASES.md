# Typesec releases

Versioning is `0.MINOR.0` — a minor bump per release (in `0.x`, a minor may
include breaking changes). Each release carries a **codename after a Venetian
landmark**, assigned in list order.

## Release log

| Version | Codename | Notes |
|---|---|---|
| 0.11.0 | Burano  | Workspace quality/DRY/test review; glob unification (behavior change); Grust 0.11 graph-type validation. |
| 0.10.0 | Murano  | Tracks Grust 0.11.0 (Crab). |
| 0.9.0  | Rialto  | Human-reviewability refactor; opens the Venetian-landmark line. |

## Codename pool (Venice landmarks, in assignment order)

Names already assigned are struck through.

1. ~~Rialto~~ — assigned to `0.9.0`
2. ~~Murano~~ — assigned to `0.10.0`
3. ~~Burano~~ — assigned to `0.11.0`
4. Torcello
5. Lido
6. Arsenale
7. Dorsoduro
8. Cannaregio
9. Castello
10. Giudecca
11. Zattere
12. Accademia
13. Frari
14. Salute
15. Redentore
16. Campanile
17. Procuratie
18. Ducale
19. Bovolo
20. Fondaco
21. Querini
22. Sansovino
23. Bragora
24. Miracoli
25. Pellestrina

Notes on the picks: *Rialto*, *Murano*, *Burano*, and *Lido* are the most
recognizable and read cleanly as names even to people who've never been.
*Arsenale* has a strong, weighty ring (and a fitting history as Venice's shipyard
and naval powerhouse). *Salute*, *Redentore*, and *Frari* are major churches with
short, memorable names. *Bovolo* (a famous spiral staircase) and *Miracoli* are
more obscure but distinctive if you want deeper cuts for internal codenames.

## Cutting a release

To cut a release:

1. Bump the workspace version **and** the internal path-dep constraints (they
   must match or cargo errors), and `crates/typesec-python/pyproject.toml`.
2. Bump the Grust path-dep constraints if tracking a new Grust release.
3. Move the `CHANGELOG.md` `Unreleased` section under the new version.
4. Add the version + codename row to the **Release log** above and strike the
   codename off the pool.
5. Rebuild the book (`docs/book/build.sh` reads the version from `Cargo.toml`).
6. Tag `vX.Y.Z` and create a GitHub release titled with the codename.

# Source Layout

The source code builds against the FSS/SCI stack from
[EzPC](https://github.com/mpc-msri/EzPC). The root CMake build creates a
build-tree overlay so existing EzPC/FSS include conventions continue to work.

This checkout is trimmed to the **DCF-based comparison** and its dependencies.

## Directories

* `commons/` — dFSS-wide types, `GroupElement`, public material helpers, common
  utilities, and key material. Also contains `field_q.h` with ML-DSA prime
  field ($q = 8380417$) constants and helpers.
* `mpc/` — low-level runtime support: communication, reconstruct/opening, COT
  accounting, MUX, Boolean gates, bit decomposition, Beaver multiplication.
* `fss/` — the dFSS FSS core: ordinary GGM, correlated GGM, payload conversion,
  DPF, iDPF, and shared-input wrapper APIs.
* `buildingblock/` — the DCF-based comparison API (`comparison.h`) and its
  underlying MIC engine (`mic.h`), plus the Z_q comparison extension
  (`comparison_zq.h`).
* `deps/` — vendored SCI dependencies (Millionaire, OT, cryptoTools).

## Library Contents

1. **FSS core**: `fss/dpf.h`, `fss/idpf.h`, `fss/fss_wrapper.h`, and
   `fss/internal/*`.
2. **MIC**: `buildingblock/mic.h`. Multi-interval containment over the
   dealer-less DCF (iDPF prefix) machinery. This is the internal engine of the
   comparison building block.
3. **Comparison (ring)**: `buildingblock/comparison.h`. Provides
   `dfss::comparison` (arithmetic output), `dfss::comparisonBit` (Boolean
   output), and the unsigned `ringExtend` helper, all built on a
   single-interval $[0, \text{threshold})$ MIC.
4. **Comparison (field)**: `buildingblock/comparison_zq.h`. Value-correct
   $Z_q$ comparison ($q = 8380417$) via 24-bit no-wrap lift and two-interval
   MIC $[0, t) \cup [q, q+t)$. No online Millionaire or B2A.

## Removed From This Fork

The following modules were removed to keep this fork focused on DCF-based
comparison: equality, standalone interval-containment API, truncation, digit
decomposition, modular reduction, signed ring extension, lookup tables,
spline/polynomial evaluation (`math/*`), the legacy NDSS baseline
(`legacy/*`), and the `tools/` generators.

For detailed usage, see `docs/developer-usage.md` and the `test` folder.

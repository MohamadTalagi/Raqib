# Vendored fonts

Fonts used by the PDF compliance report (`weasyprint` renders them via
`@font-face`, loaded through an explicit `FontConfiguration()` — see
`test_report_smoke.py` for why that step is required). Both families are
licensed under the **SIL Open Font License, Version 1.1** (OFL-1.1), which
requires the license text to accompany any redistributed copy of the Font
Software (OFL §3). The unmodified upstream license file for each family is
vendored alongside its binaries.

| Font file | Family | Version | Upstream source | License |
|---|---|---|---|---|
| `Inter-Regular.ttf` | Inter, weight 400 | v4.1 | https://github.com/rsms/inter/releases/tag/v4.1 (`extras/ttf/Inter-Regular.ttf`) | OFL-1.1 — `Inter-OFL.txt` |
| `Inter-SemiBold.ttf` | Inter, weight 600 | v4.1 | https://github.com/rsms/inter/releases/tag/v4.1 (`extras/ttf/Inter-SemiBold.ttf`) | OFL-1.1 — `Inter-OFL.txt` |
| `JetBrainsMono-Regular.ttf` | JetBrains Mono, weight 400 | v2.304 | https://github.com/JetBrains/JetBrainsMono/releases/tag/v2.304 (`fonts/ttf/JetBrainsMono-Regular.ttf`) | OFL-1.1 — `JetBrainsMono-OFL.txt` |

License files:

- `Inter-OFL.txt` — fetched unmodified from
  `https://raw.githubusercontent.com/rsms/inter/master/LICENSE.txt`
  (Copyright (c) 2016 The Inter Project Authors).
- `JetBrainsMono-OFL.txt` — fetched unmodified from
  `https://raw.githubusercontent.com/JetBrains/JetBrainsMono/v2.304/OFL.txt`
  (Copyright 2020 The JetBrains Mono Project Authors).

Note on internal naming: `Inter-SemiBold.ttf`'s internal font family name is
"Inter SemiBold", not "Inter" with a SemiBold subfamily. `@font-face` rules
that reference this file must declare `font-family: 'Inter'; font-weight:
600;` explicitly rather than relying on the file's internal name, or the
weight will not apply as expected.

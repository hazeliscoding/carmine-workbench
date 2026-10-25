# Font sources

Static TTF files, copied unchanged from each family's own release, in only the weights the screen uses. Avalonia reads neither WOFF2 nor variable fonts. All three families are under the SIL Open Font License 1.1, and each folder holds its `OFL.txt`, which the app embeds with the fonts.

| File | Version | Source | SHA-256 |
|---|---|---|---|
| `PublicSans/PublicSans-Regular.ttf` | 2.001 | [public-sans-v2.001.zip](https://github.com/uswds/public-sans/releases/download/v2.001/public-sans-v2.001.zip), `fonts/ttf/` | `b577e9bc9887284e90aae5ad0699689ce36b5cd96207efbec68f77f8aed88379` |
| `PublicSans/OFL.txt` | 2.001 | the same archive | `157a9e77f7580246e97c769490e2e977ae94399f9d30f4556015c41fe8c28bac` |
| `BarlowSemiCondensed/BarlowSemiCondensed-SemiBold.ttf` | 1.422 | [jpt/barlow at tag 1.422](https://raw.githubusercontent.com/jpt/barlow/1.422/fonts/ttf/BarlowSemiCondensed-SemiBold.ttf) | `5358c566b2039988c68b4ea2af05270da055110a5d23fbd686d5a11fbecf4e03` |
| `BarlowSemiCondensed/OFL.txt` | 1.422 | [jpt/barlow at tag 1.422](https://raw.githubusercontent.com/jpt/barlow/1.422/OFL.txt) | `186d750eb496a4c17a76385f82be6aea2ac1cf2de074a811d63786cf374ea73f` |
| `JetBrainsMono/JetBrainsMono-Regular.ttf` | 2.304 | [JetBrainsMono-2.304.zip](https://github.com/JetBrains/JetBrainsMono/releases/download/v2.304/JetBrainsMono-2.304.zip), `fonts/ttf/` | `a0bf60ef0f83c5ed4d7a75d45838548b1f6873372dfac88f71804491898d138f` |
| `JetBrainsMono/JetBrainsMono-SemiBold.ttf` | 2.304 | the same archive | `1b3bfa1ed5665a4ce3f9feb68d2d4e40e70bf8b4b7d9a3edd418f321b4e166a0` |
| `JetBrainsMono/OFL.txt` | 2.304 | the same archive | `30f0c136e3c88e422d0791acd97238870f9054a9729bc34cf2ff0d4ed8cac4ad` |

The archives: `public-sans-v2.001.zip` is `88cacdf7cd03b31af8f1f83e1f51e0eb5a6052565a6c014c90c385f1ff2d13a5`, and `JetBrainsMono-2.304.zip` is `6f6376c6ed2960ea8a963cd7387ec9d76e3f629125bc33d1fdcd7eb7012f7bbf`. Barlow's 1.422 release has no assets, so its files come from the tagged tree.

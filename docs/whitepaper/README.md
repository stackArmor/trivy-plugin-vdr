# VDR PAIN whitepaper

`vdr-pain-cvss.tex` — an RFC-style whitepaper: *A Deterministic, CVSS-Environmental
Method for FedRAMP Rev5 VDR/VER Vulnerability Prioritization*.

It argues that FedRAMP's Potential Agency Impact (PAIN, N1–N5) and remediation
requirements map directly onto the CVSS v3.1 Environmental metric group (CR/IR/AR
and the Modified Impact Sub-Score), derives PAIN and the VDR-TFR-PVR remediation
deadline in closed form, gives worked calculations, and includes a reference
architecture and a sample scan. The asset-archetype catalog is presented as an
**example**, not a standard — each CSP is encouraged to derive its own CR/IR/AR
assignment.

## Build

Any LaTeX toolchain works. Lightest local option:

```bash
brew install tectonic        # one-time
tectonic vdr-pain-cvss.tex   # emits vdr-pain-cvss.pdf next to the source
```

Or with a full TeX install: `latexmk -pdf vdr-pain-cvss.tex`. Or paste the `.tex`
into Overleaf (no install).

Requires: `amsmath`, `booktabs`, `xcolor`, `tikz`, `microtype`, `hyperref`
(all standard; Tectonic and Overleaf fetch them automatically).

The committed `vdr-pain-cvss.pdf` is the rendered output for convenience.

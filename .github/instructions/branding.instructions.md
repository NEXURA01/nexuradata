---
description: "Use when modifying branding elements: logo, header, footer, visual tokens, nav structure, or email signatures. Enforces locked branding policy. Triggers on: logo, header, footer, branding, nav, signature, brand, identity."
applyTo: ["**/*.html", "assets/**/*.css"]
---
# NEXURA DATA — Locked Branding Policy

All branding elements below are **LOCKED**. Technical and structural changes are allowed if faithful. Creative changes (logo, typography, colors, spacing, composition) are **forbidden** without explicit validation.

## Logo Assets

| File | Usage |
|------|-------|
| `assets/nexuradata-master.svg` | Header, footer, documents, institutional pages |
| `assets/nexuradata-master.png` | Environments that don't support SVG, document exports |
| `assets/nexuradata-signature.png` | Email signatures |
| `assets/nexuradata-icon.png` | Favicon, reduced icon |

Never stretch, compress, recolor, re-typeset, or rearrange internal logo blocks.

## Locked Visual Tokens

```css
:root {
  --noir: #0d0d0b;
  --os: #e8e4dc;
  --os-dim: rgba(232, 228, 220, 0.22);
  --os-ghost: rgba(232, 228, 220, 0.08);
  --rule: 0.5px solid rgba(232, 228, 220, 0.1);
  --serif: 'Georgia', 'Times New Roman', serif;
  --tracking-wide: 0.35em;
  --tracking-xwide: 0.55em;
}
```

These values are fixed — no color substitution, no typographic replacement, no framework override.

## Locked Header

```html
<header class="site-header">
  <div class="container">
    <nav class="site-nav" aria-label="Navigation principale">
      <a class="brand" href="/" aria-label="Accueil NEXURA DATA">
        <img src="/assets/nexuradata-master.svg" alt="NEXURA DATA" class="brand-logo">
      </a>
      <div class="nav-links">
        <a href="/services.html">Services</a>
        <a href="/tarifs-recuperation-donnees-montreal.html">Tarifs</a>
        <a href="/politique-confidentialite.html">Confidentialité</a>
        <a href="/conditions-intervention-paiement.html">Conditions</a>
        <a href="/#contact">Contact</a>
      </div>
    </nav>
  </div>
</header>
```

Same structure on all public FR pages. EN pages use equivalent translated links. Do not move the logo or break the `nav > brand` hierarchy.

## Locked Footer

Same footer on all public pages. Do not remove legal links, rewrite the operating note, or replace the footer logo. Full reference: see `docs/branding-read-only.txt` sections E–F.

## Locked CSS (Header/Footer/Logo)

Logo sizing, nav layout, footer grid, link styles, and responsive breakpoints are locked. No local overrides without a branding decision. Full reference: see `docs/branding-read-only.txt` section G.

## Email Signature

Only `Nom Prénom`, `Titre / Fonction`, and the email address are editable. The confidentiality text, image, and order are locked. Full reference: see `docs/branding-read-only.txt` section H.

## Change Classification

| Category | Allowed? | Examples |
|----------|----------|----------|
| **Technical** | Yes, if faithful | PNG export, responsive sizing, path correction |
| **Structural** | Yes, if coherent | New nav link, new legal page, EN extension |
| **Creative** | **No** — requires explicit validation | Logo change, font change, spacing change, composition change |

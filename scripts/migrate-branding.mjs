/**
 * Branding migration script — NEXURA DATA locked branding system.
 * 
 * Replaces headers, footers, Google Fonts links, logo references, 
 * and meta theme-color across all public HTML files.
 * 
 * Run: node scripts/migrate-branding.mjs
 * Review diffs, then delete this script.
 */

import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");

// ── Locked branding blocks ──────────────────────────────────────

const FR_HEADER = `  <header class="site-header">
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
  </header>`;

const EN_HEADER = `  <header class="site-header">
    <div class="container">
      <nav class="site-nav" aria-label="Main navigation">
        <a class="brand" href="/en/" aria-label="NEXURA DATA home">
          <img src="/assets/nexuradata-master.svg" alt="NEXURA DATA" class="brand-logo">
        </a>
        <div class="nav-links">
          <a href="/en/services.html">Services</a>
          <a href="/en/tarifs-recuperation-donnees-montreal.html">Pricing</a>
          <a href="/en/politique-confidentialite.html">Privacy</a>
          <a href="/en/conditions-intervention-paiement.html">Terms</a>
          <a href="/en/#contact">Contact</a>
        </div>
      </nav>
    </div>
  </header>`;

const FR_FOOTER = `  <footer class="site-footer">
    <div class="container">
      <section class="footer-top" aria-label="Identité et informations">
        <img src="/assets/nexuradata-master.svg" alt="NEXURA DATA" class="footer-logo">
      </section>

      <section class="footer-grid" aria-label="Informations du site">
        <div class="footer-block">
          <small>ACTIVITÉ</small>
          <p>Récupération de données, RAID, NAS, serveurs et forensique numérique.</p>
        </div>

        <div class="footer-block">
          <small>LOCALISATION</small>
          <p>Montréal, Québec, Canada</p>
        </div>

        <div class="footer-block">
          <small>COURRIEL</small>
          <p><a href="mailto:contact@nexuradata.ca">contact@nexuradata.ca</a></p>
        </div>

        <div class="footer-block">
          <small>CONFIDENTIALITÉ</small>
          <p><a href="mailto:privacy@nexuradata.ca">privacy@nexuradata.ca</a></p>
        </div>
      </section>

      <section class="footer-legal" aria-label="Liens légaux">
        <a href="/mentions-legales.html">Mentions légales</a>
        <a href="/politique-confidentialite.html">Politique de confidentialité</a>
        <a href="/engagements-conformite-quebec.html">Engagements Québec</a>
        <a href="/conditions-intervention-paiement.html">Conditions d'intervention</a>
      </section>

      <section class="footer-note" aria-label="Note d'exploitation">
        <p>
          NEXURA DATA opère au Canada en récupération de données et en analyse spécialisée.
          Les interventions sont réalisées à la suite d'une évaluation préalable et après
          validation des conditions applicables.
        </p>
      </section>
    </div>
  </footer>`;

const EN_FOOTER = `  <footer class="site-footer">
    <div class="container">
      <section class="footer-top" aria-label="Identity and information">
        <img src="/assets/nexuradata-master.svg" alt="NEXURA DATA" class="footer-logo">
      </section>

      <section class="footer-grid" aria-label="Site information">
        <div class="footer-block">
          <small>SERVICES</small>
          <p>Data recovery, RAID, NAS, servers and digital forensics.</p>
        </div>

        <div class="footer-block">
          <small>LOCATION</small>
          <p>Montreal, Quebec, Canada</p>
        </div>

        <div class="footer-block">
          <small>EMAIL</small>
          <p><a href="mailto:contact@nexuradata.ca">contact@nexuradata.ca</a></p>
        </div>

        <div class="footer-block">
          <small>PRIVACY</small>
          <p><a href="mailto:privacy@nexuradata.ca">privacy@nexuradata.ca</a></p>
        </div>
      </section>

      <section class="footer-legal" aria-label="Legal links">
        <a href="/en/mentions-legales.html">Legal notice</a>
        <a href="/en/politique-confidentialite.html">Privacy policy</a>
        <a href="/en/engagements-conformite-quebec.html">Quebec commitments</a>
        <a href="/en/conditions-intervention-paiement.html">Terms of service</a>
      </section>

      <section class="footer-note" aria-label="Operating note">
        <p>
          NEXURA DATA operates in Canada in data recovery and specialized analysis.
          All interventions are performed following a prior assessment and after
          validation of the applicable terms.
        </p>
      </section>
    </div>
  </footer>`;

// ── Replacement helpers ──────────────────────────────────────────

function replaceBlock(html, openTag, closeTag, replacement) {
  const openRe = new RegExp(`([ \\t]*)<${openTag}[^>]*>`, "s");
  const openMatch = html.match(openRe);
  if (!openMatch) return html;

  const startIdx = openMatch.index;
  const closeStr = `</${closeTag}>`;
  const closeIdx = html.indexOf(closeStr, startIdx);
  if (closeIdx === -1) return html;

  return html.slice(0, startIdx) + replacement + html.slice(closeIdx + closeStr.length);
}

function removeGoogleFonts(html) {
  // Remove preconnect links to Google Fonts
  html = html.replace(/\s*<link\s+rel="preconnect"\s+href="https:\/\/fonts\.googleapis\.com"[^>]*>/g, "");
  html = html.replace(/\s*<link\s+rel="preconnect"\s+href="https:\/\/fonts\.gstatic\.com"[^>]*>/g, "");
  // Remove the Google Fonts stylesheet link
  html = html.replace(/\s*<link\s+href="https:\/\/fonts\.googleapis\.com\/css2[^"]*"[^>]*>/g, "");
  return html;
}

function updateThemeColor(html) {
  return html.replace(
    /<meta\s+name="theme-color"\s+content="[^"]*">/g,
    '<meta name="theme-color" content="#0d0d0b">'
  );
}

function updateFavicon(html) {
  return html.replace(
    /<link\s+rel="icon"\s+type="image\/svg\+xml"\s+href="[^"]*">/g,
    '<link rel="icon" type="image/svg+xml" href="/assets/nexuradata-icon.png">'
  );
}

// ── File discovery ───────────────────────────────────────────────

async function getHtmlFiles(dir, prefix = "") {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (entry.name === "release-cloudflare" || entry.name === "node_modules") continue;
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      if (["en", "operations"].includes(entry.name) || prefix) {
        files.push(...(await getHtmlFiles(path.join(dir, entry.name), rel)));
      }
    } else if (entry.name.endsWith(".html")) {
      files.push(rel);
    }
  }
  return files;
}

// ── Main ─────────────────────────────────────────────────────────

const files = await getHtmlFiles(root);
let changed = 0;

for (const relPath of files) {
  const filePath = path.join(root, relPath);
  const original = await readFile(filePath, "utf8");
  let html = original;

  const isEN = relPath.startsWith("en/");
  const isOps = relPath.startsWith("operations/");

  // Skip operations pages — they keep their own nav
  if (isOps) {
    console.log(`SKIP (ops): ${relPath}`);
    continue;
  }

  // Replace header
  html = replaceBlock(html, "header", "header", isEN ? EN_HEADER : FR_HEADER);

  // Replace footer
  html = replaceBlock(html, "footer", "footer", isEN ? EN_FOOTER : FR_FOOTER);

  // Remove Google Fonts
  html = removeGoogleFonts(html);

  // Update theme-color to --noir
  html = updateThemeColor(html);

  // Update favicon
  html = updateFavicon(html);

  if (html !== original) {
    await writeFile(filePath, html, "utf8");
    changed++;
    console.log(`UPDATED: ${relPath}`);
  } else {
    console.log(`UNCHANGED: ${relPath}`);
  }
}

console.log(`\nMigrated ${changed} file(s).`);

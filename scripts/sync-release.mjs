import { cp, mkdir, readdir, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const releaseDir = path.join(projectRoot, "release-cloudflare");
const excludedHtmlFiles = new Set(["index2.html"]);

const rootFiles = new Set([
  "_headers",
  "_redirects",
  ".nojekyll",
  "robots.txt",
  "site.webmanifest",
  "sitemap.xml"
]);

const shouldCopyRootEntry = (entry) => {
  if (entry === "assets") {
    return true;
  }

  if (entry === "en") {
    return true;
  }

  if (entry === "operations") {
    return true;
  }

  if (entry === ".well-known") {
    return true;
  }

  if (rootFiles.has(entry)) {
    return true;
  }

  if (path.extname(entry).toLowerCase() === ".html") {
    return !excludedHtmlFiles.has(entry);
  }

  return false;
};

await rm(releaseDir, { recursive: true, force: true });
await mkdir(releaseDir, { recursive: true });

const entries = await readdir(projectRoot, { withFileTypes: true });

for (const entry of entries) {
  if (!shouldCopyRootEntry(entry.name)) {
    continue;
  }

  const source = path.join(projectRoot, entry.name);
  const destination = path.join(releaseDir, entry.name);

  await cp(source, destination, { recursive: true });
}

console.log("Generated release-cloudflare/ from the tracked site source.");

// Generate build/icon.png (512) and build/icon.ico from assets/logo.svg
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import sharp from "sharp";
import pngToIco from "png-to-ico";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const svg = readFileSync(join(root, "assets", "logo.svg"));
const buildDir = join(root, "build");
mkdirSync(buildDir, { recursive: true });

async function main() {
  // Master 512 PNG (used by Linux + as ico source)
  const png512 = await sharp(svg, { density: 384 }).resize(512, 512).png().toBuffer();
  writeFileSync(join(buildDir, "icon.png"), png512);

  // Multi-size ICO for crisp Windows rendering
  const sizes = [16, 24, 32, 48, 64, 128, 256];
  const pngs = await Promise.all(
    sizes.map((s) => sharp(svg, { density: 384 }).resize(s, s).png().toBuffer())
  );
  const ico = await pngToIco(pngs);
  writeFileSync(join(buildDir, "icon.ico"), ico);

  console.log("✔ Generated build/icon.png and build/icon.ico");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

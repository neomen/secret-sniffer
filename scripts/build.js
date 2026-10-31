import { build } from "esbuild";
import { mkdir, rm } from "node:fs/promises";

await rm("dist", { recursive: true, force: true });
await mkdir("dist", { recursive: true });

const common = {
  entryPoints: ["src/index.js"],
  bundle: true,
  platform: "neutral",
  target: ["es2022"],
  sourcemap: true,
  legalComments: "none"
};

await Promise.all([
  build({ ...common, outfile: "dist/secret-sniffer.mjs", format: "esm" }),
  build({ ...common, outfile: "dist/secret-sniffer.min.mjs", format: "esm", minify: true }),
  build({ ...common, outfile: "dist/secret-sniffer.cjs", format: "cjs", platform: "node", target: ["node18"] })
]);

console.log("Built ESM, minified ESM, and CommonJS bundles in dist/");

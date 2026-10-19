import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repo = resolve(root, "..", "..");
const capability = process.env.CLC_CAPABILITY_DIR
  ? resolve(process.env.CLC_CAPABILITY_DIR)
  : resolve(repo, "..", "capability");
const output = process.env.CLC_LAB_OUT
  ? resolve(process.env.CLC_LAB_OUT)
  : resolve(root, "dist");
const esbuildModule = process.env.CLC_ESBUILD_MODULE
  ? resolve(process.env.CLC_ESBUILD_MODULE)
  : "/home/varwof/src/github.com/aic-jwt/node_modules/esbuild/lib/main.js";

const { build } = await import(pathToFileURL(esbuildModule).href);
const cryptoShim = resolve(root, "src", "node-crypto.ts");
const bufferShim = resolve(root, "src", "buffer.ts");

await rm(output, { recursive: true, force: true });
await mkdir(join(output, "vectors"), { recursive: true });

await build({
  entryPoints: [resolve(root, "src", "main.ts")],
  outfile: join(output, "app.js"),
  bundle: true,
  format: "esm",
  platform: "browser",
  target: ["chrome110"],
  minify: true,
  sourcemap: false,
  inject: [bufferShim],
  plugins: [{
    name: "browser-node-crypto",
    setup(buildApi) {
      buildApi.onResolve({ filter: /^node:crypto$/ }, () => ({ path: cryptoShim }));
    },
  }],
  logLevel: "warning",
});

await copyFile(join(root, "lab.css"), join(output, "lab.css"));
const template = await readFile(join(root, "index.template.html"), "utf8");
await writeFile(join(output, "index.html"), template);

const vectors = [
  ["data/_vectors/clc-v1/vectors.json", "clc-a.json"],
  ["data/_vectors/clc-d/containment-vectors.json", "containment.json"],
  ["data/_vectors/clc-v1/param-bounds-vectors.json", "param-bounds.json"],
  ["data/_vectors/clc-v1/param-bounds-meet-vectors.json", "bound-meet.json"],
  ["data/_vectors/clc-v1/resolve-vectors.json", "resolve.json"],
  ["data/_vectors/clc-v1/constraint-union-vectors.json", "constraint-union.json"],
];
for (const [source, target] of vectors) {
  await copyFile(join(capability, source), join(output, "vectors", target));
}

console.log(`built CLC lab in ${output}`);

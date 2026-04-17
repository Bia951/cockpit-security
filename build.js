#!/usr/bin/env node

import { cp, mkdir, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import process from "node:process";

const require = createRequire(import.meta.url);
const esbuild = await import(require.resolve("esbuild"));

const outdir = "dist";
const watch = process.argv.includes("-w") || process.argv.includes("--watch");
const production = process.env.NODE_ENV === "production";

async function copyAssets() {
    await mkdir(outdir, { recursive: true });
    await cp("src/index.html", `${outdir}/index.html`);
    await cp("src/index.css", `${outdir}/index.css`);
    await cp("src/manifest.json", `${outdir}/manifest.json`);
}

const context = await esbuild.context({
    bundle: true,
    entryPoints: ["./src/index.js"],
    format: "iife",
    legalComments: "external",
    metafile: true,
    minify: production,
    outfile: `${outdir}/index.js`,
    plugins: [
        {
            name: "copy-assets",
            setup(build) {
                build.onEnd(async result => {
                    if (result.errors.length > 0)
                        return;

                    await copyAssets();
                    await writeFile("metafile.json", JSON.stringify(result.metafile, null, 2));
                });
            },
        },
    ],
    sourcemap: production ? false : "linked",
    target: ["es2020"],
});

async function build() {
    const start = Date.now();
    await context.rebuild();
    console.log(`Build finished in ${Date.now() - start} ms`);
}

try {
    await build();
} catch (error) {
    console.error(error);
    await context.dispose();
    process.exit(1);
}

if (watch) {
    await context.watch();
    console.log("Watching for changes...");
    process.stdin.resume();
} else {
    await context.dispose();
}

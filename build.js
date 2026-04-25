#!/usr/bin/env node

const { access } = require("node:fs/promises");
const { cp, mkdir, readdir, rm, watch, writeFile } = require("node:fs/promises");
const { constants } = require("node:fs");
const path = require("node:path");

const outdir = "dist";
const patternflyPackageDir = path.join("node_modules", "@patternfly", "patternfly");
const patternflyCss = path.join(patternflyPackageDir, "patternfly.css");
const patternflyAssets = path.join(patternflyPackageDir, "assets");
const watchMode = process.argv.includes("-w") || process.argv.includes("--watch");
let rebuildTimer = null;

async function ensureDependencies() {
    try {
        await access(patternflyCss, constants.R_OK);
    } catch (error) {
        throw new Error(
            "Missing npm dependency @patternfly/patternfly. Run `npm install` before building."
        );
    }
}

async function copyFiles() {
    await rm(outdir, { recursive: true, force: true });
    await mkdir(outdir, { recursive: true });
    await cp("src", outdir, { recursive: true });
    await cp(patternflyCss, path.join(outdir, "patternfly.css"));
    await cp(patternflyAssets, path.join(outdir, "assets"), { recursive: true });
}

async function build() {
    const start = Date.now();
    await ensureDependencies();
    const copied = await readdir("src");
    await copyFiles();
    await writeFile("metafile.json", JSON.stringify({
        copied: copied.sort(),
        outdir,
        timestamp: new Date().toISOString(),
    }, null, 2));
    console.log(`Build finished in ${Date.now() - start} ms`);
}

function queueBuild() {
    if (rebuildTimer)
        clearTimeout(rebuildTimer);

    rebuildTimer = setTimeout(async () => {
        try {
            await build();
        } catch (error) {
            console.error("Rebuild failed:", error);
        }
    }, 120);
}

async function main() {
    await build();

    if (!watchMode)
        return;

    console.log("Watching for changes...");
    process.stdin.resume();
    const watcher = watch("src", { recursive: true });

    for await (const _event of watcher)
        queueBuild();
}

main().catch(error => {
    console.error(error);
    process.exit(1);
});

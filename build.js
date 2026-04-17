#!/usr/bin/env node

const { cp, mkdir, readdir, watch, writeFile } = require("node:fs/promises");

const outdir = "dist";
const watchMode = process.argv.includes("-w") || process.argv.includes("--watch");
let rebuildTimer = null;

async function copyFiles() {
    await mkdir(outdir, { recursive: true });
    await cp("src", outdir, { recursive: true });
}

async function build() {
    const start = Date.now();
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

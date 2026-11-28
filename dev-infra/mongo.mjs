import { mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

// WiredTiger database files cannot safely live in iCloud/Dropbox/OneDrive folders:
// sync conflict copies corrupt the engine metadata. Keep local development data
// outside the repository by default and allow an explicit non-synced override.
const dataDirectory = resolve(
  process.env.DISPTCHR_LOCAL_MONGO_DIR || `${tmpdir()}/disptchr-local-mongodb`,
);
const binaryDirectory = resolve(".local/mongodb-binaries");
await mkdir(dataDirectory, { recursive: true });
await mkdir(binaryDirectory, { recursive: true });

process.env.MONGOMS_DOWNLOAD_DIR ||= binaryDirectory;

const { MongoMemoryServer } = await import("mongodb-memory-server");
const server = await MongoMemoryServer.create({
  instance: {
    port: 27017,
    ip: "127.0.0.1",
    dbName: "skyhawk_ops",
    dbPath: dataDirectory,
    storageEngine: "wiredTiger",
    launchTimeout: 60_000,
  },
});

console.log(`Local DISPTCHR MongoDB is ready on port 27017 (${dataDirectory}).`);

let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  await server.stop({ doCleanup: false, force: false });
  process.exit(0);
}

process.on("SIGINT", stop);
process.on("SIGTERM", stop);

await new Promise(() => {});

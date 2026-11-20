import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const dataDirectory = resolve(".local/mongodb");
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

console.log("Local DISPTCHR MongoDB is ready on port 27017.");

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

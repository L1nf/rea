import { appendFile } from "node:fs/promises";
import { z } from "zod";
import type { BinaryTarget } from "../../src/domain/binaryTargetTypes.js";
import { jsonValueSchema, type JsonValue } from "../../src/domain/jsonValue.js";
import {
  IdaToolRejection,
  type IdaMcpConnection,
} from "../../src/ida/IdaMcpConnection.js";
import { RecordingIdaMcp } from "./idaMcp.js";

const QUERY_LINE = /\n_rea_query\(("[^"\n]*"), ("(?:[^"\\\n]|\\.)*")\)$/u;

/**
 * Stateful Hex-Rays IDA MCP fixture at the real connection seam. Leases are
 * tracked like the official server; `execute_python` decodes REA's trailing
 * query line and answers through the database-supervisor fixture's reads.
 */
export class RecordingHexRaysIdaMcp implements IdaMcpConnection {
  readonly calls: {
    name: string;
    args: Readonly<Record<string, JsonValue>>;
  }[] = [];
  readonly reads: RecordingIdaMcp;
  /** Leases this server holds, keyed by instance id. */
  readonly leases = new Map<string, { path: string; backend: string }>();
  /** Databases other clients hold; listed without an instance id or lease. */
  peers: { path: string; backend: string; sha256?: string }[] = [];
  tools = [
    "open_database",
    "list_databases",
    "close_database",
    "execute_python",
    "reference",
    "save_database",
  ];
  openBackend = "idalib";
  /** Backend an open of a GUI-listed database reports; only gui binds one. */
  guiOpenBackend: "gui" | "idalib" = "gui";
  rejectOpen = false;
  /** Lose the open reply in transport, optionally after the lease exists. */
  loseOpenReply: { leased: boolean } | undefined;
  /** Reject close_database; `keepLease` leaves the worker registered. */
  rejectClose: { keepLease: boolean } | undefined;
  /**
   * Input path an opened database records. When set, an open is treated as an
   * existing database: health reports this input and the opened path as the
   * database, and releasing the lease repacks the opened file like idalib.
   */
  recordedInputPath: string | undefined;
  /** Engine output reported beside every execute_python result. */
  engineOutput = { stdout: "", stderr: "" };
  closes = 0;
  detaches = 0;
  #nextId = 0;
  /** The GUI database this connection last opened as its current database. */
  #currentGui:
    | { path: string; backend: string; sha256?: string; id: string }
    | undefined;
  /** MCP-local lease ids this connection holds for opened GUI databases. */
  readonly #guiLeases = new Set<string>();

  constructor(readonly target: BinaryTarget) {
    this.reads = new RecordingIdaMcp(target, "headless");
  }
  async connect() {
    return this.tools;
  }
  serverInfo() {
    return { name: "ida-mcp", version: "fixture" };
  }
  async close() {
    this.closes += 1;
  }
  detach() {
    this.detaches += 1;
  }
  async call(
    name: string,
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    this.calls.push({ name, args: structuredClone(args) });
    switch (name) {
      case "open_database": {
        if (this.rejectOpen)
          throw new IdaToolRejection("IDA MCP tool failed: cannot load file");
        const path = z.string().parse(args.path);
        const peer = this.peers.find((candidate) => candidate.path === path);
        if (peer !== undefined) {
          // Inventory rows list GUI databases without an instance id, but an
          // open assigns this connection an MCP-local lease id and, for gui
          // backends, binds the connection's current database.
          const instance_id = `guilease${(this.#nextId += 1)}`;
          if (this.guiOpenBackend === "gui") {
            this.#currentGui = { ...peer, id: instance_id };
            this.#guiLeases.add(instance_id);
            this.reads.inputPath = peer.path;
            this.reads.inputSha256 = peer.sha256 ?? this.target.sha256;
            this.reads.idbPath = undefined;
          }
          return {
            instance_id,
            backend: this.guiOpenBackend,
            status: "current",
            recovery: "none",
          };
        }
        const instance_id = `lease${(this.#nextId += 1)}`;
        if (this.loseOpenReply?.leased !== false)
          this.leases.set(instance_id, { path, backend: this.openBackend });
        this.reads.inputPath = this.recordedInputPath ?? path;
        this.reads.idbPath =
          this.recordedInputPath === undefined ? undefined : path;
        if (this.loseOpenReply !== undefined)
          throw new Error("Fixture transport lost the open reply");
        return {
          instance_id,
          backend: this.openBackend,
          status: "attached",
          recovery: "none",
        };
      }
      case "list_databases":
        return {
          instances: [
            ...[...this.leases].map(([instance_id, lease]) => ({
              path: lease.path,
              backend: lease.backend,
              status: "attached",
              instance_id,
              error: null,
            })),
            ...this.peers.map((peer) => ({
              ...peer,
              status: "available",
              instance_id: null,
              error: null,
            })),
          ],
        };
      case "close_database": {
        const id = z.string().parse(args.instance_id);
        if (this.rejectClose !== undefined) {
          if (!this.rejectClose.keepLease) this.leases.delete(id);
          throw new IdaToolRejection(
            `IDA MCP tool failed: unknown database instance: ${id}`,
          );
        }
        const lease = this.leases.get(id);
        if (lease === undefined || !this.leases.delete(id))
          throw new IdaToolRejection(
            `IDA MCP tool failed: unknown database instance: ${id}`,
          );
        if (this.recordedInputPath !== undefined)
          await appendFile(lease.path, "repacked");
        return { closed: true };
      }
      case "execute_python": {
        const id =
          args.instance_id === undefined || args.instance_id === null
            ? undefined
            : z.string().parse(args.instance_id);
        if (id === undefined) {
          // Unleased reads run against the connection's current database.
          if (this.#currentGui === undefined)
            throw new IdaToolRejection(
              "IDA MCP tool failed: no database is open on this connection",
            );
        } else if (!this.leases.has(id) && !this.#guiLeases.has(id))
          throw new IdaToolRejection(
            `IDA MCP tool failed: unknown database instance: ${id}`,
          );
        const match = QUERY_LINE.exec(z.string().parse(args.code));
        if (match === null) throw new Error("Unrecognized fixture Python");
        const tool = z.string().parse(JSON.parse(match[1] ?? ""));
        const query = z
          .record(z.string(), jsonValueSchema)
          .parse(JSON.parse(z.string().parse(JSON.parse(match[2] ?? ""))));
        const result = await this.reads.call(tool, {
          ...query,
          ...(id === undefined ? {} : { database: id }),
        });
        return { result, ...this.engineOutput };
      }
      default:
        throw new Error(`Unimplemented producer tool ${name}`);
    }
  }
}

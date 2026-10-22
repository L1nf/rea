import { z } from "zod";
import { ABORTED, waitForAbortable } from "../process/AbortablePromise.js";
import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisOperation,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisProtocolError,
  AnalysisOutputError,
  AnalysisInputError,
  AnalysisTimeoutError,
  AnalysisResourceConstraintError,
  resourceConstraintRecovery,
} from "../domain/analysisErrorCore.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { AnalysisProfileCommitment } from "../domain/analysisProfile.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import type { IdaConfiguration } from "./IdaConfiguration.js";
import { idaProtocol } from "./IdaConfiguration.js";
import { IdaToolRejection, type IdaMcpConnection } from "./IdaMcpConnection.js";
import {
  hexRaysAttachedOpenSchema,
  hexRaysCloseSchema,
  hexRaysListSchema,
  hexRaysOpenSchema,
  hexRaysTools,
  runHexRaysQuery,
} from "./IdaHexRaysProtocol.js";
import { nativeTools } from "./IdaNativeProtocol.js";
import { readSettledHealth } from "./IdaBusyHealth.js";
import { isX86OnlyTarget } from "./IdaCallGraph.js";
import {
  IdaOperationRunner,
  type IdaRawObservation,
} from "./IdaOperationRunner.js";
import {
  IDA_DATABASE_TARGET_LIMITATION,
  IDA_LIMITATIONS,
  IDA_OPERATIONS,
  IDA_PROVIDER_IDENTITY,
  idaProfileAdmits,
  type IdaOperation,
} from "./IdaProviderCapabilities.js";
import {
  absentDatabaseCloseSchema,
  closeDatabaseSchema,
  databaseListSchema,
  legacyMetadataSchema,
  modernHealthSchema,
  openDatabaseSchema,
  rejectedOpenDatabaseSchema,
} from "./IdaProtocolValues.js";
import {
  idaFileDigest,
  IdaWorkspace,
  sameIdaHostPath,
} from "./IdaWorkspace.js";
import { parseIdaInput } from "./IdaInput.js";
import { createEvidence } from "../domain/evidence.js";

const legacyTools = [
  "get_metadata",
  "list_functions",
  "list_strings",
  "get_function_by_name",
  "get_function_by_address",
  "decompile_function",
  "disassemble_function",
  "get_callers",
  "get_callees",
  "get_xrefs_to",
];
const modernTools = [
  "idb_open",
  "idb_list",
  "idb_close",
  "server_health",
  "list_funcs",
  "lookup_funcs",
  "find_regex",
  "decompile",
  "disasm",
  "callees",
  "xrefs_to",
];
const operationSet: ReadonlySet<string> = new Set(IDA_OPERATIONS);

const isIdaOperation = (operation: string): operation is IdaOperation =>
  operationSet.has(operation);
const wasCancelled = (options: ExecutionOptions | undefined): boolean =>
  options?.signal?.aborted === true;

interface IdaOperationFailureContext {
  runner: IdaOperationRunner | undefined;
  metadataBefore: JsonValue | undefined;
  metadataAfter: JsonValue | undefined;
  postOperationIdentityCheck: "not_attempted" | "started" | "verified";
  parameters: Readonly<Record<string, JsonValue>>;
}

/** Upstream session ids of inventory entries, omitting unreported ones. */
interface UpstreamSession {
  readonly session_id: string;
  readonly backend: "worker" | "gui";
  /** Upstream ownership; null when no inventory has reported it. */
  readonly owned: boolean | null;
  /** Last inventoried input binding; null until upstream reports it. */
  readonly input_path: string | null;
  /** Last inventoried activity; null before upstream reports it. */
  readonly is_active: boolean | null;
}

/** One upstream inventory row in the database-supervisor vocabulary. */
type InventoriedSession = UpstreamSession & {
  readonly owned: boolean;
  readonly input_path: string;
  readonly is_active: boolean;
};

/** A failed cleanup retains its private workspace and reports the remaining resource. */
class IdaCleanupError extends ProviderAdapterError {
  override readonly cleanupIncomplete = true;
  constructor(
    path: string,
    cause: unknown,
    sessions?: readonly UpstreamSession[],
  ) {
    super("ida", "close", {
      cause,
      capturedOutput:
        cause instanceof AnalysisError ? cause.capturedOutput : undefined,
      diagnostics: {
        ...(cause instanceof AnalysisError ? cause.diagnostics : undefined),
        reason:
          "IDA cleanup could not be verified; the remaining connection or private workspace is retained for retry.",
        failure_reason:
          cause instanceof AnalysisError
            ? (cause.diagnostics?.reason ?? cause.message)
            : cause instanceof Error
              ? cause.message
              : String(cause),
        workspace: path,
        ...(sessions === undefined
          ? {}
          : {
              upstream_sessions: {
                state: "unverified",
                sessions: sessions.map(
                  ({ session_id, backend, owned, input_path, is_active }) => ({
                    session_id,
                    backend,
                    owned,
                    input_path,
                    is_active,
                  }),
                ),
                reason:
                  "Release of upstream sessions matching the requested session ID or private input was not confirmed; input_path preserves the last observed binding and is null when no inventory has reported it. is_active preserves registry activity and is null when unknown; it does not establish process liveness. A worker outlives its supervisor and may keep running until it finishes and reaches its idle timeout; exiting REA does not stop it. A gui session belongs to an IDA instance REA does not control. An empty session_id means upstream reported none; owned is null when no inventory has reported ownership; an empty list means the requested worker's close was confirmed but no inventory has identified any remaining session.",
              },
            }),
      },
    });
    this.setCleanupResources([path]);
  }
}

/** Serial read-only session whose lifecycle authority excludes an attached GUI. */
export class IdaSessionClient implements AnalysisClient {
  #tail: Promise<void> = Promise.resolve();
  #startup: Promise<void> | undefined;
  #closed = false;
  #closing = false;
  #closePromise: Promise<Result<null, AnalysisError>> | undefined;
  #workspace: IdaWorkspace | undefined;
  #database: string | undefined;
  /** The upstream session id this client requested or was assigned; unknown before then. */
  #expectedSession: string | undefined;
  #databaseCloseCompleted = false;
  #openAttempted = false;
  #openCompleted = false;
  #ready = false;
  #blockingSessions: readonly UpstreamSession[] | undefined;
  /** True once an attached open bound the connection to the matching GUI database. */
  #hexRaysAttached = false;
  #openRejected = false;
  #callGraphAdvertised = false;
  #surveyAdvertised = false;
  #initialIdentity: string | undefined;
  #metadata: JsonValue = null;
  #lifecycle: JsonValue[] = [];
  /** Hex-Rays health reads of the current operation, kept whole beside the parsed metadata. */
  #healthObservations: IdaRawObservation[] = [];

  constructor(
    private readonly config: IdaConfiguration,
    private readonly target: BinaryTarget,
    private readonly connection: IdaMcpConnection,
    private readonly profile?: AnalysisProfileCommitment,
  ) {}

  execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ) {
    const call = this.#tail.then(() =>
      this.#execute(operation, parameters, options),
    );
    this.#tail = call.then(
      () => undefined,
      () => undefined,
    );
    return call;
  }

  async executeIfReady(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ) {
    if (!this.#ready || this.#closed || this.#closing)
      return Promise.resolve(undefined);
    const call = this.#tail.then(() => {
      if (!this.#ready || this.#closed || this.#closing) return undefined;
      if (wasCancelled(options))
        return err(new AnalysisCancelledError(operation));
      return this.#execute(operation, parameters, options, true);
    });
    this.#tail = call.then(
      () => undefined,
      () => undefined,
    );
    const result = await waitForAbortable(call, options?.signal);
    return result === ABORTED
      ? err(new AnalysisCancelledError(operation))
      : result;
  }

  async #execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
    readyOnly = false,
  ) {
    if (this.#closed || this.#closing)
      return err(
        new AnalysisProtocolError(
          "IDA session is closing or closed; reopen the target.",
        ),
      );
    if (wasCancelled(options))
      return err(new AnalysisCancelledError(operation));
    if (operation !== "health" && !isIdaOperation(operation))
      return err(
        new AnalysisCapabilityUnavailableError(
          "ida",
          operation,
          "This integration admits read-only analysis operations only.",
        ),
      );
    if (
      operation !== "health" &&
      !idaProfileAdmits(operation, this.config.mode)
    )
      return err(
        new AnalysisCapabilityUnavailableError(
          "ida",
          operation,
          "This operation is available for the modern headless profile only.",
        ),
      );
    if (
      operation === "procedure_callers" &&
      idaProtocol(this.config) !== "legacy"
    )
      return err(
        new AnalysisCapabilityUnavailableError(
          "ida",
          operation,
          "This upstream profile does not prove direct callers.",
        ),
      );
    if (operation !== "health") {
      const parsed = parseIdaInput(operation, parameters);
      if (!parsed.ok) return parsed;
      parameters = parsed.value;
    }
    const document = parameters.document;
    if (
      document !== undefined &&
      (typeof document !== "string" ||
        (!sameIdaHostPath(document, this.target.path) &&
          (this.target.sourcePath === undefined ||
            !sameIdaHostPath(document, this.target.sourcePath))))
    )
      return err(
        new AnalysisInputError(operation, undefined, [
          {
            path: ["document"],
            reason: "invalid_value",
            expected: this.target.path,
            message:
              "IDA document must be the REA-bound target; omit document or use its admitted path.",
          },
        ]),
      );
    this.#healthObservations = [];
    const failureContext: IdaOperationFailureContext = {
      runner: undefined,
      metadataBefore: undefined,
      metadataAfter: undefined,
      postOperationIdentityCheck: "not_attempted",
      parameters,
    };
    try {
      if (!readyOnly) await this.#start(operation);
      const before = await this.#observe(options);
      failureContext.metadataBefore = before;
      if (wasCancelled(options)) throw new AnalysisCancelledError(operation);
      if (operation === "health") return this.#health(before);
      if (!isIdaOperation(operation))
        throw new AnalysisProtocolError(
          "IDA operation changed after validation.",
        );
      const runner = this.#runner(options);
      failureContext.runner = runner;
      const result = await runner.run(operation, parameters);
      if (wasCancelled(options)) throw new AnalysisCancelledError(operation);
      failureContext.postOperationIdentityCheck = "started";
      const after = await this.#observe(
        options,
        (observed) => (failureContext.metadataAfter = observed),
      );
      failureContext.postOperationIdentityCheck = "verified";
      if (wasCancelled(options)) throw new AnalysisCancelledError(operation);
      return ok(
        createAnalysisExecution(result, IDA_PROVIDER_IDENTITY, {
          rawResult: {
            upstream: this.connection.serverInfo(),
            metadata_before: before,
            metadata_after: after,
            observations: jsonValueSchema.parse(runner.raw),
            ...this.#healthEvidence(),
          },
          limitations: [...this.#limitations(), ...runner.limitations],
          ...(runner.relationshipCoverage === undefined
            ? {}
            : { relationshipCoverage: runner.relationshipCoverage }),
          ...(runner.referencesTruncated !== undefined
            ? { referencesTruncated: runner.referencesTruncated }
            : {}),
          locations: [
            { kind: "artifact-path", path: this.target.path },
            ...runner.locations,
          ],
          ...(this.profile === undefined
            ? {}
            : { analysisProfile: this.profile }),
        }),
      );
    } catch (cause: unknown) {
      return this.#failure(operation, cause, options, failureContext);
    }
  }

  #runner(options: ExecutionOptions | undefined): IdaOperationRunner {
    const protocol = idaProtocol(this.config);
    const database = this.#database;
    return new IdaOperationRunner(
      this.connection,
      // Hex-Rays answers database-supervisor reads through its query bridge.
      protocol === "hexrays" ? "modern" : protocol,
      database,
      {
        // An attached session queries its bound GUI database, which reports
        // no lease id, through the connection's current database.
        ...(protocol === "hexrays" &&
        (database !== undefined || this.#hexRaysAttached)
          ? {
              invoke: (tool, args) =>
                runHexRaysQuery(
                  this.connection,
                  database,
                  tool,
                  args,
                  this.config.timeoutMs,
                ),
            }
          : {}),
        signal: options?.signal,
        selectorOrigin: options?.selectorOrigin,
        x86Only: isX86OnlyTarget(this.target),
        callGraphAvailable: this.#callGraphAdvertised,
        surveyAvailable: this.#surveyAdvertised,
        admittedDocument: this.target.path,
      },
    );
  }

  #limitations(): readonly string[] {
    return this.target.kind === "database"
      ? [...IDA_LIMITATIONS, IDA_DATABASE_TARGET_LIMITATION]
      : IDA_LIMITATIONS;
  }

  #health(metadata: JsonValue) {
    return ok(
      createAnalysisExecution(
        {
          ready: true,
          mode: this.config.mode,
          database: this.#database ?? null,
          upstream: this.connection.serverInfo(),
          metadata,
          lifecycle: this.#lifecycle,
        },
        IDA_PROVIDER_IDENTITY,
        {
          limitations: this.#limitations(),
          ...(this.profile === undefined
            ? {}
            : { analysisProfile: this.profile }),
        },
      ),
    );
  }

  #failure(
    operation: string,
    cause: unknown,
    options: ExecutionOptions | undefined,
    context: IdaOperationFailureContext,
  ) {
    let failure: AnalysisError;
    if (wasCancelled(options)) {
      failure = new AnalysisCancelledError(operation, {
        cause,
        ...(cause instanceof AnalysisError
          ? {
              capturedOutput: cause.capturedOutput,
              diagnostics: cause.diagnostics,
              partialObservation: cause.partialObservation,
              cleanup:
                cause.cleanup ??
                (cause.cleanupIncomplete
                  ? {
                      reason: cause.message,
                      resources: cause.cleanupResources,
                    }
                  : undefined),
            }
          : {}),
      });
      if (cause instanceof AnalysisError)
        failure
          .bindCleanupDependencies([cause])
          .bindCleanupResourceOwner(cause);
    } else if (
      cause instanceof ProviderAdapterError &&
      cause.operation === "transport"
    )
      failure = new ProviderAdapterError("ida", operation, {
        cause,
        capturedOutput: cause.capturedOutput,
        partialObservation: cause.partialObservation,
        cleanup: cause.cleanup,
        diagnostics: {
          ...cause.diagnostics,
          recovery:
            "Check the configured upstream MCP registration and selected target; see docs/ida-provider.md.",
        },
      });
    else if (cause instanceof AnalysisError) failure = cause;
    else if (cause instanceof z.ZodError)
      failure = new AnalysisOutputError(
        operation,
        `IDA MCP returned malformed or unsupported producer data: ${cause.issues.map((issue) => `${issue.path.join(".") || "$"}: ${issue.message}`).join("; ")}`,
        { cause },
      );
    else
      failure = new ProviderAdapterError("ida", operation, {
        cause,
        diagnostics: {
          reason:
            cause instanceof Error ? cause.message : "Unknown upstream failure",
          recovery:
            "Check the configured upstream MCP registration and selected target; see docs/ida-provider.md.",
        },
      });
    // Only operation calls made after target identity/readiness validation can
    // become partial Evidence. The failing call itself is absent from `raw`
    // when its transport or MCP envelope could not be decoded.
    const { runner, metadataBefore, metadataAfter } = context;
    if (
      runner !== undefined &&
      runner.raw.length > 0 &&
      metadataBefore !== undefined
    ) {
      const observations = jsonValueSchema.parse(runner.raw);
      const upstream = this.connection.serverInfo();
      const binding =
        context.postOperationIdentityCheck !== "verified"
          ? {
              status: "not_verified",
              reason:
                cause instanceof Error
                  ? cause.message
                  : "Post-operation target identity was not observed.",
            }
          : { status: "verified" };
      failure.retainPartialObservation(
        createEvidence(this.target, IDA_PROVIDER_IDENTITY, {
          predicateType: "analysis-observation",
          operation,
          parameters: context.parameters,
          result: {
            status: "partial",
            failed_operation: operation,
            observations,
            metadata_before: metadataBefore,
            target_binding: binding,
            ...(metadataAfter === undefined
              ? {}
              : { metadata_after: metadataAfter }),
          },
          rawResult: {
            upstream,
            observations,
            metadata_before: metadataBefore,
            ...(metadataAfter === undefined
              ? {}
              : { metadata_after: metadataAfter }),
            ...this.#healthEvidence(),
            post_operation_identity_check: context.postOperationIdentityCheck,
          },
          confidence: "observed",
          authority: "external-service",
          limitations: [
            ...this.#limitations(),
            ...runner.limitations,
            "The requested IDA operation failed after these completed upstream replies; the partial Evidence does not establish a complete result.",
            "Replies are bound to the selected target only by the pre-operation identity check unless post_operation_identity_check is verified.",
          ],
          locations: [
            { kind: "artifact-path", path: this.target.path },
            ...runner.locations,
          ],
          ...(this.profile === undefined
            ? {}
            : { analysisProfile: this.profile }),
        }),
      );
    }
    return err(failure);
  }

  async #start(operation: string): Promise<void> {
    this.#startup ??= this.#initialize();
    try {
      await this.#startup;
    } catch (cause: unknown) {
      if (
        !(cause instanceof AnalysisTimeoutError) &&
        !(cause instanceof AnalysisResourceConstraintError) &&
        !(cause instanceof ProviderAdapterError)
      )
        throw cause;
      // Transport adapters already receive caller attribution in #failure.
      if (
        cause instanceof ProviderAdapterError &&
        cause.operation === "transport"
      )
        throw cause;
      const options = {
        cause,
        capturedOutput: cause.capturedOutput,
        partialObservation: cause.partialObservation,
        cleanup: cause.cleanup,
        ...(cause.userMessage === undefined
          ? {}
          : { userMessage: cause.userMessage }),
        diagnostics: {
          ...cause.diagnostics,
          startup_operation: cause.operation,
        },
      };
      const action =
        cause.remediationAction === undefined
          ? {}
          : { remediationAction: cause.remediationAction };
      // Startup is shared, but each accepted operation owns its attribution.
      // Keep the original cached failure unchanged for later callers.
      const failure =
        cause instanceof AnalysisTimeoutError
          ? new AnalysisTimeoutError(operation, cause.timeoutMs, {
              ...options,
              ...action,
            })
          : cause instanceof AnalysisResourceConstraintError
            ? new AnalysisResourceConstraintError(
                operation,
                cause.resource,
                cause.reason,
                cause.reportedLimits,
                { ...options, ...resourceConstraintRecovery(cause) },
              )
            : new ProviderAdapterError(cause.providerId, operation, {
                ...options,
                ...action,
              });
      throw failure
        .bindCleanupDependencies([cause])
        .bindCleanupResourceOwner(cause);
    }
  }

  async #initialize(): Promise<void> {
    const protocol = idaProtocol(this.config);
    const tools = new Set(await this.connection.connect());
    // REA's query bridge implements both reads for the Hex-Rays profile.
    this.#callGraphAdvertised =
      protocol === "hexrays" || tools.has("callgraph");
    this.#surveyAdvertised =
      protocol === "hexrays" || tools.has("survey_binary");
    const expected =
      protocol === "native"
        ? nativeTools
        : protocol === "hexrays"
          ? hexRaysTools
          : this.config.mode === "attached"
            ? legacyTools
            : modernTools;
    const missing = expected.filter((name) => !tools.has(name));
    if (missing.length > 0) {
      // A registration for another profile can still point at the official
      // server; name the registration that fits instead of a reinstall.
      const servesHexRays =
        protocol !== "hexrays" && hexRaysTools.every((name) => tools.has(name));
      const hexRaysHint = servesHexRays
        ? ' This server serves the Hex-Rays IDA MCP catalog; register it with "mode": "headless" and "protocol": "hexrays".'
        : "";
      const summary =
        protocol === "hexrays"
          ? `IDA MCP Hex-Rays compatibility profile is missing tools: ${missing.join(", ")}. The Hex-Rays profile requires the official Hex-Rays IDA MCP tool catalog. See docs/ida-provider.md.`
          : `IDA MCP ${this.config.protocol === "native" ? "native attached" : this.config.mode} compatibility profile is missing tools: ${missing.join(", ")}. Native attached mode requires the native IDA MCP tool catalog; legacy attached mode requires the legacy 1.4 profile; headless mode requires the database supervisor profile.${hexRaysHint} See docs/ida-provider.md.`;
      // The caller cannot act on a profile mismatch it never sees, so the
      // missing names travel as adapter diagnostics rather than a bare message.
      throw new ProviderAdapterError("ida", "initialize", {
        userMessage: summary,
        diagnostics: {
          reason: summary,
          mode: this.config.mode,
          expected_profile:
            protocol === "native" || protocol === "hexrays"
              ? protocol
              : this.config.mode === "attached"
                ? "legacy-1.4"
                : "database-supervisor",
          missing_tools: [...missing],
          advertised_tools: [...tools].sort(),
          recovery: servesHexRays
            ? 'Set "mode": "headless" and "protocol": "hexrays" in the registration; see docs/ida-provider.md.'
            : "Install an IDA MCP build that serves the selected profile; see docs/ida-provider.md.",
        },
      });
    }
    if (this.config.mode === "headless") {
      this.#workspace = await IdaWorkspace.allocate(
        this.target,
        this.config.workspaceRoot,
      );
      await this.#workspace.copyInput();
      const workspace = this.#workspace;
      this.#openAttempted = true;
      const session =
        protocol === "hexrays"
          ? await this.#openHexRays(workspace)
          : await this.#openSupervisor(workspace);
      const inventory = await this.#inventory();
      this.#lifecycle.push(inventory.raw);
      this.#recordBlockingSessions(
        inventory.sessions.filter(
          (entry) =>
            entry.session_id === session ||
            sameIdaHostPath(entry.input_path, workspace.inputPath),
        ),
      );
      const entry = inventory.sessions.find(
        ({ session_id }) => session_id === session,
      );
      if (
        entry?.owned !== true ||
        entry.backend !== "worker" ||
        entry.is_active !== true ||
        !sameIdaHostPath(entry.input_path, workspace.inputPath)
      )
        throw new AnalysisProtocolError(
          "IDA did not return an active owned headless worker for the private input copy.",
        );
      this.#database = session;
    } else if (protocol === "hexrays") {
      await this.#bindAttachedHexRays();
    }
    this.#ready = true;
  }

  /** Request the private worker from a database supervisor; returns its session id. */
  async #openSupervisor(workspace: IdaWorkspace): Promise<string> {
    this.#expectedSession = workspace.sessionId;
    const raw = await this.connection.call("idb_open", {
      input_path: workspace.inputPath,
      mode: "force_headless",
      run_auto_analysis: true,
      build_caches: true,
      init_hexrays: true,
      preferred_session_id: workspace.sessionId,
    });
    this.#openCompleted = true;
    // A completed but malformed/positive open may still own a live Worker.
    // Only an explicit producer rejection keeps the old no-worker branch.
    this.#openRejected = rejectedOpenDatabaseSchema.safeParse(raw).success;
    this.#lifecycle.push(raw);
    const opened = openDatabaseSchema.parse(raw);
    if (!sameIdaHostPath(opened.session.input_path, workspace.inputPath))
      throw new AnalysisProtocolError(
        "IDA opened a different input than the private admitted target copy.",
      );
    if (opened.session.session_id !== workspace.sessionId)
      throw new AnalysisProtocolError(
        "IDA returned an adopted or unexpected session instead of the requested private worker.",
      );
    return opened.session.session_id;
  }

  /**
   * Lease an idalib worker for the private input copy. Hex-Rays assigns the
   * instance id, so the binding is the returned id plus its inventory row.
   */
  async #openHexRays(workspace: IdaWorkspace): Promise<string> {
    let raw: JsonValue;
    try {
      raw = await this.connection.call("open_database", {
        path: workspace.inputPath,
        set_current: false,
      });
    } catch (cause: unknown) {
      // A tool error is a completed, explicit rejection; anything else leaves
      // the open's outcome unknown and the workspace retained.
      if (cause instanceof IdaToolRejection) {
        this.#openCompleted = true;
        this.#openRejected = true;
      }
      throw cause;
    }
    this.#openCompleted = true;
    this.#lifecycle.push(raw);
    const opened = hexRaysOpenSchema.parse(raw);
    this.#expectedSession = opened.instance_id;
    if (opened.backend !== "idalib")
      throw new AnalysisProtocolError(
        "IDA attached a GUI database instead of a private idalib worker for the private input copy.",
      );
    return opened.instance_id;
  }

  /**
   * Bind the attached session to the GUI database whose recorded input
   * matches the admitted target. Inventory rows report no instance id, but
   * each open assigns this connection an MCP-local lease id that every later
   * query is pinned to; a server that reports none keeps the current
   * database binding instead.
   */
  async #bindAttachedHexRays(): Promise<void> {
    const raw = await this.connection.call("list_databases", {});
    this.#lifecycle.push(raw);
    const guiDatabases = hexRaysListSchema
      .parse(raw)
      .instances.filter(
        ({ backend, status }) => backend === "gui" && status === "available",
      );
    if (guiDatabases.length === 0)
      throw new AnalysisProtocolError(
        "The Hex-Rays IDA MCP reports no database open in the IDA GUI; open the selected target in IDA or use headless mode.",
      );
    const tried: string[] = [];
    for (const candidate of guiDatabases) {
      const rawOpen = await this.connection.call("open_database", {
        path: candidate.path,
      });
      const opened = hexRaysAttachedOpenSchema.parse(rawOpen);
      this.#lifecycle.push(rawOpen);
      // An attached lease must bind the GUI database the caller admitted; a
      // worker opened for a GUI-listed path is a different database.
      if (opened.backend !== "gui") {
        tried.push(`${candidate.path} (opened as ${opened.backend} worker)`);
        continue;
      }
      const lease = opened.instance_id ?? undefined;
      let health: JsonValue | undefined;
      let readFailure: string | undefined;
      try {
        health = await this.#readHexRaysHealth(lease);
      } catch (cause: unknown) {
        // A GUI database whose recorded input cannot be read cannot match,
        // but a transport failure must surface instead of looking like one.
        if (
          cause instanceof ProviderAdapterError ||
          cause instanceof AnalysisTimeoutError ||
          cause instanceof AnalysisResourceConstraintError
        )
          throw cause;
        readFailure = cause instanceof Error ? cause.message : String(cause);
      }
      const parsed = modernHealthSchema.safeParse(health);
      const recorded = parsed.success
        ? (parsed.data.input_sha256 ?? null)
        : null;
      if (
        recorded !== null &&
        recorded.toLowerCase() === this.target.sha256.toLowerCase()
      ) {
        this.#database = lease;
        this.#hexRaysAttached = true;
        return;
      }
      const reason =
        readFailure !== undefined
          ? `identity read failed: ${readFailure}`
          : !parsed.success
            ? "identity observation malformed"
            : recorded === null
              ? "input digest not recorded"
              : "input digest mismatch";
      tried.push(`${candidate.path} (${reason})`);
    }
    throw new AnalysisProtocolError(
      `No database open in the IDA GUI matches the selected target ${this.target.path}; GUI databases tried: ${tried.join(", ")}. Open that target in IDA or use headless mode.`,
    );
  }

  /** Upstream session inventory, normalized to the database-supervisor vocabulary. */
  async #inventory(): Promise<{
    readonly raw: JsonValue;
    readonly sessions: readonly InventoriedSession[];
  }> {
    if (idaProtocol(this.config) !== "hexrays") {
      const raw = await this.connection.call("idb_list", {});
      return { raw, sessions: databaseListSchema.parse(raw).sessions };
    }
    const raw = await this.connection.call("list_databases", {});
    return {
      raw,
      // REA's stdio server holds an instance id only for leases it opened.
      sessions: hexRaysListSchema.parse(raw).instances.map((entry) => ({
        session_id: entry.instance_id ?? "",
        backend: entry.backend === "gui" ? "gui" : "worker",
        owned: entry.instance_id !== null,
        input_path: entry.path,
        is_active: entry.status === "current" || entry.status === "attached",
      })),
    };
  }

  async #readHexRaysHealth(database: string | undefined): Promise<JsonValue> {
    const observation = await runHexRaysQuery(
      this.connection,
      database,
      "server_health",
      {},
      this.config.timeoutMs,
    );
    this.#healthObservations.push(observation);
    return observation.result;
  }

  /** The bridge digest and engine output behind this operation's identity checks. */
  #healthEvidence() {
    return this.#healthObservations.length === 0
      ? {}
      : {
          health_observations: jsonValueSchema.parse(this.#healthObservations),
        };
  }

  async #nativeMetadata(): Promise<JsonValue> {
    if (this.connection.readResource === undefined)
      throw new AnalysisProtocolError(
        "Native IDA MCP requires resources/read for recorded input metadata.",
      );
    return this.connection.readResource("ida://idb/metadata");
  }

  async #observe(
    options?: ExecutionOptions,
    onObserved?: (metadata: JsonValue) => void,
  ): Promise<JsonValue> {
    let identity: string;
    if (this.config.mode === "attached") {
      if (idaProtocol(this.config) === "hexrays") {
        // The GUI database is externally mutable, so every request rechecks
        // the digest it records for its input, not any file on disk.
        const raw = await this.#readHexRaysHealth(this.#database);
        const metadata = modernHealthSchema.parse(raw);
        this.#metadata = raw;
        onObserved?.(raw);
        if (
          (metadata.input_sha256 ?? null)?.toLowerCase() !==
          this.target.sha256.toLowerCase()
        )
          throw new AnalysisProtocolError(
            `The IDA GUI database does not record the SHA-256 of the selected target ${this.target.path}; open that target in IDA or use headless mode.`,
          );
        identity = JSON.stringify([
          metadata.input_path,
          (metadata.input_sha256 ?? null)?.toLowerCase(),
          metadata.imagebase,
        ]);
      } else {
        const raw =
          this.config.protocol === "native"
            ? await this.#nativeMetadata()
            : await this.connection.call("get_metadata", {});
        const metadata = legacyMetadataSchema.parse(raw);
        this.#metadata = raw;
        onObserved?.(raw);
        if (metadata.sha256.toLowerCase() !== this.target.sha256.toLowerCase())
          throw new AnalysisProtocolError(
            `The attached IDA input SHA-256 does not match the selected target ${this.target.path}; open that target in IDA or use headless mode.`,
          );
        identity = JSON.stringify([
          metadata.path,
          metadata.sha256.toLowerCase(),
          metadata.base,
        ]);
      }
    } else {
      if (this.#database === undefined || this.#workspace === undefined)
        throw new AnalysisProtocolError(
          "IDA headless session has no database binding.",
        );
      // Hex-Rays execute_python waits for initial auto-analysis before running.
      const raw =
        idaProtocol(this.config) === "hexrays"
          ? await this.#readHexRaysHealth(this.#database)
          : await readSettledHealth(this.connection, {
              database: this.#database,
              timeoutMs: this.config.timeoutMs,
              signal: options?.signal,
            });
      const metadata = modernHealthSchema.parse(raw);
      this.#metadata = raw;
      onObserved?.(raw);
      // A database records the input it was created from and is rewritten by
      // its worker, so the private copy is bound by the opened database path;
      // copyInput already verified the bytes it admitted.
      if (
        this.target.kind === "database"
          ? metadata.idb_path === null ||
            !sameIdaHostPath(metadata.idb_path, this.#workspace.inputPath)
          : !sameIdaHostPath(metadata.input_path, this.#workspace.inputPath) ||
            (await idaFileDigest(this.#workspace.inputPath)) !==
              this.#workspace.inputSha256
      )
        throw new AnalysisProtocolError(
          "IDA headless input identity changed after target admission.",
        );
      if (metadata.auto_analysis_ready !== true)
        throw new AnalysisProtocolError(
          "IDA auto-analysis is incomplete or readiness is unknown; retry after analysis completes.",
        );
      identity = JSON.stringify([
        this.#database,
        metadata.input_path,
        metadata.idb_path,
        metadata.imagebase,
      ]);
    }
    if (
      this.#initialIdentity !== undefined &&
      identity !== this.#initialIdentity
    )
      throw new AnalysisProtocolError(
        "The attached IDA target or image base changed during the REA session; reopen the target.",
      );
    this.#initialIdentity = identity;
    return this.#metadata;
  }

  async close(): Promise<Result<null, AnalysisError>> {
    if (this.#closePromise !== undefined) return this.#closePromise;
    const closing = this.#closeOnce();
    const shared = closing.finally(() => {
      if (this.#closePromise === shared) this.#closePromise = undefined;
    });
    this.#closePromise = shared;
    return shared;
  }

  /**
   * Upstream sessions whose release cleanup has not confirmed: the entries
   * the latest successful inventory found blocking release; else the
   * requested private worker until its close is confirmed, and then none
   * known.
   */
  #unreleasedSessions(): readonly UpstreamSession[] | undefined {
    if (this.#blockingSessions !== undefined) return this.#blockingSessions;
    if (
      !this.#openAttempted ||
      this.#workspace === undefined ||
      this.#openRejected
    )
      return undefined;
    return this.#databaseCloseCompleted
      ? []
      : [
          {
            session_id: this.#expectedSession ?? "",
            backend: "worker",
            owned: null,
            input_path: null,
            is_active: null,
          },
        ];
  }

  /** Drop a session whose release upstream confirmed, keeping other blockers. */
  #forgetReleasedSession(sessionId: string): void {
    const remaining = this.#blockingSessions?.filter(
      ({ session_id }) => session_id !== sessionId,
    );
    this.#blockingSessions =
      remaining !== undefined && remaining.length > 0 ? remaining : undefined;
  }

  /** Replace blocker evidence from a successful inventory; true when blocked. */
  #recordBlockingSessions(
    entries: readonly (UpstreamSession & { readonly owned: boolean })[],
  ): boolean {
    this.#blockingSessions =
      entries.length > 0
        ? entries.map(
            ({ session_id, backend, owned, input_path, is_active }) => ({
              session_id,
              backend,
              owned,
              input_path,
              is_active,
            }),
          )
        : undefined;
    return entries.length > 0;
  }

  /** Release the session; false when upstream rejected the release and only inventory can settle it. */
  async #closeDatabase(database: string): Promise<boolean> {
    if (idaProtocol(this.config) === "hexrays") {
      try {
        hexRaysCloseSchema.parse(
          await this.connection.call("close_database", {
            instance_id: database,
          }),
        );
        return true;
      } catch (cause: unknown) {
        // A rejected release, such as an already reaped or busy lease, is
        // settled by the inventory read that follows and retried otherwise.
        if (!(cause instanceof IdaToolRejection)) throw cause;
        return false;
      }
    }
    const response = await this.connection.call("idb_close", {
      database,
      save: false,
    });
    const closed = closeDatabaseSchema.safeParse(response);
    if (!closed.success) {
      if (!absentDatabaseCloseSchema(database).safeParse(response).success)
        throw closed.error;
      return true;
    }
    if (
      closed.data.session_id !== database ||
      closed.data.saved === true ||
      closed.data.owned !== true ||
      closed.data.backend !== "worker"
    )
      throw new AnalysisProtocolError(
        "IDA database close did not confirm the requested owned, unsaved session release.",
      );
    return true;
  }

  async #closeOnce(): Promise<Result<null, AnalysisError>> {
    this.#closing = true;
    await this.#tail;
    if (this.#closed) return ok(null);
    try {
      // An attached session holds no lease and no workspace; the bound GUI
      // database belongs to the user's IDA and is never closed or saved here.
      if (this.#workspace !== undefined && this.#openAttempted) {
        if (this.#database === undefined) {
          const inventory = await this.#inventory();
          const workspace = this.#workspace;
          const expected = this.#expectedSession;
          // REA's own Hex-Rays stdio server leases only what REA opened, so a
          // late lease on the private input is REA's even without a reply id.
          const adoptByPath =
            expected === undefined && idaProtocol(this.config) === "hexrays";
          this.#database = inventory.sessions.find(
            (entry) =>
              entry.owned &&
              entry.backend === "worker" &&
              (entry.session_id === expected || adoptByPath) &&
              sameIdaHostPath(entry.input_path, workspace.inputPath),
          )?.session_id;
          // Every same-input session and any entry under the requested ID,
          // whatever its input, stays reported until a later successful
          // inventory confirms release.
          const blocked = this.#recordBlockingSessions(
            inventory.sessions.filter(
              (entry) =>
                entry.session_id === expected ||
                sameIdaHostPath(entry.input_path, workspace.inputPath),
            ),
          );
          if (this.#database === undefined && blocked)
            throw new AnalysisProtocolError(
              "A registered session still matches the requested ID or private input without a verified private worker binding; the workspace was retained.",
            );
          if (
            this.#database === undefined &&
            this.#openCompleted &&
            !this.#openRejected
          )
            throw new AnalysisProtocolError(
              "IDA open returned without a verified private worker binding. An empty session inventory does not prove that its Worker exited; the private workspace was retained.",
            );
        }
        if (this.#database !== undefined) {
          if (
            !this.#databaseCloseCompleted &&
            (await this.#closeDatabase(this.#database))
          ) {
            this.#databaseCloseCompleted = true;
            this.#forgetReleasedSession(this.#database);
          }
          const inventory = await this.#inventory();
          const remaining = inventory.sessions.filter(
            (entry) =>
              entry.session_id === this.#database ||
              sameIdaHostPath(
                entry.input_path,
                this.#workspace?.inputPath ?? "",
              ),
          );
          if (this.#recordBlockingSessions(remaining))
            throw new AnalysisProtocolError(
              "IDA worker remains registered after close.",
            );
          // An unconfirmed close is settled once inventory shows the release.
          this.#databaseCloseCompleted = true;
          this.#database = undefined;
        }
        if (!this.#openCompleted)
          throw new AnalysisProtocolError(
            "IDA database open did not return a completed response. Worker inventory cannot prove that the request has stopped; the private workspace was retained.",
          );
        this.#openAttempted = false;
      }
      await this.connection.close();
      await this.#workspace?.remove();
      this.#closed = true;
      return ok(null);
    } catch (cause: unknown) {
      this.connection.detach();
      return err(
        new IdaCleanupError(
          this.#workspace?.directory ?? "IDA MCP connection",
          cause,
          this.#unreleasedSessions(),
        ),
      );
    }
  }
}

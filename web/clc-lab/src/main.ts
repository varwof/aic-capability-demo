import * as clc from "../../../ts/clc_semantics.ts";
import type { Decision, Grant, Operation, Resolution } from "../../../ts/clc_semantics.ts";

type Json = Record<string, unknown>;

interface SuiteVector extends Json {
  id: string;
  kind?: string;
  expect?: Json;
  derivation?: string;
}

interface Evidence {
  suite: string;
  id: string;
  expected: unknown;
  actual: unknown;
  pass: boolean;
  reason: string;
  derivation: string;
  input: unknown;
}

interface Suite {
  id: string;
  title: string;
  description: string;
  file: string;
  run: (vector: SuiteVector) => { actual: unknown; pass: boolean; reason?: string };
}

const app = document.querySelector("#lab") as HTMLElement;
const editor = document.querySelector("#editor") as HTMLTextAreaElement;
const functionSelect = document.querySelector("#function") as HTMLSelectElement;
const suiteSelect = document.querySelector("#suite") as HTMLSelectElement;
const runCustomButton = document.querySelector("#run-custom") as HTMLButtonElement;
const runSuiteButton = document.querySelector("#run-suite") as HTMLButtonElement;
const result = document.querySelector("#result") as HTMLElement;
const summary = document.querySelector("#summary") as HTMLElement;
const download = document.querySelector("#download") as HTMLButtonElement;

let evidence: Evidence[] = [];
let evidenceName = "clc-evidence.json";

function canonicalReason(value: unknown): string {
  return clc.canonicalReason(typeof value === "string" ? value : "");
}

function jsonEqual(a: unknown, b: unknown): boolean {
  return clc.canonicalStringify(a) === clc.canonicalStringify(b);
}

function checkIntersectResult(expect: Json, got: Grant): boolean {
  if ("result_params" in expect && !jsonEqual(expect.result_params ?? {}, got.params ?? {})) return false;
  if ("result_constraints" in expect && !jsonEqual(expect.result_constraints ?? [], got.constraints ?? [])) return false;
  return true;
}

function runClcAVector(v: SuiteVector): { actual: unknown; pass: boolean; reason?: string } {
  const expect = v.expect ?? {};
  const expectedVerdict = String(expect.verdict ?? "");
  const expectedReason = canonicalReason(expect.reason);
  if (v.kind === "entail" || v.kind === "decide") {
    const revision = String(v.clc_revision ?? "");
    if (revision && !clc.revisionCompatible(revision)) {
      const reason = "unsupported_language_revision";
      return {
        actual: { verdict: "deny", reason },
        pass: expectedVerdict === "deny" && expectedReason === reason,
        reason,
      };
    }
    if (typeof v.raw_params === "string" && v.raw_params) {
      try {
        clc.validateRawParams(v.raw_params);
      } catch (error) {
        const reason = canonicalReason((error as Error).message);
        return {
          actual: { verdict: "deny", reason },
          pass: "deny" === expectedVerdict && reason === expectedReason,
          reason,
        };
      }
    }
  }
  if (v.kind === "syntax") {
    try {
      const request = v.request as Json | null;
      clc.validateCapabilityID(typeof request?.id === "string" ? request.id : undefined);
      return { actual: { verdict: "valid" }, pass: "valid" === expectedVerdict && !expectedReason };
    } catch (error) {
      const reason = canonicalReason((error as Error).message);
      return {
        actual: { verdict: "invalid", reason },
        pass: "invalid" === expectedVerdict && reason === expectedReason,
        reason,
      };
    }
  }
  if (v.kind === "entail") {
    const got = clc.entails(v.grant as unknown as Grant, v.request as unknown as Operation);
    const actual = { verdict: got.entails ? "allow" : "deny", reason: canonicalReason(got.reason) };
    return {
      actual,
      pass: actual.verdict === expectedVerdict && actual.reason === expectedReason,
      reason: actual.reason,
    };
  }
  if (v.kind === "intersect") {
    const sources = [
      ...(v.grant == null ? [] : [v.grant as unknown as Grant]),
      ...((v.others ?? []) as Grant[]),
    ];
    try {
      const got = clc.intersect(sources);
      return {
        actual: { verdict: "allow", result: got },
        pass: "allow" === expectedVerdict && checkIntersectResult(expect, got),
      };
    } catch (error) {
      const reason = canonicalReason((error as Error).message);
      return {
        actual: { verdict: "deny", reason },
        pass: "deny" === expectedVerdict && reason === expectedReason,
        reason,
      };
    }
  }
  if (v.kind === "decide") {
    let grant = v.grant as Grant | null | undefined;
    const op = v.request as Operation | null | undefined;
    let decision: Decision;
    if (v.multi === true) {
      decision = clc.authorizeSet([
        grant ?? null,
        ...((v.others ?? []) as Grant[]),
      ], op);
    } else {
      const others = (v.others ?? []) as Grant[];
      if (others.length) {
        try {
          grant = clc.intersect([grant ?? ({ id: "" } as Grant), ...others]);
        } catch (error) {
          const reason = canonicalReason((error as Error).message);
          return {
            actual: { verdict: "deny", reason },
            pass: "deny" === expectedVerdict && reason === expectedReason,
            reason,
          };
        }
      }
      decision = clc.authorize(grant, op);
    }
    const reason = canonicalReason(decision.reason);
    let pass = decision.verdict === expectedVerdict && reason === expectedReason;
    if ("unresolved" in expect) {
      pass = pass && jsonEqual(expect.unresolved ?? [], decision.unresolved ?? []);
    }
    return { actual: decision, pass, reason };
  }
  return { actual: { error: `unsupported vector kind ${v.kind}` }, pass: false, reason: "unsupported_kind" };
}

const suites: Suite[] = [
  {
    id: "clc-a",
    title: "CLC-A authorization",
    description: "154 authorization, syntax, entailment, and intersection vectors",
    file: "vectors/clc-a.json",
    run: runClcAVector,
  },
  {
    id: "containment",
    title: "CLC-D containment",
    description: "64 parent/child containment vectors",
    file: "vectors/containment.json",
    run(v) {
      const got = clc.contains(v.parent as Grant, v.child as Grant);
      const expected = v.expect as Json;
      const reason = canonicalReason(got.reason);
      const pass = got.contains === expected.contains &&
        (got.contains || !expected.reason || reason === canonicalReason(expected.reason));
      return { actual: got, pass, reason };
    },
  },
  {
    id: "param-bounds",
    title: "Parameter bounds",
    description: "49 extended parameter-bound vectors",
    file: "vectors/param-bounds.json",
    run(v) {
      const grant = (v.grant ?? { id: "" }) as Grant;
      let op = (v.request ?? { id: "" }) as Operation;
      if (v.kind === "param-defaults") {
        op = clc.materializeDefaults(grant, op, v.scheme_defaults as Json | undefined);
      }
      const got = clc.entails(grant, op);
      const actual = { verdict: got.entails ? "allow" : "deny", reason: canonicalReason(got.reason) };
      const expected = v.expect as Json;
      return {
        actual,
        pass: actual.verdict === expected.verdict && actual.reason === canonicalReason(expected.reason),
        reason: actual.reason,
      };
    },
  },
  {
    id: "bound-meet",
    title: "BoundMeet",
    description: "27 bound-intersection vectors",
    file: "vectors/bound-meet.json",
    run(v) {
      const expected = v.expect as Json;
      try {
        const got = clc.intersect(v.sources as Grant[]);
        return {
          actual: got,
          pass: !expected.reason &&
            jsonEqual(got.params ?? {}, expected.params ?? {}) &&
            jsonEqual(got.param_bounds ?? {}, expected.param_bounds ?? {}),
        };
      } catch (error) {
        const reason = canonicalReason((error as Error).message);
        return {
          actual: { error: (error as Error).message },
          pass: reason === canonicalReason(expected.reason),
          reason,
        };
      }
    },
  },
  {
    id: "resolve",
    title: "Resolve",
    description: "26 obligation-resolution vectors",
    file: "vectors/resolve.json",
    run(v) {
      const got = clc.resolve(
        v.decision as Decision,
        (v.resolutions ?? []) as Resolution[],
        typeof v.now === "string" ? v.now : undefined,
      );
      const expected = v.expect as Json;
      let pass = got.verdict === expected.verdict &&
        canonicalReason(got.reason) === canonicalReason(expected.reason);
      if ("unresolved" in expected) pass = pass && jsonEqual(got.unresolved ?? [], expected.unresolved ?? []);
      return { actual: got, pass, reason: canonicalReason(got.reason) };
    },
  },
  {
    id: "constraint-union",
    title: "ConstraintUnion",
    description: "12 chain-constraint union vectors",
    file: "vectors/constraint-union.json",
    run(v) {
      const expected = v.expect as Json;
      try {
        const got = clc.constraintUnion(v.chain as Grant[]);
        return { actual: got, pass: !expected.reason && jsonEqual(got, expected.union ?? []) };
      } catch (error) {
        const reason = canonicalReason((error as Error).message);
        return {
          actual: { error: (error as Error).message },
          pass: reason === canonicalReason(expected.reason),
          reason,
        };
      }
    },
  },
];

const templates: Record<string, Json> = {
  authorizeSet: {
    grants: [{ id: "std/database-v1:query:SELECT", params: { limit: 100 } }],
    operation: { id: "std/database-v1:query:SELECT", params: { limit: 50 } },
    expect: { verdict: "allow" },
  },
  entails: {
    grant: { id: "std/database-v1:query:SELECT", params: { limit: 100 } },
    operation: { id: "std/database-v1:query:SELECT", params: { limit: 50 } },
    expect: { entails: true },
  },
  contains: {
    parent: { id: "std/database-v1:query:*", params: { limit: 100 } },
    child: { id: "std/database-v1:query:SELECT", params: { limit: 50 } },
    expect: { contains: true },
  },
  intersect: {
    sources: [
      { id: "std/database-v1:query:*", params: { limit: 100 } },
      { id: "std/database-v1:query:SELECT", params: { limit: 50 } },
    ],
    expect: { params: { limit: 50 } },
  },
  resolve: {
    decision: {
      verdict: "allow_unresolved",
      unresolved: ['varwof/constraint-v1:time:window:[{"start":"00:00","end":"01:00"}]'],
    },
    resolutions: [],
    now: "2026-10-19T12:00:00Z",
    expect: { verdict: "deny", reason: "time:violated" },
  },
  constraintUnion: {
    chain: [
      { id: "std/database-v1:query:*", constraints: ["varwof/constraint-v1:max_rows:100"] },
      { id: "std/database-v1:query:SELECT", constraints: ["varwof/constraint-v1:network:10.0.0.0/8"] },
    ],
    expect: {
      union: ["varwof/constraint-v1:max_rows:100", "varwof/constraint-v1:network:10.0.0.0/8"],
    },
  },
  authorizeWithChain: {
    chain: [
      { id: "std/database-v1:query:*", params: { limit: 100 } },
      { id: "std/database-v1:query:SELECT", params: { limit: 50 } },
    ],
    operation: { id: "std/database-v1:query:SELECT", params: { limit: 25 } },
    expect: { verdict: "allow" },
  },
  record: {
    grants: [{ id: "std/database-v1:query:SELECT", params: { limit: 100 } }],
    operation: { id: "std/database-v1:query:SELECT", params: { limit: 50 } },
  },
};

function setTemplate(): void {
  editor.value = JSON.stringify(templates[functionSelect.value], null, 2);
}

function pill(ok: boolean): HTMLElement {
  const value = document.createElement("span");
  value.className = `pill ${ok ? "ok" : "bad"}`;
  value.textContent = ok ? "PASS" : "FAIL";
  return value;
}

function pre(value: unknown): HTMLElement {
  const node = document.createElement("pre");
  node.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return node;
}

function renderSummary(pass: number, total: number, label: string): void {
  summary.replaceChildren();
  summary.append(pill(pass === total));
  const text = document.createElement("span");
  text.textContent = `${label}: ${pass}/${total} passed`;
  summary.append(text);
}

function renderEvidence(): void {
  result.replaceChildren();
  const pass = evidence.filter((item) => item.pass).length;
  renderSummary(pass, evidence.length, evidenceName);
  const table = document.createElement("table");
  table.className = "evidence-table";
  const head = document.createElement("tr");
  for (const label of ["Case", "Result", "Expected", "Actual", "Reason"]) {
    const th = document.createElement("th");
    th.textContent = label;
    head.append(th);
  }
  table.append(head);
  for (const item of evidence) {
    const row = document.createElement("tr");
    row.append(
      Object.assign(document.createElement("td"), { textContent: item.id }),
    );
    const status = document.createElement("td");
    status.append(pill(item.pass));
    row.append(status);
    row.append(Object.assign(document.createElement("td"), { textContent: JSON.stringify(item.expected) }));
    row.append(Object.assign(document.createElement("td"), { textContent: JSON.stringify(item.actual) }));
    row.append(Object.assign(document.createElement("td"), { textContent: item.reason || "—" }));
    table.append(row);
  }
  const list = document.createElement("div");
  list.className = "evidence-list";
  list.append(table);
  const details = document.createElement("details");
  const detailSummary = document.createElement("summary");
  detailSummary.textContent = "每案证据 / per-vector evidence";
  details.append(detailSummary, pre(evidence));
  list.append(details);
  result.append(list);
  download.disabled = evidence.length === 0;
}

async function runOfficialSuite(): Promise<void> {
  const suite = suites.find((item) => item.id === suiteSelect.value);
  if (!suite) return;
  summary.textContent = `Loading ${suite.title}…`;
  const response = await fetch(suite.file);
  if (!response.ok) throw new Error(`cannot load ${suite.file}: HTTP ${response.status}`);
  const vectors = (await response.json()) as SuiteVector[];
  evidence = vectors.map((vector) => {
    try {
      const got = suite.run(vector);
      return {
        suite: suite.id,
        id: vector.id,
        expected: vector.expect ?? null,
        actual: got.actual,
        pass: got.pass,
        reason: got.reason ?? "",
        derivation: vector.derivation ?? "",
        input: vector,
      };
    } catch (error) {
      return {
        suite: suite.id,
        id: vector.id,
        expected: vector.expect ?? null,
        actual: { error: (error as Error).message },
        pass: false,
        reason: "exception",
        derivation: vector.derivation ?? "",
        input: vector,
      };
    }
  });
  evidenceName = suite.title;
  renderEvidence();
}

function runCustomFunction(kind: string, input: Json): unknown {
  switch (kind) {
    case "authorizeSet":
      return clc.authorizeSet((input.grants ?? []) as Grant[], input.operation as Operation);
    case "entails":
      return clc.entails(input.grant as Grant, input.operation as Operation);
    case "contains":
      return clc.contains(input.parent as Grant, input.child as Grant);
    case "intersect":
      return clc.intersect((input.sources ?? []) as Grant[]);
    case "resolve":
      return clc.resolve(
        input.decision as Decision,
        (input.resolutions ?? []) as Resolution[],
        typeof input.now === "string" ? input.now : undefined,
      );
    case "constraintUnion":
      return clc.constraintUnion((input.chain ?? []) as Grant[]);
    case "authorizeWithChain":
      return clc.authorizeWithChain((input.chain ?? []) as Grant[], input.operation as Operation);
    case "record":
      return clc.record((input.grants ?? []) as Grant[], input.operation as Operation);
    default:
      throw new Error(`unknown function ${kind}`);
  }
}

function matchesCustomExpectation(kind: string, expect: Json, actual: unknown): boolean {
  if (kind === "authorizeSet" || kind === "authorizeWithChain") {
    const got = actual as Decision;
    if ("verdict" in expect && got.verdict !== expect.verdict) return false;
    if ("reason" in expect && canonicalReason(got.reason) !== canonicalReason(expect.reason)) return false;
    if ("unresolved" in expect && !jsonEqual(got.unresolved ?? [], expect.unresolved ?? [])) return false;
    return true;
  }
  if (kind === "entails" || kind === "contains") {
    const got = actual as { entails?: boolean; contains?: boolean; reason?: string };
    if ("entails" in expect && got.entails !== expect.entails) return false;
    if ("contains" in expect && got.contains !== expect.contains) return false;
    if ("reason" in expect && canonicalReason(got.reason) !== canonicalReason(expect.reason)) return false;
    return true;
  }
  if (kind === "intersect") {
    const got = actual as Grant;
    if ("params" in expect && !jsonEqual(got.params ?? {}, expect.params ?? {})) return false;
    if ("param_bounds" in expect && !jsonEqual(got.param_bounds ?? {}, expect.param_bounds ?? {})) return false;
    if ("constraints" in expect && !jsonEqual(got.constraints ?? [], expect.constraints ?? [])) return false;
    return true;
  }
  if (kind === "resolve") {
    const got = actual as Decision;
    if ("verdict" in expect && got.verdict !== expect.verdict) return false;
    if ("reason" in expect && canonicalReason(got.reason) !== canonicalReason(expect.reason)) return false;
    if ("unresolved" in expect && !jsonEqual(got.unresolved ?? [], expect.unresolved ?? [])) return false;
    return true;
  }
  if (kind === "constraintUnion") {
    const got = actual as string[];
    return !("union" in expect) || jsonEqual(got, expect.union ?? []);
  }
  if (kind === "record") {
    const got = actual as Json;
    return Object.entries(expect).every(([key, value]) => jsonEqual(got[key], value));
  }
  return jsonEqual(expect, actual);
}

function runCustom(): void {
  summary.textContent = "Running custom vector…";
  const input = JSON.parse(editor.value) as Json;
  let actual: unknown;
  let pass = true;
  let reason = "";
  try {
    actual = runCustomFunction(functionSelect.value, input);
    if (input.expect && typeof input.expect === "object") {
      pass = matchesCustomExpectation(functionSelect.value, input.expect as Json, actual);
    }
    reason = typeof (actual as Json)?.reason === "string"
      ? canonicalReason((actual as Json).reason)
      : "";
  } catch (error) {
    actual = { error: (error as Error).message };
    pass = false;
    reason = canonicalReason((error as Error).message);
  }
  evidence = [{
    suite: "custom",
    id: "custom-001",
    expected: input.expect ?? null,
    actual,
    pass,
    reason,
    derivation: "",
    input: {
      function: functionSelect.value,
      clc_revision: clc.CLC_REVISION,
      canonical_input: clc.canonicalJSON(input),
      request: input,
    },
  }];
  evidenceName = `Custom ${functionSelect.value}`;
  renderEvidence();
}

function init(): void {
  const revision = document.querySelector("[data-revision]");
  if (revision) revision.textContent = clc.CLC_REVISION;
  for (const suite of suites) {
    const option = document.createElement("option");
    option.value = suite.id;
    option.textContent = `${suite.title} · ${suite.description}`;
    suiteSelect.append(option);
  }
  functionSelect.append(...Object.keys(templates).map((name) => {
    const option = document.createElement("option");
    option.value = name;
    option.textContent = name;
    return option;
  }));
  functionSelect.addEventListener("change", setTemplate);
  setTemplate();
  runSuiteButton.addEventListener("click", () => void runOfficialSuite().catch((error) => {
    summary.textContent = (error as Error).message;
  }));
  runCustomButton.addEventListener("click", runCustom);
  download.addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(evidence, null, 2)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = evidenceName.replace(/\W+/g, "-").toLowerCase() + "-evidence.json";
    link.click();
    URL.revokeObjectURL(link.href);
  });
  app.dataset.ready = "true";
  app.dataset.revision = clc.CLC_REVISION;
  app.dataset.suites = String(suites.length);
  const requestedSuite = new URLSearchParams(location.search).get("suite");
  if (requestedSuite && suites.some((suite) => suite.id === requestedSuite)) {
    suiteSelect.value = requestedSuite;
    void runOfficialSuite();
  }
}

init();

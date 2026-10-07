// P07-D6 / N-06: the packaged legacy input image renders its CSP connect-src
// from the origin it was built for, so the header always matches the bundle
// and a release cannot ship a loopback origin.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const script = path.join(root, "scripts/render-nginx-conf.mjs");
const template = path.join(root, "nginx.conf.template");

function render(origin, ...flags) {
  const directory = mkdtempSync(path.join(tmpdir(), "blindpass-nginx-"));
  try {
    const output = path.join(directory, "default.conf");
    const result = spawnSync(process.execPath, [script, template, origin, output, ...flags], { encoding: "utf8" });
    return { status: result.status, stderr: result.stderr, text: result.status === 0 ? readFileSync(output, "utf8") : null };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

/** The directive values of the Content-Security-Policy add_header, parsed. */
function csp(config) {
  const line = config.split("\n").find((entry) => entry.includes("add_header Content-Security-Policy"));
  assert.ok(line, "no CSP add_header");
  const value = line.match(/add_header Content-Security-Policy "([^"]*)"/)?.[1];
  assert.ok(value, "CSP value not quoted");
  return Object.fromEntries(value.split(";").map((part) => part.trim()).filter(Boolean).map((part) => {
    const [name, ...sources] = part.split(/\s+/);
    return [name, sources];
  }));
}

test("the checked-in template carries no origin of its own", () => {
  const text = readFileSync(template, "utf8");
  assert.ok(text.includes("__CONNECT_SRC__"));
  assert.ok(!/127\.0\.0\.1|localhost/.test(text), "a loopback origin is baked into the template");
});

test("an https API origin becomes the only extra connect-src source", () => {
  const { status, text } = render("https://controller.example");
  assert.equal(status, 0);
  const policy = csp(text);
  assert.deepEqual(policy["connect-src"], ["'self'", "https://controller.example"]);
  assert.deepEqual(policy["default-src"], ["'none'"]);
  assert.deepEqual(policy["frame-ancestors"], ["'none'"]);
  assert.ok(!text.includes("__CONNECT_SRC__"));
  for (const [directive, sources] of Object.entries(policy)) {
    for (const source of sources) {
      assert.ok(!/^(https?|wss?):$/.test(source) && source !== "*", `${directive} admits ${source}`);
      assert.ok(!/localhost|127\.0\.0\.1|\[::1\]/.test(source), `${directive} names loopback ${source}`);
      assert.ok(!/unsafe-(inline|eval)/.test(source), `${directive} has ${source}`);
    }
  }
});

test("a path, userinfo, wildcard, other scheme or plain http origin is refused", () => {
  for (const origin of [
    "https://controller.example/api",
    "https://user:pass@controller.example",
    "https://*.example",
    "*",
    "https:",
    "ws://controller.example",
    "http://controller.example",
    "ftp://controller.example",
    "controller.example",
    "https://controller.example; script-src *"
  ]) {
    const { status, stderr } = render(origin);
    assert.notEqual(status, 0, `${origin} was accepted`);
    assert.ok(!stderr.includes("pass@"), "credentials echoed");
  }
});

test("an empty origin means same-origin only", () => {
  const { status, text } = render("");
  assert.equal(status, 0);
  assert.deepEqual(csp(text)["connect-src"], ["'self'"]);
});

test("loopback is refused unless the build says it is a development image", () => {
  assert.notEqual(render("http://127.0.0.1:3100").status, 0);
  assert.notEqual(render("http://localhost:3100").status, 0);
  assert.notEqual(render("https://localhost").status, 0);
  const allowed = render("http://127.0.0.1:3100", "--allow-loopback");
  assert.equal(allowed.status, 0);
  assert.deepEqual(csp(allowed.text)["connect-src"], ["'self'", "http://127.0.0.1:3100"]);
});

test("the server still sets framing, referrer, opener and type headers", () => {
  const { text } = render("https://controller.example");
  for (const header of ["Cross-Origin-Opener-Policy", "Referrer-Policy", "X-Content-Type-Options", "X-Frame-Options", "Permissions-Policy", "Cache-Control"]) {
    assert.ok(text.includes(`add_header ${header} `), header);
  }
  assert.ok(!/Strict-Transport-Security/i.test(text), "HSTS belongs to the TLS terminator");
});

test("the Dockerfile renders the config from the build origin instead of copying a fixed file", () => {
  const dockerfile = readFileSync(path.join(root, "Dockerfile"), "utf8");
  assert.ok(dockerfile.includes("render-nginx-conf.mjs"));
  assert.ok(!/COPY\s+packages\/browser-ui\/nginx\.conf\s/.test(dockerfile));
  assert.ok(/COPY --from=build [^\n]*default\.conf/.test(dockerfile));
  assert.equal(typeof execFileSync, "function");
});

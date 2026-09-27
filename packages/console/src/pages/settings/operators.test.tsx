import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { axeViolations } from "../../test/axe.js";
import { fakeController, json, renderRoute } from "../../test/controller.js";
import { HOSTILE } from "../../test/fixtures.js";

type Row = { id: string; username: string; display_name: string; role: "admin" | "operator" | "viewer"; disabled_at: null };

const ADA: Row = { id: "op_ada", username: "ada", display_name: "Ada", role: "admin", disabled_at: null };
const RINA: Row = { id: "op_rina", username: "rina", display_name: "Rina", role: "operator", disabled_at: null };
const TEMP = "tmp-9f3c1b7e2d4a6c8e0f1a2b3c";

function operatorsList(rows: Row[]) {
  return (call: { method: string; path: string }) => (call.method === "GET" && call.path === "/api/v3/admin/operators" ? json(200, { items: rows, next_cursor: null }) : undefined);
}

describe("settings / operators", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("DR settings: the only administrator can't be demoted or removed; the controls say why and send nothing", async () => {
    const { calls } = fakeController({ handler: operatorsList([ADA, RINA]) });
    const user = userEvent.setup();
    const { container } = renderRoute("/settings/operators");
    const row = await screen.findByRole("row", { name: /Ada/ });
    const role = within(row).getByRole("button", { name: "Change role for ada" }) as HTMLButtonElement;
    const remove = within(row).getByRole("button", { name: "Remove ada" }) as HTMLButtonElement;
    expect(role.disabled).toBe(true);
    expect(remove.disabled).toBe(true);
    const reason = "The controller must keep one active administrator. Make another operator an administrator first.";
    expect(document.getElementById(role.getAttribute("aria-describedby")!)?.textContent).toBe(reason);
    expect(document.getElementById(remove.getAttribute("aria-describedby")!)?.textContent).toBe(reason);
    await user.click(role);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(calls.some((call) => call.method !== "GET")).toBe(false);
    // The signed-in admin is marked, and another operator's controls are live.
    expect(within(row).getByText("You")).toBeTruthy();
    const other = screen.getByRole("row", { name: /Rina/ });
    expect((within(other).getByRole("button", { name: "Remove rina" }) as HTMLButtonElement).disabled).toBe(false);
    expect(await axeViolations(container)).toEqual([]);
  });

  it("create issues a server temporary password that forces a change; the console's throwaway password never renders", async () => {
    let rows = [ADA];
    const { calls } = fakeController({
      handler: (call) => {
        if (call.method === "POST" && call.path === "/api/v3/admin/operators") {
          rows = [...rows, { id: "op_new", username: "sam", display_name: "Sam Lee", role: "viewer", disabled_at: null }];
          return json(201, rows.at(-1));
        }
        if (call.path === "/api/v3/admin/operators/op_new/reset-password") return json(200, { temporary_password: TEMP });
        return operatorsList(rows)(call);
      }
    });
    const user = userEvent.setup();
    renderRoute("/settings/operators");
    await user.click(await screen.findByRole("button", { name: "Add operator" }));
    const dialog = await screen.findByRole("dialog", { name: "Add an operator" });
    await user.click(within(dialog).getByRole("button", { name: "Create and show password" }));
    expect(within(dialog).getByText(/3–128 letters, digits/)).toBeTruthy();
    await user.type(within(dialog).getByLabelText("Username"), "sam");
    await user.type(within(dialog).getByLabelText("Display name"), "Sam Lee");
    await user.click(within(dialog).getByRole("radio", { name: /Viewer/ }));
    await user.click(within(dialog).getByRole("button", { name: "Create and show password" }));

    const reveal = await screen.findByRole("dialog", { name: "Temporary password for sam" });
    expect(reveal.querySelector("[data-secret-reveal]")?.textContent).toBe(TEMP);
    expect(reveal.textContent).toContain("must choose a new password");
    const created = calls.find((call) => call.method === "POST" && call.path === "/api/v3/admin/operators")!;
    const body = created.body as { username: string; display_name: string; role: string; password: string };
    expect(body).toMatchObject({ username: "sam", display_name: "Sam Lee", role: "viewer" });
    expect(body.password.length).toBeGreaterThanOrEqual(32);
    expect(document.body.textContent).not.toContain(body.password);
    const order = calls.filter((call) => call.method === "POST").map((call) => call.path);
    expect(order).toEqual(["/api/v3/admin/operators", "/api/v3/admin/operators/op_new/reset-password"]);

    await user.click(within(reveal).getByLabelText("I stored this value somewhere safe"));
    await user.click(within(reveal).getByRole("button", { name: "Done" }));
    expect(await screen.findByRole("row", { name: /Sam Lee/ })).toBeTruthy();
    expect(document.body.textContent).not.toContain(TEMP);
  });

  it("if the temporary password can't be issued after create, the operator is flagged with a retry and no usable password is implied", async () => {
    let fail = true;
    fakeController({
      handler: (call) => {
        if (call.method === "POST" && call.path === "/api/v3/admin/operators") return json(201, { id: "op_new", username: "sam", display_name: "Sam", role: "operator", disabled_at: null });
        if (call.path === "/api/v3/admin/operators/op_new/reset-password") return fail ? json(500, { error: "internal" }) : json(200, { temporary_password: TEMP });
        return operatorsList([ADA])(call);
      }
    });
    const user = userEvent.setup();
    renderRoute("/settings/operators");
    await user.click(await screen.findByRole("button", { name: "Add operator" }));
    const dialog = await screen.findByRole("dialog", { name: "Add an operator" });
    await user.type(within(dialog).getByLabelText("Username"), "sam");
    await user.type(within(dialog).getByLabelText("Display name"), "Sam");
    await user.click(within(dialog).getByRole("button", { name: "Create and show password" }));
    expect(await within(dialog).findByText("sam was created, but no password was issued")).toBeTruthy();
    expect(within(dialog).getByText(/can't sign in until you issue one/)).toBeTruthy();
    fail = false;
    await user.click(within(dialog).getByRole("button", { name: "Issue temporary password" }));
    expect(await screen.findByRole("dialog", { name: "Temporary password for sam" })).toBeTruthy();
  });

  it("role change shows current and new role, sends only the role and reports a lost last-admin race", async () => {
    const other: Row = { ...RINA, role: "admin" };
    const { calls } = fakeController({
      handler: (call) => {
        if (call.method === "PATCH") return json(409, { error: "last_admin_required", message: "the instance must retain an active administrator" });
        return operatorsList([ADA, other])(call);
      }
    });
    const user = userEvent.setup();
    renderRoute("/settings/operators");
    await user.click(await screen.findByRole("button", { name: "Change role for rina" }));
    const dialog = await screen.findByRole("dialog", { name: "Change rina's role" });
    const submit = within(dialog).getByRole("button", { name: "Change role" }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    await user.click(within(dialog).getByRole("radio", { name: /Viewer/ }));
    expect(within(dialog).getByText("Administrator → Viewer")).toBeTruthy();
    expect(within(dialog).getByText(/takes effect on their open sessions immediately/)).toBeTruthy();
    await user.click(submit);
    expect(await within(dialog).findByText(/must keep one active administrator/)).toBeTruthy();
    expect(calls.find((call) => call.method === "PATCH")!.body).toEqual({ role: "viewer" });
  });

  it("demoting yourself warns that you lose this page", async () => {
    fakeController({ handler: operatorsList([ADA, { ...RINA, role: "admin" }]) });
    const user = userEvent.setup();
    renderRoute("/settings/operators");
    await user.click(await screen.findByRole("button", { name: "Change role for ada" }));
    const dialog = await screen.findByRole("dialog", { name: "Change your role" });
    await user.click(within(dialog).getByRole("radio", { name: /Operator/ }));
    expect(within(dialog).getByText(/You'll lose access to operator management/)).toBeTruthy();
  });

  it("remove shows exactly who, ends their sessions and handles a record that's already gone", async () => {
    const { calls } = fakeController({
      handler: (call) => {
        if (call.method === "DELETE") return json(404, { error: "operator_not_found" });
        return operatorsList([ADA, RINA])(call);
      }
    });
    const user = userEvent.setup();
    renderRoute("/settings/operators");
    await user.click(await screen.findByRole("button", { name: "Remove rina" }));
    const dialog = await screen.findByRole("dialog", { name: "Remove rina?" });
    expect(dialog.textContent).toContain("op_rina");
    expect(dialog.textContent).toContain("Rina");
    expect(dialog.textContent).toContain("Their open sessions end immediately");
    expect((within(dialog).getByRole("button", { name: "Cancel" }) as HTMLButtonElement) === document.activeElement).toBe(true);
    await user.click(within(dialog).getByRole("button", { name: "Remove operator" }));
    expect(await within(dialog).findByText(/no longer exists/)).toBeTruthy();
    expect(calls.find((call) => call.method === "DELETE")!.path).toBe("/api/v3/admin/operators/op_rina");
  });

  it("you can't remove your own account from here", async () => {
    fakeController({ handler: operatorsList([ADA, { ...RINA, role: "admin" }]) });
    renderRoute("/settings/operators");
    const row = await screen.findByRole("row", { name: /Ada/ });
    const remove = within(row).getByRole("button", { name: "Remove ada" }) as HTMLButtonElement;
    expect(remove.disabled).toBe(true);
    expect(document.getElementById(remove.getAttribute("aria-describedby")!)?.textContent).toMatch(/another administrator/);
  });

  it("operator names are untrusted text", async () => {
    const { container } = (fakeController({ handler: operatorsList([ADA, { ...RINA, display_name: HOSTILE }]) }), renderRoute("/settings/operators"));
    expect(await screen.findByText(HOSTILE)).toBeTruthy();
    expect(container.querySelector("main img, main b")).toBeNull();
  });

  it("operators and viewers get the role page for /settings/operators and no Operators link", async () => {
    const { calls } = fakeController({ role: "operator", handler: () => undefined });
    renderRoute("/settings/operators");
    expect(await screen.findByRole("heading", { name: "Your role can't open this page" })).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Operators" })).toBeNull();
    await waitFor(() => expect(calls.some((call) => call.path === "/api/v3/admin/operators")).toBe(false));
  });
});

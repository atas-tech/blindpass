import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client.js";
import { axeViolations } from "../test/axe.js";
import { Button } from "./button.js";
import { Dialog } from "./dialog.js";
import { EmptyState, ErrorState, Notice, StatusBadge } from "./feedback.js";
import { Checkbox, SelectField, TextField } from "./field.js";
import { KeyValue, SegmentedControl, UntrustedText, VerifiedBlock } from "./layout.js";

function DialogHarness({ onConfirm = () => undefined }: { onConfirm?: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button onClick={() => setOpen(true)}>Open dialog</Button>
      <Dialog
        open={open}
        title="Revoke grant"
        description="The node must reconnect to receive it."
        onClose={() => setOpen(false)}
        footer={
          <>
            <Button onClick={() => setOpen(false)}>Cancel</Button>
            <Button variant="danger" onClick={onConfirm}>
              Revoke
            </Button>
          </>
        }
      >
        <p>Scope details</p>
      </Dialog>
    </>
  );
}

describe("primitives", () => {
  it("form fields associate labels, hints and errors", async () => {
    const { container } = render(
      <form>
        <TextField label="Username" hint="Letters and digits" error="Use at least 3 characters." />
        <SelectField label="Role" defaultValue="viewer">
          <option value="viewer">Viewer</option>
        </SelectField>
        <Checkbox label="Require approval" hint="Approvers must be named" />
      </form>
    );
    const input = screen.getByLabelText("Username");
    expect(input.getAttribute("aria-invalid")).toBe("true");
    const described = input.getAttribute("aria-describedby")?.split(" ") ?? [];
    expect(described).toHaveLength(2);
    expect(described.map((id) => document.getElementById(id)?.textContent)).toEqual(["Letters and digits", "Use at least 3 characters."]);
    expect(screen.getByLabelText("Role")).toBeTruthy();
    expect(screen.getByLabelText("Require approval").getAttribute("type")).toBe("checkbox");
    expect(await axeViolations(container)).toEqual([]);
  });

  it("status badges carry words, not colour alone", () => {
    render(<StatusBadge tone="warn">Revocation queued</StatusBadge>);
    expect(screen.getByText("Revocation queued")).toBeTruthy();
  });

  it("a failed read renders an error with retry, never an empty result", async () => {
    const retry = vi.fn();
    const { container } = render(<ErrorState error={new ApiError(0, "timeout", "late")} onRetry={retry} />);
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("didn't answer in time");
    expect(alert.textContent).not.toMatch(/\b0\b|no pending|none/i);
    await userEvent.click(within(alert).getByRole("button", { name: "Try again" }));
    expect(retry).toHaveBeenCalledOnce();
    expect(await axeViolations(container)).toEqual([]);
  });

  it("a forbidden read does not offer a pointless retry", () => {
    render(<ErrorState error={new ApiError(403, "role_denied", "no")} onRetry={() => undefined} />);
    expect(screen.queryByRole("button", { name: "Try again" })).toBeNull();
    expect(screen.getByRole("alert").dataset.errorKind).toBe("forbidden");
  });

  it("dialogs move focus in, close on Escape and return focus to the opener", async () => {
    const user = userEvent.setup();
    render(<DialogHarness />);
    const opener = screen.getByRole("button", { name: "Open dialog" });
    await user.click(opener);
    const dialog = screen.getByRole("dialog", { name: "Revoke grant" });
    expect(dialog.hasAttribute("open")).toBe(true);
    expect(dialog.contains(document.activeElement)).toBe(true);
    dialog.dispatchEvent(new Event("cancel", { cancelable: true }));
    await vi.waitFor(() => expect(dialog.hasAttribute("open")).toBe(false));
    expect(document.activeElement).toBe(opener);
  });

  it("busy buttons announce state and block repeat clicks", async () => {
    const click = vi.fn();
    render(
      <Button busy onClick={click}>
        Approve
      </Button>
    );
    const button = screen.getByRole("button", { name: "Approve" });
    expect(button.getAttribute("aria-busy")).toBe("true");
    expect((button as HTMLButtonElement).disabled).toBe(true);
    await userEvent.click(button);
    expect(click).not.toHaveBeenCalled();
  });

  it("segmented controls behave as a radio group with arrow keys", async () => {
    const user = userEvent.setup();
    function Harness() {
      const [value, setValue] = useState<"pending" | "approved" | "rejected">("pending");
      return (
        <SegmentedControl
          label="Status"
          value={value}
          onChange={setValue}
          options={[
            { value: "pending", label: "Pending" },
            { value: "approved", label: "Approved" },
            { value: "rejected", label: "Rejected" }
          ]}
        />
      );
    }
    const { container } = render(<Harness />);
    const pending = screen.getByRole("radio", { name: "Pending" });
    expect(pending.getAttribute("aria-checked")).toBe("true");
    pending.focus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("radio", { name: "Approved" }).getAttribute("aria-checked")).toBe("true");
    expect(document.activeElement).toBe(screen.getByRole("radio", { name: "Approved" }));
    await user.keyboard("{ArrowLeft}{ArrowLeft}");
    expect(screen.getByRole("radio", { name: "Rejected" }).getAttribute("aria-checked")).toBe("true");
    expect(await axeViolations(container)).toEqual([]);
  });

  it("untrusted text renders markup as inert text", () => {
    const hostile = '<img src=x onerror="alert(1)"> **bold** [link](javascript:alert(1))';
    const { container } = render(<UntrustedText label="Requester-provided purpose">{hostile}</UntrustedText>);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("a")).toBeNull();
    expect(container.querySelector("strong")).toBeNull();
    expect(screen.getByText(hostile)).toBeTruthy();
    expect(screen.getByText("Not verified")).toBeTruthy();
  });

  it("O05: untrusted text shows bidi overrides and terminal escapes instead of applying them, and is isolated from its surroundings", () => {
    const { container } = render(<UntrustedText label="Requester-provided purpose">{"Rotate \u202Etxt.yek\u001b[2J"}</UntrustedText>);
    const quote = container.querySelector("blockquote")!;
    expect(quote.textContent).toBe("Rotate ⟨U+202E⟩txt.yek⟨U+001B⟩[2J");
    expect(quote.getAttribute("dir")).toBe("auto");
  });

  it("composite surfaces pass axe", async () => {
    const { container } = render(
      <main>
        <VerifiedBlock title="Verified by the controller">
          <KeyValue items={[{ label: "Node", value: "build-01" }, { label: "Unit", value: "deploy.service" }]} />
        </VerifiedBlock>
        <Notice tone="warn" title="Revocation queued">
          The node must reconnect to receive it.
        </Notice>
        <EmptyState title="No pending approvals" />
      </main>
    );
    expect(await axeViolations(container)).toEqual([]);
  });
});

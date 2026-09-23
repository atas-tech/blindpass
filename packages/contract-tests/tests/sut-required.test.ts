import { describe, expect, it } from "vitest";

describe("P00 contract execution configuration", () => {
  it("requires an explicit server under test", () => {
    expect(["ts", "base", "rust"]).toContain(process.env.SUT);
  });
});

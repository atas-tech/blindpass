import { describe, expect, it } from "vitest";

describe("P00 contract execution configuration", () => {
  it("requires an explicit server under test", () => {
    expect(process.env.SUT).toBe("rust");
  });
});

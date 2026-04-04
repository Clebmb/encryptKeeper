import { describe, expect, test } from "vitest";
import { normalizeNoteName } from "./noteName";

describe("normalizeNoteName", () => {
  test("adds gpg extension when missing", () => {
    expect(normalizeNoteName("secret")).toBe("secret.gpg");
  });

  test("rejects traversal", () => {
    expect(() => normalizeNoteName("../secret")).toThrow(/Parent directory/);
  });
});

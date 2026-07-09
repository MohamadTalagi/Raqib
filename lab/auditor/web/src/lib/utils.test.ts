import { describe, expect, it } from "vitest";
import { cn } from "./utils";

describe("cn", () => {
  it("merges class names and drops falsy values", () => {
    expect(cn("a", false, undefined, "b")).toBe("a b");
  });

  it("lets tailwind-merge resolve conflicting utility classes", () => {
    expect(cn("p-2", "p-4")).toBe("p-4");
  });
});

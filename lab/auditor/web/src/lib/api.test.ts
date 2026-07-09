import { afterEach, describe, expect, it, vi } from "vitest";

describe("resolveApiBaseUrl (via api module's derived base URL)", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it("falls back to the page's own host:8000 when VITE_API_URL is not set at build time", async () => {
    vi.stubEnv("VITE_API_URL", "");
    vi.stubGlobal("location", { protocol: "http:", hostname: "100.99.182.30" });
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(new Response("{}", { status: 200 }))),
    );

    vi.resetModules();
    const { api } = await import("./api");
    await api.summary();

    expect(fetch).toHaveBeenCalledWith("http://100.99.182.30:8000/summary");
  });

  it("still honors an explicit VITE_API_URL override when one is configured", async () => {
    vi.stubEnv("VITE_API_URL", "https://api.example.internal");
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(new Response("{}", { status: 200 }))),
    );

    vi.resetModules();
    const { api } = await import("./api");
    await api.summary();

    expect(fetch).toHaveBeenCalledWith("https://api.example.internal/summary");
  });
});

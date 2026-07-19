import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./api";

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

describe("device api", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("posts a device and returns the created record", async () => {
    const created = { device_id: "test-camera", registered: true, services: [] };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 201,
        json: async () => created,
      }),
    );

    const result = await api.createDevice({
      device_id: "test-camera",
      display_name: "Test Camera",
      tier: "insecure",
      host: "test-camera",
      services: [{ service_type: "http", port: 80, published_port: 8091 }],
    });

    expect(result.device_id).toBe("test-camera");
  });

  it("throws a field-tagged error on 400 so the form can highlight the field", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({ field: "host", detail: "IP must be inside 172.30.0.0/24" }),
      }),
    );

    await expect(
      api.createDevice({
        device_id: "bad",
        display_name: "Bad",
        tier: "unknown",
        host: "10.0.0.5",
        services: [{ service_type: "http", port: 80, published_port: null }],
      }),
    ).rejects.toMatchObject({ field: "host", message: "IP must be inside 172.30.0.0/24" });
  });

  it("fetches a single device detail", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ device: { device_id: "d1" }, evidence: [], verdicts: [] }),
      }),
    );

    const detail = await api.device("d1");

    expect(detail.device.device_id).toBe("d1");
  });
});

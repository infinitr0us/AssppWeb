import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildPlist } from "../../src/apple/plist";
import { authenticate } from "../../src/apple/authenticate";
import { appleRequest } from "../../src/apple/request";
import { fetchBag } from "../../src/apple/bag";
import { prepareSigner } from "../../src/apple/sap/client";

vi.mock("../../src/apple/request", () => ({
  appleRequest: vi.fn(),
}));

vi.mock("../../src/apple/bag", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/apple/bag")>()),
  fetchBag: vi.fn(),
}));

vi.mock("../../src/apple/sap/client", () => ({
  prepareSigner: vi.fn(),
}));

// The transient-retry loop (#93) and SAP signing (#89) meet in authenticate():
// every replayed request must carry a signature computed for that attempt.
describe("apple/authenticate SAP signing with transient retries", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    vi.mocked(fetchBag).mockResolvedValue({
      authURL:
        "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate",
      sapEndpoints: {
        setupURL: "https://buy.itunes.apple.com/sign-sap-setup",
        certificateURL: "https://s.mzstatic.com/sap-cert",
        version: 200,
      },
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("signs each replay of a transient response afresh", async () => {
    let signatures = 0;
    const sign = vi.fn(async () => `signature-${++signatures}`);
    vi.mocked(prepareSigner).mockResolvedValue({ sign } as any);
    vi.mocked(appleRequest)
      .mockResolvedValueOnce({
        status: 204,
        statusText: "",
        headers: {},
        rawHeaders: [],
        body: "",
      })
      .mockResolvedValueOnce({
        status: 200,
        statusText: "OK",
        headers: {},
        rawHeaders: [],
        body: buildPlist({
          accountInfo: { address: {} },
          passwordToken: "token",
          dsPersonId: "123",
        }),
      });

    const account = authenticate(
      "test@example.com",
      "password",
      undefined,
      undefined,
      "aabbccddeeff",
    );
    await vi.advanceTimersByTimeAsync(10_000);

    await expect(account).resolves.toMatchObject({ passwordToken: "token" });
    expect(prepareSigner).toHaveBeenCalledTimes(1);
    expect(sign).toHaveBeenCalledTimes(2);
    const calls = vi.mocked(appleRequest).mock.calls;
    expect(calls).toHaveLength(2);
    expect(calls[0][0].headers?.["X-Apple-ActionSignature"]).toBe("signature-1");
    expect(calls[1][0].headers?.["X-Apple-ActionSignature"]).toBe("signature-2");
    // #91: the legacy MZFinance endpoint gains its trailing slash.
    expect(calls[0][0]).toMatchObject({
      host: "buy.itunes.apple.com",
      path: "/WebObjects/MZFinance.woa/wa/authenticate/?guid=aabbccddeeff",
    });
  });
});

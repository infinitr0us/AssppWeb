import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../src/i18n';
import { buildPlist } from '../../src/apple/plist';
import { authenticate } from '../../src/apple/authenticate';
import { appleRequest } from '../../src/apple/request';
import { fetchBag } from '../../src/apple/bag';

vi.mock('../../src/apple/sap', () => ({
  connectSAP: vi.fn(async () => ({ sign: async () => Uint8Array.of(1, 2, 3) })),
}));

vi.mock('../../src/apple/request', () => ({
  appleRequest: vi.fn(),
}));

vi.mock('../../src/apple/bag', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/apple/bag')>()),
  fetchBag: vi.fn(),
}));

describe('apple/authenticate transient responses', () => {
  const accountReply = () => ({
    status: 200,
    statusText: 'OK',
    headers: {},
    rawHeaders: [],
    body: buildPlist({
      accountInfo: { address: {} },
      passwordToken: 'token',
      dsPersonId: '123',
    }),
  });
  const transientReply = (status: number, headers: Record<string, string> = {}) => ({
    status,
    statusText: '',
    headers,
    rawHeaders: [],
    body: '',
  });
  const login = (onRetry?: Parameters<typeof authenticate>[5]) =>
    authenticate('test@example.com', 'password', undefined, undefined, 'aabbccddeeff', onRetry);

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    vi.mocked(fetchBag).mockResolvedValue({
      authURL: 'https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/',
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('replays a 204 after 5s and reports the wait', async () => {
    vi.mocked(appleRequest).mockResolvedValueOnce(transientReply(204)).mockResolvedValueOnce(accountReply());
    const onRetry = vi.fn();

    const account = login(onRetry);
    await vi.advanceTimersByTimeAsync(5_000);

    await expect(account).resolves.toMatchObject({ passwordToken: 'token' });
    expect(appleRequest).toHaveBeenCalledTimes(2);
    expect(onRetry).toHaveBeenCalledWith({
      status: 204,
      attempt: 2,
      attempts: 5,
      delayMs: 5_000,
    });
  });

  it('backs off 5s, 10s, then 20s and gives up after five transient responses', async () => {
    vi.mocked(appleRequest).mockResolvedValue(transientReply(404));
    const onRetry = vi.fn();

    const account = login(onRetry);
    const assertion = expect(account).rejects.toThrow('404, 404, 404, 404, 404');
    await vi.advanceTimersByTimeAsync(55_000);

    await assertion;
    expect(appleRequest).toHaveBeenCalledTimes(5);
    expect(onRetry.mock.calls.map(([retry]) => retry.delayMs)).toEqual([5_000, 10_000, 20_000, 20_000]);
  });

  it('succeeds when a later attempt reaches a server that answers', async () => {
    vi.mocked(appleRequest)
      .mockResolvedValueOnce(transientReply(503))
      .mockResolvedValueOnce(transientReply(404))
      .mockResolvedValueOnce(transientReply(204))
      .mockResolvedValueOnce(accountReply());

    const account = login();
    await vi.advanceTimersByTimeAsync(35_000);

    await expect(account).resolves.toMatchObject({ passwordToken: 'token' });
    expect(appleRequest).toHaveBeenCalledTimes(4);
  });

  it('sends every sign-in attempt over a new connection', async () => {
    vi.mocked(appleRequest).mockResolvedValueOnce(transientReply(204)).mockResolvedValueOnce(accountReply());

    const account = login();
    await vi.advanceTimersByTimeAsync(5_000);

    await expect(account).resolves.toBeDefined();
    for (const [request] of vi.mocked(appleRequest).mock.calls) {
      expect(request).toMatchObject({ method: 'POST', freshConnection: true });
    }
  });

  it('waits as long as Retry-After asks, within 30s', async () => {
    vi.mocked(appleRequest)
      .mockResolvedValueOnce(transientReply(429, { 'retry-after': '5' }))
      .mockResolvedValueOnce(accountReply());
    const onRetry = vi.fn();

    const account = login(onRetry);
    await vi.advanceTimersByTimeAsync(5_000);

    await expect(account).resolves.toBeDefined();
    expect(onRetry).toHaveBeenCalledWith(expect.objectContaining({ status: 429, delayMs: 5_000 }));
  });

  it('stops when Apple asks to wait longer than 30s', async () => {
    vi.mocked(appleRequest).mockResolvedValue(transientReply(503, { 'retry-after': '120' }));

    await expect(login()).rejects.toThrow(i18n.t('errors.auth.retryLater', { seconds: 120 }));
    expect(appleRequest).toHaveBeenCalledTimes(1);
  });
});

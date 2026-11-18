import { beforeEach, describe, expect, it, vi } from 'vitest';
import { appleRequest } from '../../src/apple/request';

const { pooledFetch, sessionFetch, sessionClose, HTTPSession } = vi.hoisted(() => {
  const pooledFetch = vi.fn();
  const sessionFetch = vi.fn();
  const sessionClose = vi.fn();
  const HTTPSession = vi.fn(function (this: { fetch: unknown; close: unknown }) {
    this.fetch = sessionFetch;
    this.close = sessionClose;
  });
  return { pooledFetch, sessionFetch, sessionClose, HTTPSession };
});

vi.mock('../../src/apple/libcurl-init', () => ({
  initLibcurl: vi.fn(async () => {}),
  libcurl: { fetch: pooledFetch, HTTPSession },
}));

const reply = (status = 200, body = 'ok') => ({
  status,
  statusText: '',
  raw_headers: [['X-Test', 'yes']] as [string, string][],
  text: async () => body,
});

const request = { method: 'POST', host: 'buy.itunes.apple.com', path: '/auth', body: 'x' };

describe('apple/request connections', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('uses the shared connection pool by default', async () => {
    pooledFetch.mockResolvedValue(reply());

    const response = await appleRequest(request);

    expect(response).toMatchObject({ status: 200, body: 'ok', headers: { 'x-test': 'yes' } });
    expect(pooledFetch).toHaveBeenCalledWith(
      'https://buy.itunes.apple.com/auth',
      expect.objectContaining({ method: 'POST', redirect: 'manual', _libcurl_http_version: 1.1 }),
    );
    expect(HTTPSession).not.toHaveBeenCalled();
  });

  it('opens a private session for a fresh connection and closes it after the body', async () => {
    let bodyRead = false;
    sessionFetch.mockResolvedValue({
      ...reply(204, ''),
      text: async () => {
        bodyRead = true;
        return '';
      },
    });
    sessionClose.mockImplementation(() => expect(bodyRead).toBe(true));

    const response = await appleRequest({ ...request, freshConnection: true });

    expect(response.status).toBe(204);
    expect(HTTPSession).toHaveBeenCalledTimes(1);
    expect(sessionFetch).toHaveBeenCalledWith(
      'https://buy.itunes.apple.com/auth',
      expect.objectContaining({ method: 'POST', redirect: 'manual', _libcurl_http_version: 1.1 }),
    );
    expect(sessionClose).toHaveBeenCalledTimes(1);
    expect(pooledFetch).not.toHaveBeenCalled();
  });

  it('closes the private session when the request fails', async () => {
    sessionFetch.mockRejectedValue(new TypeError('Request failed with error code 7'));

    await expect(appleRequest({ ...request, freshConnection: true })).rejects.toThrow('error code 7');
    expect(sessionClose).toHaveBeenCalledTimes(1);
  });
});

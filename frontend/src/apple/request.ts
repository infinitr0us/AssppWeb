import { libcurl, initLibcurl } from './libcurl-init';
import { buildCookieHeader } from './cookies';
import { userAgent } from './config';
import type { Cookie } from '../types';

export interface AppleRequestOptions {
  host: string;
  path: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
  cookies?: Cookie[];
  /**
   * Send the request over a new connection instead of a kept-alive one from
   * the shared pool. Since November 2026 Apple's sign-in servers answer the
   * same request inconsistently, and a reused connection would send every
   * retry to the same server.
   */
  freshConnection?: boolean;
}

export interface AppleResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  rawHeaders: [string, string][];
  body: string;
}

export async function appleRequest(opts: AppleRequestOptions): Promise<AppleResponse> {
  await initLibcurl();

  const url = `https://${opts.host}${opts.path}`;
  const headers: Record<string, string> = {
    'User-Agent': userAgent,
    ...opts.headers,
  };

  if (opts.cookies?.length) {
    const cookieHeader = buildCookieHeader(opts.cookies, url);
    if (cookieHeader) {
      headers['Cookie'] = cookieHeader;
    }
  }

  // A private session has its own connection pool; it is closed once the body
  // has been read, so its connection is never reused.
  const session = opts.freshConnection ? new libcurl.HTTPSession() : undefined;
  try {
    const resp = await (session ?? libcurl).fetch(url, {
      method: opts.method,
      headers,
      body: opts.body,
      redirect: 'manual',
      _libcurl_http_version: 1.1,
    });

    const responseHeaders: Record<string, string> = {};
    for (const [key, value] of resp.raw_headers) {
      responseHeaders[key.toLowerCase()] = value;
    }

    const body = await resp.text();

    return {
      status: resp.status,
      statusText: resp.statusText,
      headers: responseHeaders,
      rawHeaders: resp.raw_headers,
      body,
    };
  } finally {
    session?.close();
  }
}

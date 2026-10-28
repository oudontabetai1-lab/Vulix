/**
 * api-client.js — Shared Typed API Client for Vulix UI
 *
 * Provides typed HTTP/network/decode/401 result states and AbortController
 * cancellation support to prevent stale reads from updating unmounted views.
 *
 * Old body/file/ZIP/report download APIs remain untouched.
 */
(function (global) {
  'use strict';

  /**
   * Result representation for API calls.
   * Typed states:
   *  - 'success': HTTP 200..299, successfully decoded.
   *  - 'unauthorized': HTTP 401, requires authentication / token.
   *  - 'http_error': HTTP 4xx (non-401) or 5xx response.
   *  - 'network_error': Network connection failure / offline / DNS error.
   *  - 'decode_error': Response could not be parsed according to expected format (e.g. invalid JSON).
   *  - 'aborted': Request was cancelled via AbortController / AbortSignal.
   */
  class ApiResult {
    constructor(init = {}) {
      this.ok = Boolean(init.ok);
      this.kind = init.kind || (this.ok ? 'success' : 'http_error');
      this.status = typeof init.status === 'number' ? init.status : 0;
      this.statusText = init.statusText || '';
      this.data = init.data !== undefined ? init.data : null;
      this.error = init.error || null;
      this.headers = init.headers || null;
      this.rawText = init.rawText || null;
      this._customErrorMessage = init.errorMessage || '';
    }

    isSuccess() {
      return this.kind === 'success';
    }

    isUnauthorized() {
      return this.kind === 'unauthorized';
    }

    isHttpError() {
      return this.kind === 'http_error';
    }

    isNetworkError() {
      return this.kind === 'network_error';
    }

    isDecodeError() {
      return this.kind === 'decode_error';
    }

    isAborted() {
      return this.kind === 'aborted';
    }

    get errorMessage() {
      if (this._customErrorMessage) {
        return this._customErrorMessage;
      }
      switch (this.kind) {
        case 'unauthorized':
          return '認証が必要です (HTTP 401 Unauthorized)。ログインするか認証トークンを確認してください。';
        case 'http_error':
          return `HTTP ${this.status}: ${this.statusText || 'Error'}`;
        case 'decode_error':
          return 'レスポンスの解析に失敗しました: ' + (this.error && this.error.message ? this.error.message : 'JSON parse error');
        case 'network_error':
          return '通信エラーが発生しました: ' + (this.error && this.error.message ? this.error.message : 'Network request failed');
        case 'aborted':
          return 'リクエストがキャンセルされました';
        case 'success':
          return '';
        default:
          return this.error && this.error.message ? this.error.message : '不明なエラーが発生しました';
      }
    }

    static success(data, status = 200, headers = null, statusText = 'OK') {
      return new ApiResult({
        ok: true,
        kind: 'success',
        status: status,
        statusText: statusText,
        data: data,
        headers: headers,
      });
    }

    static unauthorized(statusText = 'Unauthorized', headers = null, data = null, error = null) {
      return new ApiResult({
        ok: false,
        kind: 'unauthorized',
        status: 401,
        statusText: statusText,
        data: data,
        headers: headers,
        error: error || new Error('HTTP 401: Unauthorized'),
      });
    }

    static httpError(status, statusText = '', headers = null, data = null, error = null) {
      return new ApiResult({
        ok: false,
        kind: status === 401 ? 'unauthorized' : 'http_error',
        status: status,
        statusText: statusText,
        data: data,
        headers: headers,
        error: error || new Error(`HTTP ${status}: ${statusText}`),
      });
    }

    static networkError(error) {
      return new ApiResult({
        ok: false,
        kind: 'network_error',
        status: 0,
        statusText: '',
        error: error,
      });
    }

    static decodeError(status, statusText = '', headers = null, rawText = null, error = null) {
      return new ApiResult({
        ok: false,
        kind: 'decode_error',
        status: status,
        statusText: statusText,
        headers: headers,
        rawText: rawText,
        error: error,
      });
    }

    static aborted(error) {
      return new ApiResult({
        ok: false,
        kind: 'aborted',
        status: 0,
        statusText: 'Aborted',
        error: error || new Error('Request was aborted'),
      });
    }
  }

  /**
   * ScopedApiClient: provides an isolated scope for requests with bulk cancellation.
   * Ideal for view / component lifecycles to cancel pending reads when unmounting.
   */
  class ScopedApiClient {
    /**
     * @param {ApiClient} client
     */
    constructor(client) {
      this._client = client;
      this._controllers = new Set();
    }

    /**
     * Perform a request within this scope.
     * @param {string} path
     * @param {Object} [options]
     * @returns {Promise<ApiResult>}
     */
    async request(path, options = {}) {
      const controller = new (global.AbortController || AbortController)();
      this._controllers.add(controller);

      // If an external signal was also provided, listen to it
      let externalCleanup = null;
      if (options.signal) {
        const extSignal = options.signal;
        if (extSignal.aborted) {
          controller.abort(extSignal.reason);
        } else {
          const onExtAbort = () => controller.abort(extSignal.reason);
          extSignal.addEventListener('abort', onExtAbort, { once: true });
          externalCleanup = () => extSignal.removeEventListener('abort', onExtAbort);
        }
      }

      const mergedOptions = Object.assign({}, options, {
        signal: controller.signal,
      });

      try {
        return await this._client.request(path, mergedOptions);
      } finally {
        if (externalCleanup) {
          externalCleanup();
        }
        this._controllers.delete(controller);
      }
    }

    get(path, options) {
      return this.request(path, Object.assign({}, options, { method: 'GET' }));
    }

    post(path, body, options) {
      return this.request(path, Object.assign({}, options, { method: 'POST', body: body }));
    }

    put(path, body, options) {
      return this.request(path, Object.assign({}, options, { method: 'PUT', body: body }));
    }

    delete(path, options) {
      return this.request(path, Object.assign({}, options, { method: 'DELETE' }));
    }

    /**
     * Cancel all pending in-flight requests created in this scope.
     * @param {string} [reason]
     */
    cancelAll(reason) {
      const list = Array.from(this._controllers);
      this._controllers.clear();
      for (let i = 0; i < list.length; i++) {
        try {
          list[i].abort(reason || 'Cancelled by scope');
        } catch (_) {
          // Ignore cancellation errors
        }
      }
    }

    /**
     * Returns the number of currently active in-flight requests in this scope.
     */
    getActiveCount() {
      return this._controllers.size;
    }
  }

  /**
   * Main ApiClient implementation.
   */
  class ApiClient {
    /**
     * @param {Object} [options]
     * @param {string} [options.baseUrl='']
     * @param {Function} [options.fetch] - custom fetch implementation
     * @param {Object} [options.defaultHeaders]
     * @param {string} [options.credentials='same-origin']
     * @param {Function} [options.onUnauthorized] - hook called on 401 responses
     */
    constructor(options = {}) {
      this.baseUrl = options.baseUrl || '';
      this._fetch = options.fetch || (typeof fetch !== 'undefined' ? fetch.bind(global) : null);
      this.defaultHeaders = Object.assign(
        {
          Accept: 'application/json',
        },
        options.defaultHeaders || {}
      );
      this.credentials = options.credentials || 'same-origin';
      this.onUnauthorized = typeof options.onUnauthorized === 'function' ? options.onUnauthorized : null;
    }

    /**
     * Create an isolated cancellation scope bound to this client.
     * @returns {ScopedApiClient}
     */
    createScope() {
      return new ScopedApiClient(this);
    }

    /**
     * Perform an HTTP request with typed result handling.
     * Never logs credential tokens or sensitive request/response bodies.
     *
     * @param {string} path
     * @param {Object} [options]
     * @param {string} [options.method='GET']
     * @param {Object} [options.headers]
     * @param {any} [options.body]
     * @param {AbortSignal} [options.signal]
     * @param {'json'|'text'|'none'} [options.decode='json']
     * @returns {Promise<ApiResult>}
     */
    async request(path, options = {}) {
      const fetchImpl = this._fetch || (typeof fetch !== 'undefined' ? fetch.bind(global) : null);
      if (typeof fetchImpl !== 'function') {
        return ApiResult.networkError(new Error('No fetch implementation available'));
      }

      const url = (this.baseUrl ? this.baseUrl.replace(/\/+$/, '') : '') + path;
      const method = (options.method || 'GET').toUpperCase();
      const decodeType = options.decode || 'json';

      const headers = Object.assign({}, this.defaultHeaders, options.headers || {});
      let body = options.body;

      if (body !== undefined && body !== null) {
        if (typeof body === 'object' && !(body instanceof (global.FormData || Object)) && !(body instanceof (global.Blob || Object))) {
          if (!headers['Content-Type']) {
            headers['Content-Type'] = 'application/json';
          }
          if (headers['Content-Type'].includes('application/json') && typeof body !== 'string') {
            body = JSON.stringify(body);
          }
        }
      }

      const fetchInit = {
        method: method,
        headers: headers,
        credentials: options.credentials || this.credentials,
      };

      if (body !== undefined && body !== null && method !== 'GET' && method !== 'HEAD') {
        fetchInit.body = body;
      }

      if (options.signal) {
        fetchInit.signal = options.signal;
      }

      // Check if already aborted before calling fetch
      if (options.signal && options.signal.aborted) {
        return ApiResult.aborted(options.signal.reason);
      }

      let res;
      try {
        res = await fetchImpl(url, fetchInit);
      } catch (err) {
        if (err && (err.name === 'AbortError' || (options.signal && options.signal.aborted))) {
          return ApiResult.aborted(err);
        }
        return ApiResult.networkError(err);
      }

      // Check for 401 Unauthorized state
      if (res.status === 401) {
        let errData = null;
        try {
          const raw = await res.text();
          if (raw) {
            try {
              errData = JSON.parse(raw);
            } catch (_) {
              errData = raw;
            }
          }
        } catch (_) {
          // Ignore body read errors on 401
        }
        const result = ApiResult.unauthorized(res.statusText || 'Unauthorized', res.headers, errData);
        if (this.onUnauthorized) {
          try {
            this.onUnauthorized(result);
          } catch (hookErr) {
            console.error('Error in onUnauthorized hook:', hookErr);
          }
        }
        return result;
      }

      // Check for non-2xx HTTP errors (4xx, 5xx)
      if (!res.ok) {
        let errData = null;
        try {
          const raw = await res.text();
          if (raw) {
            try {
              errData = JSON.parse(raw);
            } catch (_) {
              errData = raw;
            }
          }
        } catch (_) {
          // Ignore read error
        }
        return ApiResult.httpError(res.status, res.statusText || 'Error', res.headers, errData);
      }

      // Decode successful response (200..299)
      if (decodeType === 'none') {
        return ApiResult.success(res, res.status, res.headers, res.statusText);
      }

      let rawText = '';
      try {
        rawText = await res.text();
      } catch (readErr) {
        if (readErr && (readErr.name === 'AbortError' || (options.signal && options.signal.aborted))) {
          return ApiResult.aborted(readErr);
        }
        return ApiResult.networkError(readErr);
      }

      if (decodeType === 'text') {
        return ApiResult.success(rawText, res.status, res.headers, res.statusText);
      }

      // Default: JSON decoding
      if (!rawText || !rawText.trim()) {
        return ApiResult.success(null, res.status, res.headers, res.statusText);
      }

      try {
        const parsed = JSON.parse(rawText);
        return ApiResult.success(parsed, res.status, res.headers, res.statusText);
      } catch (parseErr) {
        return ApiResult.decodeError(res.status, res.statusText, res.headers, rawText, parseErr);
      }
    }

    get(path, options) {
      return this.request(path, Object.assign({}, options, { method: 'GET' }));
    }

    post(path, body, options) {
      return this.request(path, Object.assign({}, options, { method: 'POST', body: body }));
    }

    put(path, body, options) {
      return this.request(path, Object.assign({}, options, { method: 'PUT', body: body }));
    }

    delete(path, options) {
      return this.request(path, Object.assign({}, options, { method: 'DELETE' }));
    }
  }

  const defaultClient = new ApiClient();

  const apiModuleExport = {
    ApiResult: ApiResult,
    ApiClient: ApiClient,
    ScopedApiClient: ScopedApiClient,
    defaultClient: defaultClient,
    createScope: function () {
      return defaultClient.createScope();
    },
    request: function (path, options) {
      return defaultClient.request(path, options);
    },
    get: function (path, options) {
      return defaultClient.get(path, options);
    },
    post: function (path, body, options) {
      return defaultClient.post(path, body, options);
    },
    put: function (path, body, options) {
      return defaultClient.put(path, body, options);
    },
    delete: function (path, options) {
      return defaultClient.delete(path, options);
    },
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = apiModuleExport;
  }
  if (global) {
    global.VulixApiClient = apiModuleExport;
  }
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));

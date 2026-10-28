/**
 * event-stream.js — Shared Single EventStream & Cursor Projection for Vulix UI
 *
 * Responsibilities:
 *  1. WebSocket lifecycle management (single socket, deterministic 3000ms auto-reconnect).
 *  2. Socket identity & generation tracking to eliminate late-event / close races.
 *  3. Close code 4401 (unauthorized) interception to halt retry storm and prompt login.
 *  4. In-flight message buffering and RAF batching (up to 50 events per frame).
 *  5. Cursor & snapshot projection boundary (sequence gaps, duplicates, new run vs same run,
 *     server instance matching) before dispatching to legacy event handlers.
 *  6. Safe disposal, queue cleanup, and timer cancellation without ghost reconnections.
 *
 * Invariant Preservation:
 *  - Preserves exact 3000ms reconnect timing (no random/exponential backoff).
 *  - Preserves requestAnimationFrame 50-event batching.
 *  - Dispatches validated events to existing legacy handlers without rewriting DOM logic.
 *  - Single state of truth: coordinates with existing `state` object.
 */
(function (global) {
  'use strict';

  function _raf(cb) {
    if (typeof requestAnimationFrame === 'function') {
      return requestAnimationFrame(cb);
    }
    return setTimeout(cb, 16);
  }

  function _cancelRaf(id) {
    if (typeof cancelAnimationFrame === 'function') {
      cancelAnimationFrame(id);
    } else {
      clearTimeout(id);
    }
  }

  /**
   * Safely derive an on-origin return URL for login redirects.
   * Prevents open-redirect and protocol-relative vulnerabilities.
   *
   * @param {Object|Location} [loc]
   * @returns {string}
   */
  function getSafeReturnUrl(loc) {
    const l = loc || (typeof location !== 'undefined' ? location : null);
    if (!l) return '/monitor';
    const path = l.pathname || '/';
    // Reject non-relative or protocol-relative paths
    if (!path.startsWith('/') || path.startsWith('//')) {
      return '/monitor';
    }
    const search = l.search || '';
    const hash = l.hash || '';
    return path + search + hash;
  }

  /**
   * Build login URL with safe return reference.
   * @param {Object|Location} [loc]
   * @returns {string}
   */
  function getLoginUrl(loc) {
    return `/login?next=${encodeURIComponent(getSafeReturnUrl(loc))}`;
  }

  /**
   * CursorProjection: Validates event envelope against scan cursor state.
   * Evaluates sequence gaps, deduplication, server identity, and new run resets.
   */
  class CursorProjection {
    /**
     * @param {Function|Object} stateAccessor - function returning current state or state object
     */
    constructor(stateAccessor) {
      this._stateAccessor = typeof stateAccessor === 'function' ? stateAccessor : (() => stateAccessor);
    }

    /**
     * Inspect an incoming event against the current cursor state.
     * Returns an evaluation outcome:
     *  - { action: 'ignore', reason: string }
     *  - { action: 'apply_snapshot' }
     *  - { action: 'drop', reason: string, ... }
     *  - { action: 'reset_and_process', incomingRunId: string|null }
     *  - { action: 'reconnect_on_gap', expected: number, actual: number }
     *  - { action: 'process', advanceCursor?: boolean, advanceCount?: boolean }
     *
     * @param {Object} event
     * @returns {Object}
     */
    evaluate(event) {
      if (!event || typeof event !== 'object') {
        return { action: 'drop', reason: 'invalid_event' };
      }

      const type = event.type;
      if (type === 'ping') {
        return { action: 'ignore', reason: 'ping' };
      }

      if (type === 'scan_snapshot') {
        return { action: 'apply_snapshot' };
      }

      const state = this._stateAccessor();
      if (!state) {
        return { action: 'process', advanceCount: type !== 'manual_crawl_frame' };
      }

      if (event.server_id && Number.isInteger(event.sequence)) {
        if (state.serverInstanceId && event.server_id !== state.serverInstanceId) {
          return { action: 'drop', reason: 'server_instance_mismatch', expected: state.serverInstanceId, actual: event.server_id };
        }

        const incomingRunId = event.run_id || null;
        const newRun = incomingRunId !== state.scanRunId;
        if (newRun) {
          if (type !== 'scan_started') {
            return { action: 'drop', reason: 'new_run_not_started', expected: state.scanRunId, actual: incomingRunId };
          }
          if (event.sequence <= 0) {
            return { action: 'drop', reason: 'duplicate', sequence: event.sequence, lastSeq: 0 };
          }
          if (event.sequence !== 1) {
            return {
              action: 'reconnect_on_gap',
              expected: 1,
              actual: event.sequence,
            };
          }
          return { action: 'reset_and_process', incomingRunId: incomingRunId, advanceCursor: true };
        }

        const lastSeq = Number.isInteger(state.lastEventSequence) ? state.lastEventSequence : 0;
        if (event.sequence <= lastSeq) {
          return { action: 'drop', reason: 'duplicate', sequence: event.sequence, lastSeq: lastSeq };
        }

        if (event.sequence !== lastSeq + 1) {
          // A sequence gap means some live state was missed; reconnect for a fresh snapshot.
          return {
            action: 'reconnect_on_gap',
            expected: lastSeq + 1,
            actual: event.sequence,
          };
        }

        return { action: 'process', advanceCursor: true, incomingRunId: incomingRunId };
      }

      return {
        action: 'process',
        advanceCount: type !== 'manual_crawl_frame',
      };
    }

    /**
     * Mutate cursor fields on the target state object.
     * @param {Object} event
     * @param {Object} evaluation
     */
    applyCursor(event, evaluation) {
      const state = this._stateAccessor();
      if (!state) return;

      if (evaluation.action === 'reset_and_process') {
        state.serverInstanceId = event.server_id;
        state.scanRunId = evaluation.incomingRunId;
        state.scanId = event.scan_id || null;
        state.lastEventSequence = event.sequence;
        state.eventCount = event.sequence;
      } else if (evaluation.advanceCursor) {
        state.serverInstanceId = event.server_id;
        state.scanRunId = evaluation.incomingRunId !== undefined ? evaluation.incomingRunId : (event.run_id || null);
        state.scanId = event.scan_id || null;
        state.lastEventSequence = event.sequence;
        state.eventCount = event.sequence;
      } else if (evaluation.advanceCount) {
        state.eventCount = (Number(state.eventCount) || 0) + 1;
      }
    }
  }

  /**
   * EventStreamClient: Single WebSocket connection and event dispatching manager.
   */
  class EventStreamClient {
    /**
     * @param {Object} [options]
     */
    constructor(options = {}) {
      this.options = options;
      this.host = options.host || (typeof location !== 'undefined' ? location.host : '127.0.0.1:8000');
      this.protocol = options.protocol || (typeof location !== 'undefined' && location.protocol === 'https:' ? 'wss' : 'ws');
      this.path = options.path || '/ws';
      this.reconnectDelay = options.reconnectDelay != null ? options.reconnectDelay : 3000;
      this.batchSize = options.batchSize || 50;

      this.onEvent = typeof options.onEvent === 'function' ? options.onEvent : null;
      this.onStatusChange = typeof options.onStatusChange === 'function' ? options.onStatusChange : null;
      this.onAuthRequired = typeof options.onAuthRequired === 'function' ? options.onAuthRequired : null;
      this.onResetLiveScan = typeof options.onResetLiveScan === 'function' ? options.onResetLiveScan : null;
      this.onApplySnapshot = typeof options.onApplySnapshot === 'function' ? options.onApplySnapshot : null;

      this.stateAccessor = options.stateAccessor || (() => options.state || (global.state || null));
      this.cursorProjection = options.cursorProjection || new CursorProjection(this.stateAccessor);

      this.ws = null;
      this.connected = false;
      this._generation = 0;
      this._reconnectTimer = null;
      this._msgQueue = [];
      this._rafId = null;
      this._rafPending = false;
      this._stopped = false;
      this._disposed = false;

      this._flushBound = this._flushMsgQueue.bind(this);
    }

    /**
     * Connect or reconnect the WebSocket.
     */
    connect() {
      if (this._disposed) return;
      this._stopped = false;
      this._clearReconnectTimer();

      if (this.ws && (this.ws.readyState === 0 || this.ws.readyState === 1)) {
        return;
      }

      this._generation++;
      const currentGen = this._generation;
      const url = `${this.protocol}://${this.host}${this.path}`;

      const WebSocketCtor = this.options.WebSocket || (typeof WebSocket !== 'undefined' ? WebSocket : null);
      if (!WebSocketCtor) {
        throw new Error('WebSocket constructor is not available');
      }

      const ws = new WebSocketCtor(url);
      this.ws = ws;

      const state = this.stateAccessor();
      if (state) {
        state.ws = ws;
      }

      ws.onopen = () => {
        if (this._disposed || this._generation !== currentGen || this.ws !== ws) return;
        this.connected = true;
        if (state) state.connected = true;
        if (this.onStatusChange) {
          this.onStatusChange({ connected: true });
        }
      };

      ws.onclose = (evt) => {
        if (this._disposed || this._generation !== currentGen || this.ws !== ws) return;
        this.connected = false;
        if (state) state.connected = false;

        const code = evt ? evt.code : 1000;
        if (this.onStatusChange) {
          this.onStatusChange({ connected: false, code: code, reason: evt ? evt.reason : '' });
        }

        // Close code 4401: Unauthorized session expiry from wscan/monitor.py
        if (code === 4401) {
          this._stopped = true;
          this._clearReconnectTimer();
          if (this.onAuthRequired) {
            this.onAuthRequired(evt);
          }
          return;
        }

        // If stopped or disposed, do NOT schedule reconnect
        if (this._stopped || this._disposed) {
          return;
        }

        this._scheduleReconnect();
      };

      ws.onerror = () => {
        if (this._disposed || this._generation !== currentGen || this.ws !== ws) return;
        try {
          ws.close();
        } catch (_) {}
      };

      ws.onmessage = (evt) => {
        if (this._disposed || this._generation !== currentGen || this.ws !== ws) return;
        try {
          const raw = evt && evt.data;
          const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
          if (parsed && typeof parsed === 'object') {
            this.enqueueMessage(parsed);
          }
        } catch (_) {}
      };
    }

    /**
     * Enqueue a message for batch processing via requestAnimationFrame.
     * @param {Object} message
     */
    enqueueMessage(message) {
      if (this._disposed) return;
      this._msgQueue.push(message);
      if (!this._rafPending) {
        this._rafPending = true;
        this._rafId = _raf(this._flushBound);
      }
    }

    /**
     * Process up to batchSize messages per frame.
     */
    _flushMsgQueue() {
      this._rafPending = false;
      this._rafId = null;
      if (this._disposed) {
        this._msgQueue.length = 0;
        return;
      }

      const batch = this._msgQueue.splice(0, this.batchSize);
      for (let i = 0; i < batch.length; i++) {
        this.processEvent(batch[i]);
      }

      if (this._msgQueue.length > 0 && !this._disposed) {
        this._rafPending = true;
        this._rafId = _raf(this._flushBound);
      }
    }

    /**
     * Process a single event through the cursor projection gate, then dispatch to legacy handler.
     * @param {Object} event
     */
    processEvent(event) {
      if (!event || typeof event !== 'object') return;
      const evaluation = this.cursorProjection.evaluate(event);

      if (evaluation.action === 'ignore' || evaluation.action === 'drop') {
        return;
      }

      if (evaluation.action === 'apply_snapshot') {
        if (this.onApplySnapshot) {
          this.onApplySnapshot(event);
        }
        return;
      }

      if (evaluation.action === 'reconnect_on_gap') {
        // Sequence gap means live state was missed; reconnect for fresh snapshot
        this.reconnect();
        return;
      }

      if (evaluation.action === 'reset_and_process') {
        if (this.onResetLiveScan) {
          this.onResetLiveScan();
        }
        this.cursorProjection.applyCursor(event, evaluation);
      } else if (evaluation.action === 'process') {
        this.cursorProjection.applyCursor(event, evaluation);
      }

      const state = this.stateAccessor();
      if (state && typeof document !== 'undefined') {
        const el = document.getElementById('eventCount');
        if (el) el.textContent = state.eventCount;
      }

      if (this.onEvent) {
        this.onEvent(event);
      }
    }

    /**
     * Force reconnection to retrieve a fresh snapshot (e.g. after a sequence gap).
     */
    reconnect() {
      if (this._disposed) return;
      this._clearReconnectTimer();
      if (this.ws && (this.ws.readyState === 0 || this.ws.readyState === 1)) {
        try {
          this.ws.close();
        } catch (_) {}
      }
      this.connect();
    }

    /**
     * Send payload through active WebSocket.
     * @param {Object|string} obj
     * @returns {boolean}
     */
    send(obj) {
      if (!this.ws || this.ws.readyState !== 1) {
        return false;
      }
      try {
        this.ws.send(typeof obj === 'string' ? obj : JSON.stringify(obj));
        return true;
      } catch (_) {
        return false;
      }
    }

    _scheduleReconnect() {
      this._clearReconnectTimer();
      if (this._stopped || this._disposed) return;
      this._reconnectTimer = setTimeout(() => {
        this._reconnectTimer = null;
        this.connect();
      }, this.reconnectDelay);
    }

    _clearReconnectTimer() {
      if (this._reconnectTimer) {
        clearTimeout(this._reconnectTimer);
        this._reconnectTimer = null;
      }
    }

    _clearRaf() {
      if (this._rafId != null) {
        _cancelRaf(this._rafId);
        this._rafId = null;
      }
      this._rafPending = false;
    }

    /**
     * Explicitly stop the event stream and cancel auto-reconnect.
     */
    stop() {
      this._stopped = true;
      this._clearReconnectTimer();
      if (this.ws) {
        try {
          this.ws.close();
        } catch (_) {}
      }
    }

    /**
     * Completely dispose this instance, cleaning up queues, RAF, timers, and active socket.
     */
    dispose() {
      this._disposed = true;
      this._stopped = true;
      this._clearReconnectTimer();
      this._clearRaf();
      this._msgQueue.length = 0;
      const state = this.stateAccessor();
      const ownedSocket = this.ws;
      if (ownedSocket) {
        try {
          ownedSocket.close();
        } catch (_) {}
        this.ws = null;
      }
      this.connected = false;
      // state.ws は legacy コマンド送信 (_wsSend) の参照元なので、
      // 自分が所有していた socket のときだけ解放し、他インスタンスの socket は触らない。
      if (state && ownedSocket && state.ws === ownedSocket) {
        state.ws = null;
        state.connected = false;
      }
    }
  }

  const exportsObj = {
    CursorProjection,
    EventStreamClient,
    getSafeReturnUrl,
    getLoginUrl,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportsObj;
  }
  Object.assign(global, exportsObj);
})(typeof window !== 'undefined' ? window : globalThis);

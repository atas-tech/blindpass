// SPDX-License-Identifier: AGPL-3.0-only
const failed = () => new Error('client_task_failed');
export class AiTaskObserver {
  lastTool = 'none';
  failureReason = 'none';
  toolTrace = [];
  #navigations = 0; #waitNavigation = 0; #readNavigation = 0;
  #pending = new Map(); #callbacks; #requests = 0; #ready = false; #reads = 0; #reconnects = 0; #cancel = false;
  constructor(callbacks) {
    if (['requested', 'ready', 'firstSnapshot', 'cancelled'].some(key => typeof callbacks?.[key] !== 'function')) throw failed();
    this.#callbacks = callbacks;
  }
  fromModel(message) {
    if (message.method !== undefined && Object.hasOwn(message, 'id')) {
      if (this.#pending.size >= 64 || this.#pending.has(message.id)) throw failed();
      this.#pending.set(message.id, message.method === 'tools/call' ? message.params?.name : 'protocol');
    }
  }
  async fromServer(message) {
    if (message.method !== undefined || !Object.hasOwn(message, 'id')) return;
    const name = this.#pending.get(message.id); this.#pending.delete(message.id);
    if (!name || name === 'protocol') return;
    this.lastTool = ['blindpass_request_operation', 'blindpass_operation_status', 'blindpass_cancel_operation', 'browser_navigate', 'browser_wait_for', 'browser_snapshot'].includes(name) ? name : 'other';
    this.toolTrace.push(this.lastTool); if (this.toolTrace.length > 16) this.toolTrace.shift();
    if (message.error || message.result?.isError || !message.result) { this.failureReason = 'tool-error'; throw failed(); }
    const metadata = message.result.structuredContent;
    if (name === 'blindpass_request_operation') {
      if (this.#requests || metadata?.status !== 'requested' || !/^event_[A-Za-z0-9_-]{16,100}$/.test(metadata.eventKey)) throw failed();
      this.#requests++; await this.#callbacks.requested(metadata.eventKey);
    } else if (name === 'blindpass_operation_status' && metadata?.status === 'ready') {
      if (!this.#requests) throw failed();
      if (!this.#ready) await this.#callbacks.ready(); this.#ready = true;
    } else if (name === 'browser_navigate') {
      this.#navigations++;
    } else if (name === 'browser_wait_for') {
      this.#waitNavigation = this.#navigations;
    } else if (name === 'browser_snapshot') {
      if (!this.#ready || !JSON.stringify(message.result).includes('Coordinator report: 12 artifacts')) {
        this.failureReason = this.#ready ? 'report-text-missing' : 'report-before-ready'; throw failed();
      }
      if (this.#navigations <= this.#readNavigation || this.#waitNavigation !== this.#navigations) {
        this.failureReason = 'report-sequence'; throw failed();
      }
      this.#readNavigation = this.#navigations;
      this.#reads++;
      if (this.#reads === 1) { await this.#callbacks.firstSnapshot(); this.#reconnects++; }
    } else if (name === 'blindpass_cancel_operation') {
      if (!['cancellation_requested', 'closed'].includes(metadata?.status)) throw failed();
      this.#cancel = true; await this.#callbacks.cancelled();
    }
  }
  result() { return { brokerRequests: this.#requests, readyObserved: this.#ready, stockReportReads: this.#reads,
    stockReconnects: this.#reconnects, cancellationRequested: this.#cancel }; }
}

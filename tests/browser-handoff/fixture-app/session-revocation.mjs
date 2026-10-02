// SPDX-License-Identifier: AGPL-3.0-only
// Used only after the application's separate administrator authentication.
// Epochs also fence password verification already in flight during logout.
export class AccountRevocation {
  #epochs;
  constructor(accounts) { this.#epochs = new Map(accounts.map((account) => [account, 0])); }
  begin(account) { return this.#epochs.get(account); }
  canCommit(account, epoch) { return this.#epochs.has(account) && this.#epochs.get(account) === epoch; }
  revoke(account, sessions, references) {
    if (!this.#epochs.has(account)) throw new Error('invalid_account');
    // BigInt avoids an eventual numeric rollover reopening an old generation.
    this.#epochs.set(account, BigInt(this.#epochs.get(account)) + 1n);
    for (const [reference, record] of references) if (record.account === account) {
      references.delete(reference); sessions.delete(record.tokenDigest); record.revoked = true;
    }
  }
}

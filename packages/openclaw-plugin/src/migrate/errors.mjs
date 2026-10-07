// A refusal raised before (or instead of) any change. `reason` is a stable machine-readable code;
// the message and extra fields never carry secret values.
export class PreflightError extends Error {
    constructor(reason, detail, extra = {}) {
        super(detail ? `${reason}: ${detail}` : reason);
        this.name = "PreflightError";
        this.reason = reason;
        Object.assign(this, extra);
    }
}

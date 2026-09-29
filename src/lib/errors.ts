export class ControllerError extends Error {
  readonly code: string;
  readonly details: Record<string, unknown> | undefined;

  constructor(code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "ControllerError";
    this.code = code;
    this.details = details;
  }
}

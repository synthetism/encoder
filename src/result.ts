/**
 * Foundational Result Pattern for Encoder Operations
 * 
 * Local copy following Unit Architecture Doctrine #14: ERROR BOUNDARY CLARITY
 * Simple operations throw, complex operations use Result pattern
 */

export class Result<T> {
  private constructor(
    private readonly _value: T | null,
    private readonly _error: string | null,
    private readonly _errorCause?: unknown
  ) {}

  static success<T>(value: T): Result<T> {
    return new Result(value, null);
  }

  static fail<T>(message: string, cause?: unknown): Result<T> {
    return new Result<T>(null, message, cause);
  }

  get isSuccess(): boolean {
    return this._error === null;
  }

  get isFailure(): boolean {
    return this._error !== null;
  }

  get value(): T {
    if (this._error !== null) {
      throw new Error(`Attempted to get value from failed Result: ${this._error}`);
    }
    return this._value as T;
  }

  get error(): string {
    return this._error || '';
  }

  get errorCause(): unknown {
    return this._errorCause;
  }

  map<U>(fn: (value: T) => U): Result<U> {
    if (this.isFailure) {
      return Result.fail<U>(this._error || 'Unknown error', this._errorCause);
    }
    try {
      return Result.success(fn(this.value));
    } catch (error) {
      return Result.fail<U>(
        `Map operation failed: ${error instanceof Error ? error.message : String(error)}`,
        error
      );
    }
  }

  flatMap<U>(fn: (value: T) => Result<U>): Result<U> {
    if (this.isFailure) {
      return Result.fail<U>(this._error || 'Unknown error', this._errorCause);
    }
    try {
      return fn(this.value);
    } catch (error) {
      return Result.fail<U>(
        `FlatMap operation failed: ${error instanceof Error ? error.message : String(error)}`,
        error
      );
    }
  }

  getOrElse(defaultValue: T): T {
    return this.isSuccess ? this.value : defaultValue;
  }

  match<U>(onSuccess: (value: T) => U, onFailure: (error: string) => U): U {
    return this.isSuccess ? onSuccess(this.value) : onFailure(this.error);
  }
}

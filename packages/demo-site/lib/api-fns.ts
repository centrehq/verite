import { ValidationError, ValidationErrorArray } from "@centre/verity"
import { NextApiHandler, NextApiResponse } from "next"

export type ApiErrorResponse = {
  status: number
  errors: ApiError[]
}

export type ApiError = {
  message: string
  details?: string
}

export type ApiResponse<T> = NextApiResponse<T | ApiErrorResponse>

export function apiError(
  res: NextApiResponse<ApiErrorResponse>,
  status: number,
  error: Error | ValidationError | ValidationErrorArray
): void {
  const errors: Array<ValidationError | Error> =
    error instanceof ValidationErrorArray ? error.errors : [error]
  const errorMessages = errors.map((e) => {
    if (e instanceof ValidationError) {
      return {
        message: e.message,
        details: e.details
      }
    }

    return {
      message: e.message
    }
  })

  res.status(status).json({
    status,
    errors: errorMessages
  })
}

export function notFound(res: NextApiResponse<ApiErrorResponse>): void {
  apiError(res, 404, new Error("Not found"))
}

export function methodNotAllowed(res: NextApiResponse<ApiErrorResponse>): void {
  apiError(res, 405, new Error("Method not allowed"))
}

/**
 * Wrapper for API requests which handles API Errors and includes basic logging
 *
 * @remark This method is a wrapper around your existing api handler
 *
 * @example
 * export default apiHandler(async (req, res) => { ... })
 * export default apiHandler<ResponseType>(async (req, res) => { ... })
 */
export function apiHandler<T>(
  handler: NextApiHandler<T | ApiErrorResponse>
): NextApiHandler<T | ApiErrorResponse> {
  return async (req, res) => {
    // Log the HTTP request, but not in test environments
    if (process.env.NODE_ENV !== "test") {
      console.info(`> ${req.method} ${req.url}`)
    }

    try {
      // Call the original API method
      await handler(req, res)
    } catch (e) {
      apiError(res, 400, e)
    }
  }
}

import { reactive } from 'vue'

export type ToastKind = 'info' | 'success' | 'error'

export interface Toast {
  id: number
  kind: ToastKind
  message: string
}

const state = reactive<{ toasts: Toast[] }>({ toasts: [] })
let counter = 0

export function useToasts() {
  return state
}

export function toast(message: string, kind: ToastKind = 'info', timeout = 4000) {
  const id = ++counter
  state.toasts.push({ id, kind, message })
  if (timeout > 0) {
    setTimeout(() => dismiss(id), timeout)
  }
}

export const toastError = (message: string) => toast(message, 'error', 6000)
export const toastSuccess = (message: string) => toast(message, 'success')

export function dismiss(id: number) {
  const i = state.toasts.findIndex((t) => t.id === id)
  if (i >= 0) state.toasts.splice(i, 1)
}

/** Wrap a throwing operation and surface a toast on failure. */
export function tryRun<T>(fn: () => T, errPrefix = 'Error'): T | undefined {
  try {
    return fn()
  } catch (e) {
    toastError(`${errPrefix}: ${e instanceof Error ? e.message : String(e)}`)
    return undefined
  }
}

// Lightweight toast helpers that proxy to Nuxt UI's `useToast()`.
//
// `registerToast` is called once from a component mounted inside <UApp>
// (see AppToaster.vue). Everything else in the app can then call `toast()` /
// `toastError()` / `toastSuccess()` without being inside a setup scope.

export type ToastKind = 'info' | 'success' | 'error'

interface ToastPayload {
  title: string
  color?: 'success' | 'error' | 'info' | 'primary' | 'neutral' | 'warning'
  icon?: string
}
type AddFn = (payload: ToastPayload) => unknown

let add: AddFn | null = null

export function registerToast(fn: AddFn) {
  add = fn
}

const colorFor: Record<ToastKind, ToastPayload['color']> = {
  info: 'info',
  success: 'success',
  error: 'error',
}
const iconFor: Record<ToastKind, string> = {
  info: 'i-lucide-info',
  success: 'i-lucide-circle-check',
  error: 'i-lucide-circle-alert',
}

export function toast(message: string, kind: ToastKind = 'info') {
  if (!add) {
    // eslint-disable-next-line no-console
    console[kind === 'error' ? 'error' : 'log'](message)
    return
  }
  add({ title: message, color: colorFor[kind], icon: iconFor[kind] })
}

export const toastError = (message: string) => toast(message, 'error')
export const toastSuccess = (message: string) => toast(message, 'success')

/** Wrap a throwing operation and surface a toast on failure. */
export function tryRun<T>(fn: () => T, errPrefix = 'Error'): T | undefined {
  try {
    return fn()
  } catch (e) {
    toastError(`${errPrefix}: ${e instanceof Error ? e.message : String(e)}`)
    return undefined
  }
}

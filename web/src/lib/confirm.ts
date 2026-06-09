// Imperative confirm-dialog service — a custom replacement for window.confirm().
//
// `registerConfirm` is called once by <ConfirmHost> (mounted inside <UApp> in
// App.vue). Anywhere in the app can then `await confirmDialog({...})` from a
// plain function and get a boolean, without being inside a setup scope.
//
// Dismissing the dialog (Esc, overlay, or Cancel) always resolves to `false`,
// and the host focuses the non-destructive (Cancel) button by default.

export interface ConfirmOptions {
  title: string
  message: string
  /** Label for the confirming (often destructive) action. */
  confirmLabel?: string
  cancelLabel?: string
  /** Render the confirm button as destructive (red). */
  danger?: boolean
}

type Opener = (opts: ConfirmOptions) => Promise<boolean>

let opener: Opener | null = null

export function registerConfirm(fn: Opener) {
  opener = fn
}

export function confirmDialog(opts: ConfirmOptions): Promise<boolean> {
  // If the host isn't mounted (shouldn't happen), fail safe: don't proceed
  // with the (often destructive) action rather than fall back to confirm().
  if (!opener) return Promise.resolve(false)
  return opener(opts)
}

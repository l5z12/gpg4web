// Inactivity auto-lock.
//
// Tracks the time of the last user interaction and, on a periodic check,
// locks the vault once the configured idle timeout has elapsed. Using a
// timestamp + interval (rather than a single resettable timeout) keeps the
// hot path cheap and means the vault also locks correctly after the device
// sleeps/wakes, since the elapsed wall-clock time is what's checked.

import { onBeforeUnmount, onMounted } from 'vue'

interface AutoLockOptions {
  /** Whether the vault is currently unlocked. */
  isUnlocked: () => boolean
  /** Idle timeout in minutes; 0 (or less) disables auto-lock. */
  getMinutes: () => number
  /** Called when the idle timeout elapses. */
  onLock: () => void
}

const ACTIVITY_EVENTS = ['mousedown', 'mousemove', 'keydown', 'touchstart', 'scroll', 'wheel']
const CHECK_INTERVAL_MS = 5_000
const THROTTLE_MS = 1_000

export function useAutoLock(opts: AutoLockOptions) {
  let lastActivity = Date.now()
  let lastBump = 0
  let timer: ReturnType<typeof setInterval> | undefined

  /** Record activity (throttled so frequent events like mousemove are cheap). */
  const bump = () => {
    const now = Date.now()
    if (now - lastBump > THROTTLE_MS) {
      lastBump = now
      lastActivity = now
    }
  }

  /** Restart the idle window (e.g. right after unlocking). */
  const reset = () => {
    lastActivity = Date.now()
  }

  const onVisible = () => {
    if (document.visibilityState === 'visible') check()
  }

  const check = () => {
    const minutes = opts.getMinutes()
    if (!opts.isUnlocked() || !minutes || minutes <= 0) return
    if (Date.now() - lastActivity >= minutes * 60_000) opts.onLock()
  }

  onMounted(() => {
    ACTIVITY_EVENTS.forEach((e) => window.addEventListener(e, bump, { passive: true }))
    document.addEventListener('visibilitychange', onVisible)
    timer = setInterval(check, CHECK_INTERVAL_MS)
  })

  onBeforeUnmount(() => {
    ACTIVITY_EVENTS.forEach((e) => window.removeEventListener(e, bump))
    document.removeEventListener('visibilitychange', onVisible)
    if (timer) clearInterval(timer)
  })

  return { reset }
}

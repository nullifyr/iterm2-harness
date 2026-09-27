"""Non-modal local consent. No app-modal fallback and no HTTP approval endpoint."""
import asyncio
import time
from .common import APIError

_TARGET = None
_LOCK = None


async def ask(message, timeout=60):
    global _TARGET, _LOCK
    if _LOCK is None:
        _LOCK = asyncio.Lock()
    if _LOCK.locked():
        raise APIError(429, "approval_busy", "A local approval is already pending")
    async with _LOCK:
        window = None
        try:
            import AppKit as A
            if _TARGET is None:
                class HarnessConsentTarget(A.NSObject):
                    def allow_(self, sender):
                        self.decision = True

                    def deny_(self, sender):
                        self.decision = False
                _TARGET = HarnessConsentTarget
            target = _TARGET.alloc().init()
            target.decision = None
            app = A.NSApplication.sharedApplication()
            app.setActivationPolicy_(A.NSApplicationActivationPolicyAccessory)
            alert = A.NSAlert.alloc().init()
            alert.setMessageText_("iTerm2 Harness — local approval")
            alert.setInformativeText_(message)
            allow = alert.addButtonWithTitle_("Allow")
            deny = alert.addButtonWithTitle_("Deny")
            allow.setTarget_(target)
            allow.setAction_("allow:")
            allow.setKeyEquivalent_("")
            deny.setTarget_(target)
            deny.setAction_("deny:")
            deny.setKeyEquivalent_("\x1b")
            alert.setShowsSuppressionButton_(False)
            alert.layout()
            window = alert.window()
            window.setLevel_(A.NSFloatingWindowLevel)
            window.makeKeyAndOrderFront_(None)
            app.activateIgnoringOtherApps_(True)
            deadline = time.monotonic() + timeout
            mask = getattr(A, "NSEventMaskAny", None)
            if mask is None:
                mask = A.NSAnyEventMask
            while time.monotonic() < deadline:
                # A finite event batch prevents a busy event queue starving asyncio.
                for _ in range(32):
                    event = app.nextEventMatchingMask_untilDate_inMode_dequeue_(
                        mask, A.NSDate.distantPast(), A.NSDefaultRunLoopMode, True)
                    if event is None:
                        break
                    app.sendEvent_(event)
                if target.decision is not None:
                    return bool(target.decision)
                if not window.isVisible():
                    return False
                await asyncio.sleep(0.05)
            return False
        except APIError:
            raise
        except Exception:
            raise APIError(503, "approval_unavailable", "Local approval UI is unavailable; no action was authorized")
        finally:
            if window is not None:
                window.orderOut_(None)
                window.close()

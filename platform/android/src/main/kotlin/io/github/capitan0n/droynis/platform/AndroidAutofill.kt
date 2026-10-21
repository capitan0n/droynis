package io.github.capitan0n.droynis.platform

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.view.autofill.AutofillManager
import io.github.capitan0n.droynis.checks.base.AutofillProbe
import io.github.capitan0n.droynis.checks.base.AutofillState
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

/** Public API, no permission: the service answers any caller about its own user. */
internal class AndroidAutofill(private val context: Context) : AutofillProbe {

    override fun state(): Reading<AutofillState> {
        val source = Source("AutofillManager.getAutofillServiceComponentName()")
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return Reading.Unsupported("needs API 28", source)
        if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_AUTOFILL)) {
            return Reading.Unsupported("this phone has no autofill", source)
        }
        val manager = context.getSystemService(AutofillManager::class.java)
            ?: return Reading.Unsupported("no AutofillManager service", source)
        return probe(source) {
            // False only when a device policy (DISALLOW_AUTOFILL) turns autofill off for this user.
            val allowed = manager.isAutofillSupported
            val component = manager.autofillServiceComponentName?.flattenToShortString()
            Reading.Value(AutofillState(component, allowed), source)
        }
    }
}

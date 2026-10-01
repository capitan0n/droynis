package io.github.capitan0n.droynis

import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.platform.AndroidPlatform
import io.github.capitan0n.droynis.ui.DroynisTheme
import io.github.capitan0n.droynis.ui.HomeScreen

class MainActivity : ComponentActivity() {

    private val viewModel: HomeViewModel by viewModels {
        viewModelFactory { initializer { HomeViewModel(AndroidPlatform(applicationContext)) } }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            DroynisTheme {
                val state by viewModel.state.collectAsStateWithLifecycle()
                HomeScreen(state = state, onRescan = viewModel::scan, onOpenSettings = ::openSettings)
            }
        }
    }

    /** Opens the first of [actions] this device can show. Droynis never changes a setting itself. */
    private fun openSettings(actions: List<String>) {
        for (action in actions + SettingsActions.SETTINGS) {
            try {
                startActivity(Intent(action))
                return
            } catch (e: ActivityNotFoundException) {
                continue
            } catch (e: SecurityException) {
                continue // some OEMs do not export every Settings screen
            }
        }
    }
}

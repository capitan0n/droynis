package io.github.capitan0n.droynis

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.capitan0n.droynis.checks.base.baseChecks
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Scanner
import io.github.capitan0n.droynis.platform.AndroidPlatform
import io.github.capitan0n.droynis.report.HardeningIndex
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed interface ScanState {
    data class Scanning(val done: Int, val total: Int) : ScanState

    data class Done(
        val context: ScanContext,
        val findings: List<Finding>,
        val index: HardeningIndex,
    ) : ScanState
}

class HomeViewModel(private val platform: AndroidPlatform) : ViewModel() {

    // Each tier module contributes its registry here (adbChecks, shizukuChecks, ...).
    private val checks = baseChecks(platform)
    private val scanner = Scanner()
    private val _state = MutableStateFlow<ScanState>(ScanState.Scanning(done = 0, total = checks.size))
    val state: StateFlow<ScanState> = _state.asStateFlow()
    private var scanJob: Job? = null

    init {
        scan()
    }

    fun scan() {
        scanJob?.cancel()
        scanJob = viewModelScope.launch {
            val context = platform.newScanContext()
            val findings = mutableListOf<Finding>()
            _state.value = ScanState.Scanning(done = 0, total = checks.size)
            scanner.scan(checks, context).collect { finding ->
                findings += finding
                _state.value = ScanState.Scanning(done = findings.size, total = checks.size)
            }
            val order = checks.map { it.spec.id }
            val sorted = findings.sortedBy { order.indexOf(it.spec.id) }
            _state.value = ScanState.Done(context, sorted, HardeningIndex.of(sorted))
        }
    }
}

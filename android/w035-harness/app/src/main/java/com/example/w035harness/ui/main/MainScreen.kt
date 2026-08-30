package com.example.w035harness.ui.main

import android.util.Log
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation3.runtime.NavKey
import com.example.w035harness.ObservationProvider
import com.example.w035harness.data.DefaultDataRepository
import com.example.w035harness.theme.W035HarnessTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@Composable
fun MainScreen(
  onItemClick: (NavKey) -> Unit,
  modifier: Modifier = Modifier,
  viewModel: MainScreenViewModel = viewModel { MainScreenViewModel(DefaultDataRepository()) },
) {
  val context = LocalContext.current
  val scope = rememberCoroutineScope()
  val state by viewModel.uiState.collectAsStateWithLifecycle()
  Column(modifier) {
    Row {
      Button(onClick = {
        val snapshot = ObservationProvider.getSnapshot(context)
        Log.i("W035_HARNESS", "OBSERVATION: $snapshot")
      }) {
        Text("Emit Now")
      }
      Button(onClick = {
        scope.launch {
          Log.i("W035_HARNESS", "Delayed observation started (3s)...")
          delay(3000)
          val snapshot = ObservationProvider.getSnapshot(context)
          Log.i("W035_HARNESS", "OBSERVATION: $snapshot")
        }
      }) {
        Text("Emit in 3s")
      }
    }
    when (state) {
      MainScreenUiState.Loading -> {
        // Blank
      }
      is MainScreenUiState.Success -> {
        MainScreen(data = (state as MainScreenUiState.Success).data)
      }
      is MainScreenUiState.Error -> {
        Text("Error loading data: ${(state as MainScreenUiState.Error).throwable.message}")
      }
    }
  }
}

@Composable
internal fun MainScreen(data: List<String>, modifier: Modifier = Modifier) {
  Column(modifier) { data.forEach { Greeting(it) } }
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
  Text(text = "Hello $name!", modifier = modifier)
}

@Preview(showBackground = true)
@Composable
fun MainScreenPreview() {
  W035HarnessTheme { MainScreen(listOf("Android")) }
}

@Preview(showBackground = true, widthDp = 340)
@Composable
fun MainScreenPortraitPreview() {
  W035HarnessTheme { MainScreen(listOf("Android")) }
}

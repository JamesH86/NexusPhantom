import SwiftUI
import Combine

struct BugBountyView: View {
    @EnvironmentObject var toolRunner: ToolRunner
    @EnvironmentObject var aiOrchestrator: AIOrchestrator
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var voiceManager: VoiceManager
    
    @State private var targetDomain = ""
    @State private var isRunning = false
    
    var body: some View {
        VStack {
            Text("Bug Bounty Hunter")
                .font(.largeTitle)
                .fontWeight(.bold)
            
            TextField("Target Domain", text: $targetDomain)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 300)
            
            Button("Start Bug Bounty Hunt") {
                Task {
                    await startBugBountyHunt()
                }
            }
            .disabled(targetDomain.isEmpty || isRunning)
            
            if isRunning {
                ProgressView("Running bug bounty automation...")
                    .progressViewStyle(CircularProgressViewStyle())
            }
        }
        .padding()
        .navigationTitle("Bug Bounty Hunter")
        .onAppear {
            voiceManager.speak("Bug bounty hunter module activated")
        }
    }
    
    private func startBugBountyHunt() async {
        isRunning = true
        voiceManager.speak("Starting automated bug bounty hunt on \(targetDomain)")
        
        // Simple bug bounty automation
        await toolRunner.runFullSecurityScan()
        
        isRunning = false
        voiceManager.speak("Bug bounty hunt completed")
    }
}

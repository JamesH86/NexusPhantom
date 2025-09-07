import SwiftUI
import AVFoundation

// MARK: - Enhanced Status Bar View
struct EnhancedStatusBarView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var voiceManager: VoiceManager
    @EnvironmentObject var aiOrchestrator: AIOrchestrator
    @EnvironmentObject var toolRunner: ToolRunner
    @State private var currentTime = Date()
    
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()
    
    var body: some View {
        HStack {
            // NEXUS PHANTOM Branding
            HStack(spacing: 8) {
                Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                    .foregroundStyle(.linearGradient(
                        colors: [.cyan, .purple],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ))
                    .font(.title2)
                
                VStack(alignment: .leading, spacing: 0) {
                    Text("NEXUS PHANTOM")
                        .font(.headline)
                        .fontWeight(.bold)
                        .foregroundColor(.primary)
                    
                    Text("Elite Cyber AI")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            
            Spacer()
            
            // Status Indicators
            HStack(spacing: 16) {
                // AI Status
                AIStatusIndicator()
                
                // Voice Control
                VoiceControlButton()
                
                // Tool Status
                ToolStatusIndicator()
                
                // Time
                Text(currentTime.formatted(.dateTime.hour().minute().second()))
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(.secondary)
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
        .onReceive(timer) { _ in
            currentTime = Date()
        }
    }
}

// MARK: - Tool GUI Wrapper
struct ToolGUIWrapper: View {
    let tool: CyberSecTool
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                VStack(alignment: .leading) {
                    Text(tool.name)
                        .font(.title2)
                        .fontWeight(.bold)
                    
                    Text(tool.description)
                        .font(.body)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                Button("Close") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
            }
            .padding()
            
            Divider()
            
            // Tool Interface
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // Tool-specific interface would go here
                    Text("Tool interface for \(tool.name) would be implemented here")
                        .foregroundColor(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .padding()
                }
            }
        }
        .frame(minWidth: 800, minHeight: 600)
    }
}

// MARK: - AI Drone Control Panel
struct AIDroneControlPanel: View {
    @EnvironmentObject var aiDroneSystem: AIDroneSystem
    @State private var isExpanded = false
    
    var body: some View {
        VStack(alignment: .trailing, spacing: 8) {
            // Toggle Button
            Button(action: {
                withAnimation(.spring()) {
                    isExpanded.toggle()
                }
            }) {
                HStack(spacing: 6) {
                    Text("AI Drones")
                        .font(.caption)
                        .fontWeight(.semibold)
                    
                    Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                        .font(.caption)
                }
                .foregroundColor(.white)
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(.purple, in: RoundedRectangle(cornerRadius: 8))
            }
            .buttonStyle(.borderless)
            
            // Expanded Panel
            if isExpanded {
                VStack(alignment: .trailing, spacing: 12) {
                    // Learning Status
                    LearningStatusCard()
                    
                    // Active Drones
                    ForEach(aiDroneSystem.activeDrones.prefix(3)) { drone in
                        DroneCard(drone: drone)
                    }
                    
                    if aiDroneSystem.activeDrones.count > 3 {
                        Text("+ \(aiDroneSystem.activeDrones.count - 3) more drones")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
                .transition(.asymmetric(
                    insertion: .move(edge: .trailing).combined(with: .opacity),
                    removal: .move(edge: .trailing).combined(with: .opacity)
                ))
            }
        }
    }
}

// MARK: - Learning Status Card
struct LearningStatusCard: View {
    @EnvironmentObject var aiDroneSystem: AIDroneSystem
    
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: aiDroneSystem.learningStatus.icon)
                .foregroundColor(aiDroneSystem.learningStatus.color)
                .font(.caption)
            
            VStack(alignment: .leading, spacing: 2) {
                Text("Learning System")
                    .font(.caption2)
                    .fontWeight(.semibold)
                
                Text(aiDroneSystem.learningStatus.rawValue)
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
            
            Text("\(aiDroneSystem.totalKnowledgeEntries)")
                .font(.caption)
                .fontWeight(.bold)
                .foregroundColor(.green)
        }
        .padding(8)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
        .frame(width: 200)
    }
}

// MARK: - Drone Card
struct DroneCard: View {
    @ObservedObject var drone: AIDrone
    
    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(drone.status.color)
                .frame(width: 8, height: 8)
            
            VStack(alignment: .leading, spacing: 2) {
                Text(drone.name)
                    .font(.caption2)
                    .fontWeight(.semibold)
                
                Text(drone.status.rawValue)
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
            
            if drone.progress > 0 {
                ProgressView(value: drone.progress)
                    .progressViewStyle(.linear)
                    .frame(width: 40)
            }
        }
        .padding(8)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
        .frame(width: 200)
    }
}

// MARK: - Tool Status Indicator
struct ToolStatusIndicator: View {
    @EnvironmentObject var toolRunner: ToolRunner
    
    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: !toolRunner.runningTools.isEmpty ? "gearshape.2.fill" : "gearshape.2")
                .foregroundColor(!toolRunner.runningTools.isEmpty ? .orange : .secondary)
                .font(.caption)
            
            Text("\(toolRunner.runningTools.count) Tools")
                .font(.caption)
                .fontWeight(.semibold)
        }
        .help("Running Tools: \(toolRunner.runningTools.map { $0.name }.joined(separator: ", "))")
    }
}


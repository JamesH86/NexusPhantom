import SwiftUI
import AVFoundation

struct ContentView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var voiceManager: VoiceManager
    @EnvironmentObject var aiOrchestrator: AIOrchestrator
    @EnvironmentObject var toolRunner: ToolRunner
    @StateObject private var aiDroneSystem = AIDroneSystem()
    @State private var showingToolGUI = false
    @State private var selectedTool: CyberSecTool?
    
    var body: some View {
        NavigationSplitView {
            // Sidebar Navigation with Scroll Support
            ScrollView {
                SidebarView()
            }
        } detail: {
            // Main Content Area with Enhanced Layout
            VStack(spacing: 0) {
                // Enhanced Status Bar
                EnhancedStatusBarView()
                    .background(.regularMaterial)
                
                // Main Content with Scroll Support
                ScrollView {
                    LazyVStack(spacing: 20) {
                        MainContentView()
                    }
                    .padding()
                }
            }
        }
        .navigationSplitViewStyle(.balanced)
        .environmentObject(aiDroneSystem)
        .sheet(isPresented: $showingToolGUI) {
            if let tool = selectedTool {
                ToolGUIWrapper(tool: tool)
                    .frame(minWidth: 800, minHeight: 600)
            }
        }
        .overlay(alignment: .topTrailing) {
            if appState.isVoiceModeActive {
                VoiceOverlay()
                    .padding()
                    .transition(.asymmetric(
                        insertion: .move(edge: .top).combined(with: .opacity),
                        removal: .move(edge: .top).combined(with: .opacity)
                    ))
            }
        }
        .overlay(alignment: .bottomTrailing) {
            VStack(alignment: .trailing, spacing: 12) {
                // AI Drone Control Panel
                AIDroneControlPanel()
                
                // Notification Panel
                NotificationPanel()
            }
            .padding()
        }
        .task {
            await initializeEnhancedSystems()
        }
    }
    
    private func initializeEnhancedSystems() async {
        await toolRunner.initializeTools()
        await aiDroneSystem.initialize()
        await aiDroneSystem.startRealTimeLearning()
    }
}

// MARK: - Sidebar Navigation
struct SidebarView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var toolRunner: ToolRunner
    // @EnvironmentObject var threatDetectionEngine: ThreatDetectionEngine
    
    var body: some View {
        VStack(spacing: 0) {
            // App Header
            VStack {
                Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                    .font(.system(size: 40, weight: .bold))
                    .foregroundStyle(.linearGradient(
                        colors: [.cyan, .purple],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ))
                
                Text("NEXUS PHANTOM")
                    .font(.headline)
                    .fontWeight(.bold)
                    .foregroundColor(.primary)
                
                Text("Elite Cyber AI")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding(.vertical, 20)
            
            Divider()
            
            // Navigation Menu
            List(AppState.MainView.allCases, id: \.self, selection: $appState.currentView) { view in
                NavigationLink(value: view) {
                    HStack {
                        Image(systemName: view.icon)
                            .frame(width: 20)
                            .foregroundColor(.accentColor)
                        Text(view.rawValue)
                            .fontWeight(.medium)
                    }
                    .padding(.vertical, 4)
                }
            }
            .listStyle(.sidebar)
            
            Spacer()
            
            // Quick Actions
            VStack(spacing: 8) {
                QuickActionButton(
                    title: "Emergency Stop",
                    icon: "stop.circle.fill",
                    color: .red
                ) {
                    Task {
                        await emergencyStop()
                    }
                }
                
                QuickActionButton(
                    title: "Full Scan",
                    icon: "magnifyingglass.circle.fill",
                    color: .orange
                ) {
                    Task {
                        await initiateFullScan()
                    }
                }
            }
            .padding()
        }
        .frame(minWidth: 250)
        .background(Color(NSColor.controlBackgroundColor))
    }
    
    private func emergencyStop() async {
        // Stop all running operations
        await toolRunner.stopAllOperations()
        // await threatDetectionEngine.pauseMonitoring()
    }
    
    private func initiateFullScan() async {
        // Start comprehensive security scan
        await toolRunner.runFullSecurityScan()
    }
}

// MARK: - Main Content Views
struct MainContentView: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        Group {
            switch appState.currentView {
            case .dashboard:
                DashboardView()
            case .reconnaissance:
                ReconnaissanceView()
            case .exploitation:
                ExploitationView()
            case .defense:
                DefenseView()
            case .criticalInfrastructure:
                CriticalInfrastructureView()
            case .bugBounty:
                BugBountyView()
            case .compliance:
                ComplianceView()
            case .research:
                ResearchView()
            case .reports:
                ReportsView()
            case .settings:
                SettingsView()
            }
        }
        .background(Color(NSColor.windowBackgroundColor))
    }
}

// MARK: - Voice Control Components
struct VoiceControlButton: View {
    @EnvironmentObject var voiceManager: VoiceManager
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        Button(action: {
            appState.isVoiceModeActive.toggle()
            if appState.isVoiceModeActive {
                voiceManager.startListening()
            } else {
                voiceManager.stopListening()
            }
        }) {
            Image(systemName: appState.isVoiceModeActive ? "mic.fill" : "mic")
                .foregroundColor(appState.isVoiceModeActive ? .red : .accentColor)
        }
        .buttonStyle(.borderless)
        .help("Toggle Voice Mode (⌘M)")
        .keyboardShortcut("m", modifiers: .command)
    }
}

struct VoiceOverlay: View {
    @EnvironmentObject var voiceManager: VoiceManager
    
    var body: some View {
        VStack {
            HStack {
                Image(systemName: "waveform")
                    .foregroundColor(.red)
                    // .symbolEffect(.pulse) // Requires macOS 14+
                
                Text("Voice Mode Active")
                    .font(.headline)
                    .foregroundColor(.red)
            }
            
            if !voiceManager.lastTranscription.isEmpty {
                Text(voiceManager.lastTranscription)
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
        .shadow(radius: 8)
    }
}

// MARK: - Status Indicators
struct ThreatStatusIndicator: View {
    @EnvironmentObject var threatEngine: ThreatDetectionEngine
    
    var body: some View {
        HStack {
            Circle()
                .fill(threatEngine.currentThreatLevel.color)
                .frame(width: 8, height: 8)
            
            Text(threatEngine.currentThreatLevel.rawValue)
                .font(.caption)
                .fontWeight(.semibold)
        }
        .help("Current Threat Level")
    }
}

struct AIStatusIndicator: View {
    @EnvironmentObject var aiOrchestrator: AIOrchestrator
    
    var body: some View {
        HStack {
            Image(systemName: aiOrchestrator.isProcessing ? "brain" : "brain.head.profile")
                .foregroundColor(aiOrchestrator.isProcessing ? .green : .secondary)
                // .symbolEffect(.pulse, isActive: aiOrchestrator.isProcessing) // Requires macOS 14+
            
            Text("\\(aiOrchestrator.activeModels.count) AI")
                .font(.caption)
                .fontWeight(.semibold)
        }
        .help("AI Models Active: \(aiOrchestrator.activeModels.joined(separator: ", "))")
    }
}

// MARK: - Quick Action Button
struct QuickActionButton: View {
    let title: String
    let icon: String
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack {
                Image(systemName: icon)
                Text(title)
                    .font(.caption)
                    .fontWeight(.medium)
            }
            .foregroundColor(.white)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(color, in: RoundedRectangle(cornerRadius: 8))
        }
        .buttonStyle(.borderless)
    }
}

// MARK: - Notification Panel
struct NotificationPanel: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        if !appState.notifications.isEmpty {
            VStack(alignment: .trailing, spacing: 8) {
                ForEach(appState.notifications.prefix(3)) { notification in
                    NotificationCard(notification: notification)
                }
                
                if appState.notifications.count > 3 {
                    Text("+ \(appState.notifications.count - 3) more")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .frame(maxWidth: 300)
        }
    }
}

struct NotificationCard: View {
    let notification: SecurityNotification
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(notification.title)
                    .font(.headline)
                    .fontWeight(.semibold)
                
                Spacer()
                
                Text(notification.severity.rawValue)
                    .font(.caption)
                    .fontWeight(.bold)
                    .foregroundColor(notification.severity.color)
            }
            
            Text(notification.message)
                .font(.body)
                .foregroundColor(.secondary)
                .lineLimit(3)
            
            Text(notification.timestamp.formatted(.relative(presentation: .named)))
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
        .shadow(radius: 4)
    }
}


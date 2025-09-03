import SwiftUI
import Foundation
import AVFoundation
import Speech
import Combine
import NexusPhantomCore

// MARK: - Main App Structure
@main
struct NexusPhantomApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var voiceManager = VoiceManager()
    @StateObject private var aiOrchestrator = AIOrchestrator()
    @StateObject private var toolRunner = ToolRunner()
    // @StateObject private var threatDetection = ThreatDetectionEngine()
    @StateObject private var appState = AppState()
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(voiceManager)
                .environmentObject(aiOrchestrator)
                .environmentObject(toolRunner)
                .environmentObject(appState)
                .frame(minWidth: 1200, minHeight: 800)
                .background(Color.black)
                .preferredColorScheme(.dark)
        }
        .windowStyle(.hiddenTitleBar)
        .windowToolbarStyle(.unified)
        .commands {
            NexusPhantomCommands()
        }
        
        Settings {
            SettingsView()
                .environmentObject(appState)
                .environmentObject(voiceManager)
                .environmentObject(aiOrchestrator)
                .environmentObject(toolRunner)
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        print("🔥 NEXUS PHANTOM Initializing...")
        
        // Handle command line arguments
        handleCommandLineArguments()
        
        // Setup security monitoring (without permissions for now)
        setupSecurityMonitoring()
        
        print("✅ NEXUS PHANTOM Ready for cyber operations")
        print("ℹ️  Note: Microphone and speech permissions will be requested when needed")
    }
    
    func applicationWillTerminate(_ notification: Notification) {
        print("🔒 NEXUS PHANTOM Shutting down securely...")
        // Clean up any sensitive data
        cleanupOnExit()
    }
    
    private func handleCommandLineArguments() {
        let args = CommandLine.arguments
        
        if args.contains("--gui") {
            print("🖥️ Launching GUI mode")
        } else if args.contains("--voice-only") {
            print("🎤 Launching voice-only mode")
        } else if args.contains("--daemon") {
            print("⚙️ Running as background service")
        } else if args.contains("--test-voice") {
            print("🎤 Testing voice capabilities")
            testVoiceCapabilities()
        }
    }
    
    private func requestPermissions() {
        // Request microphone permission - macOS uses different API
        #if os(iOS)
        AVAudioSession.sharedInstance().requestRecordPermission { granted in
            DispatchQueue.main.async {
                print(granted ? "🎤 Microphone access granted" : "❌ Microphone access denied")
            }
        }
        #else
        // macOS permission handling
        print("🎤 Microphone permission handled by macOS")
        #endif
        
        // Request speech recognition permission
        SFSpeechRecognizer.requestAuthorization { status in
            DispatchQueue.main.async {
                switch status {
                case .authorized:
                    print("🗣️ Speech recognition authorized")
                case .denied, .restricted, .notDetermined:
                    print("❌ Speech recognition not authorized")
                @unknown default:
                    print("❓ Unknown speech recognition status")
                }
            }
        }
    }
    
    private func setupSecurityMonitoring() {
        print("🛡️ Setting up real-time threat monitoring")
    }
    
    private func testVoiceCapabilities() {
        let synthesizer = AVSpeechSynthesizer()
        let utterance = AVSpeechUtterance(string: "NEXUS PHANTOM voice systems operational. Ready for cyber warfare commands.")
        utterance.voice = AVSpeechSynthesisVoice(language: "en-US")
        utterance.rate = 0.5
        synthesizer.speak(utterance)
        
        print("🎤 Voice test completed")
    }
    
    private func cleanupOnExit() {
        print("🧹 Cleaning up sensitive data...")
        
        let tempDir = "/tmp/nexus_phantom"
        try? FileManager.default.removeItem(atPath: tempDir)
        
        print("✅ Cleanup completed")
    }
}

// MARK: - Core App State Management
@MainActor
class AppState: ObservableObject {
    @Published var currentView: MainView = .dashboard
    @Published var isVoiceModeActive: Bool = false
    @Published var isFullscreen: Bool = false
    @Published var theme: AppTheme = .cyberpunk
    @Published var notifications: [SecurityNotification] = []
    
    enum MainView: String, CaseIterable, Identifiable {
        case dashboard = "Dashboard"
        case reconnaissance = "Reconnaissance"
        case exploitation = "Exploitation"
        case defense = "Defense"
        case bugBounty = "Bug Bounty"
        case compliance = "Compliance"
        case research = "Research"
        case reports = "Reports"
        case settings = "Settings"
        
        var id: String { rawValue }
        
        var icon: String {
            switch self {
            case .dashboard: return "chart.line.uptrend.xyaxis"
            case .reconnaissance: return "eye.trianglebadge.exclamationmark"
            case .exploitation: return "bolt.shield"
            case .defense: return "shield.checkerboard"
            case .bugBounty: return "dollarsign.circle"
            case .compliance: return "checkmark.seal"
            case .research: return "lightbulb.min"
            case .reports: return "doc.text.magnifyingglass"
            case .settings: return "gearshape"
            }
        }
    }
    
    enum AppTheme: String, CaseIterable {
        case cyberpunk = "Cyberpunk"
        case matrix = "Matrix"
        case terminal = "Terminal"
        case enterprise = "Enterprise"
    }
}

// MARK: - Security Notification System
struct SecurityNotification: Identifiable, Codable {
    let id = UUID()
    let title: String
    let message: String
    let severity: Severity
    let timestamp: Date
    let source: String
    
    enum Severity: String, Codable, CaseIterable {
        case critical = "Critical"
        case high = "High" 
        case medium = "Medium"
        case low = "Low"
        case info = "Info"
        
        var color: Color {
            switch self {
            case .critical: return .red
            case .high: return .orange
            case .medium: return .yellow
            case .low: return .blue
            case .info: return .green
            }
        }
    }
}

// MARK: - Menu Commands
struct NexusPhantomCommands: Commands {
    var body: some Commands {
        CommandGroup(after: .newItem) {
            Button("New Security Scan") {
                // Trigger new security scan
            }
            .keyboardShortcut("n", modifiers: [.command, .shift])
            
            Button("Start Bug Bounty Hunt") {
                // Launch bug bounty automation
            }
            .keyboardShortcut("b", modifiers: [.command, .shift])
            
            Button("Emergency Threat Response") {
                // Activate emergency response mode
            }
            .keyboardShortcut("e", modifiers: [.command, .shift])
        }
        
        CommandMenu("NEXUS Tools") {
            Button("Launch Burp Suite") {
                // Launch Burp Suite
            }
            .keyboardShortcut("u", modifiers: [.command, .option])
            
            Button("Activate Metasploit") {
                // Start Metasploit framework
            }
            .keyboardShortcut("m", modifiers: [.command, .option])
            
            Button("Network Reconnaissance") {
                // Start network recon
            }
            .keyboardShortcut("r", modifiers: [.command, .option])
        }
    }
}

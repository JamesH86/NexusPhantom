import SwiftUI
import AVFoundation

struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var voiceManager: VoiceManager
    // @EnvironmentObject var threatEngine: ThreatDetectionEngine
    @EnvironmentObject var aiOrchestrator: AIOrchestrator
    @EnvironmentObject var toolRunner: ToolRunner
    
    @State private var selectedTab: SettingsTab = .general
    @State private var isExporting = false
    @State private var importFileURL: URL?
    
    enum SettingsTab: String, CaseIterable {
        case general = "General"
        case voice = "Voice & AI"
        case security = "Security"
        case tools = "Tools"
        case automation = "Automation"
        case advanced = "Advanced"
        case about = "About"
        
        var icon: String {
            switch self {
            case .general: return "gear"
            case .voice: return "mic.circle"
            case .security: return "shield.checkerboard"
            case .tools: return "wrench.and.screwdriver"
            case .automation: return "bolt.circle"
            case .advanced: return "cpu"
            case .about: return "info.circle"
            }
        }
    }
    
    var body: some View {
        HStack(spacing: 0) {
            // Settings sidebar
            VStack(alignment: .leading, spacing: 0) {
                Text("NEXUS PHANTOM")
                    .font(.title2)
                    .fontWeight(.bold)
                    .padding()
                
                Text("Configuration")
                    .font(.headline)
                    .foregroundColor(.secondary)
                    .padding(.horizontal)
                
                List(SettingsTab.allCases, id: \.self, selection: $selectedTab) { tab in
                    HStack {
                        Image(systemName: tab.icon)
                            .frame(width: 20)
                            .foregroundColor(.accentColor)
                        Text(tab.rawValue)
                            .fontWeight(.medium)
                    }
                    .padding(.vertical, 4)
                }
                .listStyle(.sidebar)
                
                Spacer()
            }
            .frame(width: 200)
            .background(Color(NSColor.controlBackgroundColor))
            
            Divider()
            
            // Settings content
            ScrollView {
                settingsContent
                    .padding()
            }
            .frame(maxWidth: .infinity)
        }
        .frame(width: 900, height: 650)
        .navigationTitle("Settings")
    }
    
    @ViewBuilder
    private var settingsContent: some View {
        switch selectedTab {
        case .general:
            GeneralSettingsView()
        case .voice:
            VoiceSettingsView()
        case .security:
            SecuritySettingsView()
        case .tools:
            ToolsSettingsView()
        case .automation:
            AutomationSettingsView()
        case .advanced:
            AdvancedSettingsView()
        case .about:
            AboutView()
        }
    }
}

// MARK: - General Settings
struct GeneralSettingsView: View {
    @EnvironmentObject var appState: AppState
    @AppStorage("launchAtStartup") private var launchAtStartup = false
    @AppStorage("enableNotifications") private var enableNotifications = true
    @AppStorage("darkModeForced") private var darkModeForced = true
    @AppStorage("autoUpdateEnabled") private var autoUpdateEnabled = true
    
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            SettingsSection("Appearance") {
                VStack(alignment: .leading, spacing: 12) {
                    Picker("Theme", selection: $appState.theme) {
                        ForEach(AppState.AppTheme.allCases, id: \.self) { theme in
                            Text(theme.rawValue).tag(theme)
                        }
                    }
                    .pickerStyle(.segmented)
                    
                    Toggle("Force Dark Mode", isOn: $darkModeForced)
                        .help("Override system appearance settings")
                }
            }
            
            SettingsSection("Startup") {
                VStack(alignment: .leading, spacing: 12) {
                    Toggle("Launch at Startup", isOn: $launchAtStartup)
                        .help("Start NEXUS PHANTOM when macOS starts")
                    
                    Toggle("Enable Notifications", isOn: $enableNotifications)
                        .help("Show security alerts and system notifications")
                    
                    Toggle("Auto-Update", isOn: $autoUpdateEnabled)
                        .help("Automatically check for and install updates")
                }
            }
            
            SettingsSection("Performance") {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("CPU Usage Limit")
                        Spacer()
                        Text("80%")
                            .foregroundColor(.secondary)
                    }
                    
                    HStack {
                        Text("Memory Usage Limit")
                        Spacer()
                        Text("4 GB")
                            .foregroundColor(.secondary)
                    }
                    
                    HStack {
                        Text("Concurrent Operations")
                        Spacer()
                        Text("10")
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
    }
}

// MARK: - Voice Settings
struct VoiceSettingsView: View {
    @EnvironmentObject var voiceManager: VoiceManager
    @EnvironmentObject var aiOrchestrator: AIOrchestrator
    @State private var availableVoices: [AVSpeechSynthesisVoice] = []
    
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            SettingsSection("Speech Recognition") {
                VStack(alignment: .leading, spacing: 12) {
                    Toggle("Voice Commands", isOn: .constant(true))
                        .help("Enable voice command processing")
                    
                    Toggle("Continuous Listening", isOn: .constant(false))
                        .help("Always listen for voice commands")
                    
                    HStack {
                        Text("Language")
                        Spacer()
                        Picker("Language", selection: .constant("en-US")) {
                            Text("English (US)").tag("en-US")
                            Text("English (UK)").tag("en-GB")
                        }
                        .frame(width: 150)
                    }
                }
            }
            
            SettingsSection("Speech Synthesis") {
                VStack(alignment: .leading, spacing: 12) {
                    if let selectedVoice = voiceManager.selectedVoice {
                        HStack {
                            Text("Voice")
                            Spacer()
                            Picker("Voice", selection: $voiceManager.selectedVoice) {
                                ForEach(availableVoices, id: \.name) { voice in
                                    Text(voice.name).tag(voice as AVSpeechSynthesisVoice?)
                                }
                            }
                            .frame(width: 200)
                        }
                    }
                    
                    VStack {
                        HStack {
                            Text("Speech Rate")
                            Spacer()
                            Text("\(voiceManager.speechRate, specifier: "%.1f")")
                                .foregroundColor(.secondary)
                        }
                        Slider(value: $voiceManager.speechRate, in: 0.1...1.0)
                    }
                    
                    VStack {
                        HStack {
                            Text("Speech Pitch")
                            Spacer()
                            Text("\(voiceManager.speechPitch, specifier: "%.1f")")
                                .foregroundColor(.secondary)
                        }
                        Slider(value: $voiceManager.speechPitch, in: 0.5...2.0)
                    }
                    
                    VStack {
                        HStack {
                            Text("Volume")
                            Spacer()
                            Text("\(voiceManager.speechVolume, specifier: "%.1f")")
                                .foregroundColor(.secondary)
                        }
                        Slider(value: $voiceManager.speechVolume, in: 0.0...1.0)
                    }
                }
            }
            
            SettingsSection("AI Models") {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(aiOrchestrator.activeModels, id: \.self) { model in
                        HStack {
                            Circle()
                                .fill(.green)
                                .frame(width: 8, height: 8)
                            
                            Text(model)
                                .fontWeight(.medium)
                            
                            Spacer()
                            
                            if let metrics = aiOrchestrator.modelPerformance[model] {
                                VStack(alignment: .trailing) {
                                    Text("\(metrics.avgResponseTime, specifier: "%.1f")s")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                    Text("\(metrics.successRate * 100, specifier: "%.0f")% success")
                                        .font(.caption)
                                        .foregroundColor(.green)
                                }
                            }
                        }
                        .padding(.vertical, 2)
                    }
                }
            }
        }
        .onAppear {
            availableVoices = AVSpeechSynthesisVoice.speechVoices()
        }
    }
}

// MARK: - Security Settings
struct SecuritySettingsView: View {
    // @EnvironmentObject var threatEngine: ThreatDetectionEngine
    @AppStorage("autoMitigation") private var autoMitigation = true
    @AppStorage("threatIntelEnabled") private var threatIntelEnabled = true
    @AppStorage("encryptLogs") private var encryptLogs = true
    @AppStorage("retentionDays") private var retentionDays = 90.0
    @State private var isMonitoring = true
    
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            SettingsSection("Threat Detection") {
                VStack(alignment: .leading, spacing: 12) {
                    Toggle("Real-time Monitoring", isOn: $isMonitoring)
                        .help("Enable continuous threat monitoring")
                    
                    Toggle("Auto-Mitigation", isOn: $autoMitigation)
                        .help("Automatically respond to critical threats")
                    
                    Toggle("Threat Intelligence", isOn: $threatIntelEnabled)
                        .help("Use external threat intelligence feeds")
                    
                    HStack {
                        Text("Detection Sensitivity")
                        Spacer()
                        Picker("Sensitivity", selection: .constant("High")) {
                            Text("Low").tag("Low")
                            Text("Medium").tag("Medium")
                            Text("High").tag("High")
                            Text("Paranoid").tag("Paranoid")
                        }
                        .frame(width: 120)
                    }
                }
            }
            
            SettingsSection("Data Protection") {
                VStack(alignment: .leading, spacing: 12) {
                    Toggle("Encrypt Logs", isOn: $encryptLogs)
                        .help("Encrypt all log files with AES-256")
                    
                    VStack {
                        HStack {
                            Text("Data Retention")
                            Spacer()
                            Text("\\(Int(retentionDays)) days")
                                .foregroundColor(.secondary)
                        }
                        Slider(value: $retentionDays, in: 7...365, step: 1)
                    }
                    
                    HStack {
                        Text("Secure Storage")
                        Spacer()
                        Text("Keychain")
                            .foregroundColor(.green)
                    }
                }
            }
            
            SettingsSection("Access Control") {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("Root Access")
                        Spacer()
                        Text("Authorized")
                            .foregroundColor(.orange)
                    }
                    
                    HStack {
                        Text("Network Scanning")
                        Spacer()
                        Text("Enabled")
                            .foregroundColor(.green)
                    }
                    
                    HStack {
                        Text("Exploit Execution")
                        Spacer()
                        Text("Restricted")
                            .foregroundColor(.yellow)
                    }
                }
            }
        }
    }
}

// MARK: - Tools Settings
struct ToolsSettingsView: View {
    @EnvironmentObject var toolRunner: ToolRunner
    @State private var selectedCategory: ToolRunner.ToolCategory = .reconnaissance
    
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            SettingsSection("Tool Categories") {
                VStack {
                    Picker("Category", selection: $selectedCategory) {
                        ForEach(ToolRunner.ToolCategory.allCases, id: \.self) { category in
                            Text(category.rawValue).tag(category)
                        }
                    }
                    .pickerStyle(.segmented)
                    
                    // Tools in selected category
                    let categoryTools = toolRunner.availableTools.filter { $0.category == selectedCategory }
                    
                    LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 16) {
                        ForEach(categoryTools) { tool in
                            ToolStatusCard(tool: tool)
                        }
                    }
                }
            }
            
            SettingsSection("Installation") {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Button("Install Missing Tools") {
                            Task {
                                await toolRunner.initializeTools()
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        
                        Spacer()
                        
                        let installedCount = toolRunner.availableTools.filter { $0.isInstalled }.count
                        let totalCount = toolRunner.availableTools.count
                        
                        Text("\\(installedCount)/\\(totalCount) tools ready")
                            .foregroundColor(installedCount == totalCount ? .green : .orange)
                    }
                    
                    Button("Run Installation Script") {
                        runInstallationScript()
                    }
                    .buttonStyle(.bordered)
                    
                    Button("Verify All Tools") {
                        runToolVerification()
                    }
                    .buttonStyle(.bordered)
                }
            }
        }
    }
    
    private func runInstallationScript() {
        let script = "/Users/\\(NSUserName())/CyberSecAI/NexusPhantom/install_tools.sh"
        let process = Process()
        process.launchPath = "/bin/bash"
        process.arguments = [script]
        
        do {
            try process.run()
        } catch {
            print("Failed to run installation script: \\(error)")
        }
    }
    
    private func runToolVerification() {
        let script = "/opt/nexusphantom/verify_tools.py"
        let process = Process()
        process.launchPath = "/usr/local/bin/python3"
        process.arguments = [script]
        
        do {
            try process.run()
        } catch {
            print("Failed to run verification script: \\(error)")
        }
    }
}

struct ToolStatusCard: View {
    let tool: CyberSecTool
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(tool.name)
                    .font(.headline)
                    .fontWeight(.semibold)
                
                Spacer()
                
                Image(systemName: tool.isInstalled ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundColor(tool.isInstalled ? .green : .red)
            }
            
            Text(tool.description)
                .font(.caption)
                .foregroundColor(.secondary)
                .lineLimit(2)
            
            Text(tool.category.rawValue)
                .font(.caption)
                .fontWeight(.medium)
                .foregroundColor(.blue)
        }
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
    }
}

// MARK: - Automation Settings
struct AutomationSettingsView: View {
    @EnvironmentObject var aiOrchestrator: AIOrchestrator
    @AppStorage("bugBountyAutoMode") private var bugBountyAutoMode = false
    @AppStorage("autoReporting") private var autoReporting = true
    @AppStorage("autoSubmission") private var autoSubmission = false
    @AppStorage("maxConcurrentScans") private var maxConcurrentScans = 5.0
    @AppStorage("scanTimeoutMinutes") private var scanTimeoutMinutes = 30.0
    
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            SettingsSection("Bug Bounty Automation") {
                VStack(alignment: .leading, spacing: 12) {
                    Toggle("Fully Autonomous Mode", isOn: $bugBountyAutoMode)
                        .help("Enable completely autonomous bug bounty hunting")
                    
                    Toggle("Auto-Generate Reports", isOn: $autoReporting)
                        .help("Automatically generate professional reports")
                    
                    Toggle("Auto-Submit (DANGEROUS)", isOn: $autoSubmission)
                        .help("⚠️ Automatically submit reports to bug bounty programs")
                        .foregroundColor(autoSubmission ? .red : .primary)
                }
            }
            
            SettingsSection("Scanning Configuration") {
                VStack(alignment: .leading, spacing: 12) {
                    VStack {
                        HStack {
                            Text("Max Concurrent Scans")
                            Spacer()
                            Text("\\(Int(maxConcurrentScans))")
                                .foregroundColor(.secondary)
                        }
                        Slider(value: $maxConcurrentScans, in: 1...20, step: 1)
                    }
                    
                    VStack {
                        HStack {
                            Text("Scan Timeout")
                            Spacer()
                            Text("\\(Int(scanTimeoutMinutes)) minutes")
                                .foregroundColor(.secondary)
                        }
                        Slider(value: $scanTimeoutMinutes, in: 5...120, step: 5)
                    }
                }
            }
            
            SettingsSection("AI Configuration") {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(aiOrchestrator.activeModels, id: \.self) { model in
                        HStack {
                            Text(model)
                            Spacer()
                            Toggle("", isOn: .constant(true))
                        }
                    }
                }
            }
        }
    }
}

// MARK: - Advanced Settings
struct AdvancedSettingsView: View {
    @State private var debugMode = false
    @State private var developmentMode = false
    @State private var expertMode = false
    @State private var apiKeys: [String: String] = [:]
    
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            SettingsSection("Developer Mode") {
                VStack(alignment: .leading, spacing: 12) {
                    Toggle("Debug Logging", isOn: $debugMode)
                        .help("Enable verbose debug logging")
                    
                    Toggle("Development Mode", isOn: $developmentMode)
                        .help("Enable development features and testing")
                    
                    Toggle("Expert Mode", isOn: $expertMode)
                        .help("Unlock advanced cybersecurity features")
                }
            }
            
            SettingsSection("API Configuration") {
                VStack(alignment: .leading, spacing: 12) {
                    APIKeyField(service: "Shodan", key: $apiKeys["shodan"])
                    APIKeyField(service: "VirusTotal", key: $apiKeys["virustotal"])
                    APIKeyField(service: "Censys", key: $apiKeys["censys"])
                    APIKeyField(service: "HackerOne", key: $apiKeys["hackerone"])
                    APIKeyField(service: "OpenAI", key: $apiKeys["openai"])
                    APIKeyField(service: "Perplexity", key: $apiKeys["perplexity"])
                }
            }
            
            SettingsSection("Data Management") {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Button("Export Configuration") {
                            exportConfiguration()
                        }
                        .buttonStyle(.bordered)
                        
                        Button("Import Configuration") {
                            importConfiguration()
                        }
                        .buttonStyle(.bordered)
                        
                        Spacer()
                    }
                    
                    HStack {
                        Button("Clear Cache") {
                            clearCache()
                        }
                        .buttonStyle(.bordered)
                        
                        Button("Reset to Defaults") {
                            resetToDefaults()
                        }
                        .buttonStyle(.bordered)
                        .foregroundColor(.red)
                        
                        Spacer()
                    }
                }
            }
        }
    }
    
    private func exportConfiguration() {
        // Export all settings to JSON file
    }
    
    private func importConfiguration() {
        // Import settings from JSON file
    }
    
    private func clearCache() {
        // Clear all cached data
    }
    
    private func resetToDefaults() {
        // Reset all settings to default values
    }
}

// MARK: - About View
struct AboutView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            // App info section
            VStack {
                Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                    .font(.system(size: 80, weight: .bold))
                    .foregroundStyle(.linearGradient(
                        colors: [.cyan, .purple],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ))
                
                Text("NEXUS PHANTOM")
                    .font(.largeTitle)
                    .fontWeight(.bold)
                
                Text("Elite Cybersecurity AI Platform")
                    .font(.title2)
                    .foregroundColor(.secondary)
                
                Text("Version 1.0.0 (Build 1)")
                    .font(.body)
                    .foregroundColor(.secondary)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical)
            
            SettingsSection("Platform Details") {
                VStack(alignment: .leading, spacing: 12) {
                    InfoRow(label: "Full Name", value: "Network EXploit Unified System - Penetration & Hacking Adversarial Network Tool for Offensive Management")
                    InfoRow(label: "Platform", value: "macOS 13.0+")
                    InfoRow(label: "Architecture", value: "Swift + Python + AI")
                    InfoRow(label: "License", value: "Enterprise Security License")
                }
            }
            
            SettingsSection("Capabilities") {
                VStack(alignment: .leading, spacing: 8) {
                    CapabilityRow(capability: "Autonomous Bug Bounty Hunting", enabled: true)
                    CapabilityRow(capability: "Real-time Threat Detection", enabled: true)
                    CapabilityRow(capability: "AI-Powered Exploitation", enabled: true)
                    CapabilityRow(capability: "Voice Command Interface", enabled: true)
                    CapabilityRow(capability: "Enterprise Compliance Auditing", enabled: true)
                    CapabilityRow(capability: "Multi-AI Model Integration", enabled: true)
                    CapabilityRow(capability: "NSA Tool Integration", enabled: true)
                    CapabilityRow(capability: "Root & Jailbreak Assistance", enabled: true)
                }
            }
            
            SettingsSection("Legal & Compliance") {
                VStack(alignment: .leading, spacing: 12) {
                    Text("⚠️ This software is designed for authorized cybersecurity professionals only.")
                        .font(.body)
                        .foregroundColor(.orange)
                    
                    Text("• Only use on systems you own or have explicit authorization to test")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    Text("• Follow responsible disclosure practices for any vulnerabilities discovered")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    Text("• Comply with all applicable laws and regulations")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
    }
}

// MARK: - Helper Views

struct SettingsSection<Content: View>: View {
    let title: String
    let content: Content
    
    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.title2)
                .fontWeight(.bold)
            
            content
        }
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
    }
}

struct APIKeyField: View {
    let service: String
    @Binding var key: String?
    @State private var isSecure = true
    
    var body: some View {
        HStack {
            Text(service)
                .frame(width: 100, alignment: .leading)
            
            if isSecure {
                SecureField("API Key", text: Binding(
                    get: { key ?? "" },
                    set: { key = $0.isEmpty ? nil : $0 }
                ))
            } else {
                TextField("API Key", text: Binding(
                    get: { key ?? "" },
                    set: { key = $0.isEmpty ? nil : $0 }
                ))
            }
            
            Button(action: { isSecure.toggle() }) {
                Image(systemName: isSecure ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
        }
    }
}

struct InfoRow: View {
    let label: String
    let value: String
    
    var body: some View {
        HStack {
            Text(label)
                .fontWeight(.medium)
            Spacer()
            Text(value)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.trailing)
        }
    }
}

struct CapabilityRow: View {
    let capability: String
    let enabled: Bool
    
    var body: some View {
        HStack {
            Image(systemName: enabled ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundColor(enabled ? .green : .red)
            
            Text(capability)
                .font(.body)
            
            Spacer()
        }
    }
}


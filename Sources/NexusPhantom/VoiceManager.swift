import SwiftUI
import Speech
import AVFoundation
import Combine
import os.log

@MainActor
class VoiceManager: NSObject, ObservableObject {
    @Published var isListening = false
    @Published var isProcessingVoice = false
    @Published var lastTranscription = ""
    @Published var isAvailable = false
    @Published var confidence: Float = 0.0
    
    // Voice settings
    @Published var speechRate: Float = 0.5
    @Published var speechPitch: Float = 1.0
    @Published var speechVolume: Float = 1.0
    @Published var selectedVoice: AVSpeechSynthesisVoice?
    
    // Voice commands and cybersecurity integration
    @Published var voiceCommands: [VoiceCommand] = []
    @Published var lastExecutedCommand: VoiceCommand?
    
    private var speechRecognizer: SFSpeechRecognizer?
    private var recognitionRequest: SFSpeechAudioBufferRecognitionRequest?
    private var recognitionTask: SFSpeechRecognitionTask?
    private let audioEngine = AVAudioEngine()
    private let speechSynthesizer = AVSpeechSynthesizer()
    
    private let logger = Logger(subsystem: "NexusPhantom", category: "VoiceManager")
    private var cancellables = Set<AnyCancellable>()
    
    override init() {
        super.init()
        setupVoiceSystem()
        setupCybersecurityCommands()
        speechSynthesizer.delegate = self
    }
    
    private func setupVoiceSystem() {
        selectedVoice = AVSpeechSynthesisVoice(language: "en-US")
        
        // Don't create speech recognizer or request permissions immediately
        logger.info("🎤 Voice system initialized (permissions deferred)")
    }
    
    private func requestSpeechAuthorization() {
        SFSpeechRecognizer.requestAuthorization { authStatus in
            DispatchQueue.main.async {
                switch authStatus {
                case .authorized:
                    self.isAvailable = true
                    self.logger.info("✅ Speech recognition authorized")
                case .denied, .restricted, .notDetermined:
                    self.isAvailable = false
                    self.logger.warning("❌ Speech recognition not available: \(authStatus.rawValue)")
                @unknown default:
                    self.isAvailable = false
                }
            }
        }
    }
    
    private func requestMicrophonePermission() {
        #if os(iOS)
        AVAudioSession.sharedInstance().requestRecordPermission { granted in
            DispatchQueue.main.async {
                if granted {
                    self.isListening = true
                    print("🎤 Microphone permission granted")
                } else {
                    print("❌ Microphone permission denied")
                }
            }
        }
        #else
        // macOS handles microphone permissions differently
        DispatchQueue.main.async {
            self.isListening = true
            print("🎤 Microphone access configured for macOS")
        }
        #endif
    }
    
    private func setupCybersecurityCommands() {
        voiceCommands = [
            // Navigation Commands
            VoiceCommand(phrase: "dashboard", action: .navigation, confidence: 0.9, parameters: ["target": "dashboard"]),
            VoiceCommand(phrase: "reconnaissance", action: .navigation, confidence: 0.9, parameters: ["target": "recon"]),
            VoiceCommand(phrase: "exploitation", action: .navigation, confidence: 0.9, parameters: ["target": "exploit"]),
            VoiceCommand(phrase: "bug bounty", action: .navigation, confidence: 0.9, parameters: ["target": "bugbounty"]),
            
            // Cybersecurity Commands
            VoiceCommand(phrase: "start nmap scan", action: .cybersecurity, confidence: 0.95, parameters: ["tool": "nmap", "action": "scan"]),
            VoiceCommand(phrase: "launch burp suite", action: .cybersecurity, confidence: 0.95, parameters: ["tool": "burp", "action": "launch"]),
            VoiceCommand(phrase: "run nuclei", action: .cybersecurity, confidence: 0.9, parameters: ["tool": "nuclei", "action": "scan"]),
            VoiceCommand(phrase: "threat analysis", action: .cybersecurity, confidence: 0.9, parameters: ["tool": "threat", "action": "analyze"]),
            VoiceCommand(phrase: "start metasploit", action: .cybersecurity, confidence: 0.95, parameters: ["tool": "metasploit", "action": "launch"]),
            VoiceCommand(phrase: "run subfinder", action: .cybersecurity, confidence: 0.9, parameters: ["tool": "subfinder", "action": "scan"]),
            
            // System Commands
            VoiceCommand(phrase: "stop all", action: .system, confidence: 0.9, parameters: ["action": "stop_all"]),
            VoiceCommand(phrase: "emergency stop", action: .system, confidence: 0.99, parameters: ["action": "emergency_stop"]),
            VoiceCommand(phrase: "status report", action: .system, confidence: 0.85, parameters: ["action": "status"])
        ]
    }
    
    func requestPermissionsAndStart() {
        // Initialize speech recognizer when needed
        if speechRecognizer == nil {
            speechRecognizer = SFSpeechRecognizer(locale: Locale(identifier: "en-US"))
            speechRecognizer?.delegate = self
        }
        
        // Request permissions and start listening
        requestSpeechAuthorization()
        requestMicrophonePermission()
    }
    
    func startListening() {
        // First check if we need permissions
        if !isAvailable {
            requestPermissionsAndStart()
            return
        }
        
        guard !isListening else { return }
        
        do {
            try startAudioEngine()
            isListening = true
            logger.info("🎤 Voice recognition started")
        } catch {
            logger.error("❌ Failed to start voice recognition: \(error)")
        }
    }
    
    func stopListening() {
        audioEngine.stop()
        recognitionRequest?.endAudio()
        recognitionTask?.cancel()
        
        recognitionRequest = nil
        recognitionTask = nil
        isListening = false
        
        logger.info("🔇 Voice recognition stopped")
    }
    
    private func startAudioEngine() throws {
        // Cancel previous task
        recognitionTask?.cancel()
        recognitionTask = nil
        
        // Create recognition request
        recognitionRequest = SFSpeechAudioBufferRecognitionRequest()
        
        guard let recognitionRequest = recognitionRequest else {
            throw VoiceError.recognitionRequestFailed
        }
        
        recognitionRequest.shouldReportPartialResults = true
        
        // Create recognition task
        recognitionTask = speechRecognizer?.recognitionTask(with: recognitionRequest) { result, error in
            DispatchQueue.main.async {
                if let result = result {
                    self.lastTranscription = result.bestTranscription.formattedString
                    self.confidence = result.bestTranscription.segments.first?.confidence ?? 0.0
                    
                    // Process command if final result
                    if result.isFinal {
                        Task {
                            await self.processVoiceCommand(self.lastTranscription)
                        }
                    }
                }
                
                if error != nil {
                    self.stopListening()
                }
            }
        }
        
        // Configure audio input
        let inputNode = audioEngine.inputNode
        let recordingFormat = inputNode.outputFormat(forBus: 0)
        
        inputNode.installTap(onBus: 0, bufferSize: 1024, format: recordingFormat) { buffer, _ in
            self.recognitionRequest?.append(buffer)
        }
        
        audioEngine.prepare()
        try audioEngine.start()
    }
    
    private func processVoiceCommand(_ command: String) async {
        isProcessingVoice = true
        defer { isProcessingVoice = false }
        
        let lowercaseCommand = command.lowercased()
        
        // Enhanced command processing with AI integration
        if let matchedCommand = findBestMatch(for: lowercaseCommand) {
            await executeVoiceCommand(matchedCommand, originalText: command)
        } else {
            // Send to AI orchestrator for natural language processing
            await processNaturalLanguageCommand(command)
        }
    }
    
    private func findBestMatch(for input: String) -> VoiceCommand? {
        return voiceCommands.first { command in
            input.contains(command.phrase.lowercased()) ||
            levenshteinDistance(input, command.phrase.lowercased()) < 3
        }
    }
    
    private func executeVoiceCommand(_ command: VoiceCommand, originalText: String) async {
        speak("Executing \(command.phrase)")
        
        // Route to appropriate system based on command
        switch command.action {
        case .cybersecurity:
            await routeCybersecurityCommand(command, originalText: originalText)
        case .navigation:
            await routeNavigationCommand(command)
        case .system:
            await routeSystemCommand(command)
        }
    }
    
    private func routeCybersecurityCommand(_ command: VoiceCommand, originalText: String) async {
        // Integration point with AI Orchestrator and Tool Runner
        // This will be expanded to call the actual cybersecurity operations
        
        if originalText.contains("scan") {
            speak("Initiating security scan")
            // await toolRunner.startNmapScan()
        } else if originalText.contains("exploit") {
            speak("Loading exploitation framework")
            // await toolRunner.launchMetasploit()
        } else if originalText.contains("burp") {
            speak("Starting Burp Suite proxy")
            // await toolRunner.launchBurpSuite()
        } else if originalText.contains("threat") {
            speak("Analyzing threat landscape")
            // await threatDetectionEngine.performThreatAnalysis()
        }
    }
    
    private func routeNavigationCommand(_ command: VoiceCommand) async {
        // Navigate between app sections
        speak("Navigating to \(command.phrase)")
    }
    
    private func routeSystemCommand(_ command: VoiceCommand) async {
        // System-level operations
        speak("Executing system command \(command.phrase)")
    }
    
    private func processNaturalLanguageCommand(_ command: String) async {
        speak("Processing natural language command")
        // Send to AI orchestrator for interpretation
        // This will integrate with ChatGPT-5, Ollama, etc.
    }
    
    func speak(_ text: String, priority: SpeechPriority = .normal) {
        let utterance = AVSpeechUtterance(string: text)
        utterance.voice = selectedVoice
        utterance.rate = speechRate
        utterance.pitchMultiplier = speechPitch
        utterance.volume = speechVolume
        
        // Cybersecurity-appropriate speech characteristics
        utterance.preUtteranceDelay = priority == .urgent ? 0.1 : 0.3
        utterance.postUtteranceDelay = 0.2
        
        speechSynthesizer.speak(utterance)
    }
    
    func speakUrgent(_ text: String) {
        speak(text, priority: .urgent)
    }
    
    // Utility functions
    private func extractParameters(from command: String) -> [String: String] {
        var params: [String: String] = [:]
        
        // Extract target from commands like "scan target 192.168.1.1"
        if let targetRange = command.range(of: "target ") {
            let target = String(command[targetRange.upperBound...])
            params["target"] = target
        }
        
        return params
    }
    
    private func levenshteinDistance(_ s1: String, _ s2: String) -> Int {
        let a = Array(s1)
        let b = Array(s2)
        var matrix = Array(repeating: Array(repeating: 0, count: b.count + 1), count: a.count + 1)
        
        for i in 0...a.count { matrix[i][0] = i }
        for j in 0...b.count { matrix[0][j] = j }
        
        for i in 1...a.count {
            for j in 1...b.count {
                if a[i-1] == b[j-1] {
                    matrix[i][j] = matrix[i-1][j-1]
                } else {
                    matrix[i][j] = min(matrix[i-1][j], matrix[i][j-1], matrix[i-1][j-1]) + 1
                }
            }
        }
        
        return matrix[a.count][b.count]
    }
}

// MARK: - Speech Recognizer Delegate
extension VoiceManager: SFSpeechRecognizerDelegate {
    func speechRecognizer(_ speechRecognizer: SFSpeechRecognizer, availabilityDidChange available: Bool) {
        if !available {
            stopListening()
        }
    }
}

// MARK: - Speech Synthesizer Delegate
extension VoiceManager: AVSpeechSynthesizerDelegate {
    func speechSynthesizer(_ synthesizer: AVSpeechSynthesizer, didFinish utterance: AVSpeechUtterance) {
        // Can resume listening after speech output
    }
}

// MARK: - Voice Command Models
struct VoiceCommand: Identifiable, Codable {
    let id = UUID()
    let phrase: String
    let action: CommandAction
    let confidence: Float
    let parameters: [String: String]
    
    enum CommandAction: String, Codable, CaseIterable {
        case cybersecurity = "cybersecurity"
        case navigation = "navigation" 
        case system = "system"
    }
}

enum SpeechPriority {
    case urgent
    case normal
    case background
}

enum VoiceError: Error {
    case recognitionRequestFailed
    case audioEngineFailed
    case authorizationDenied
}

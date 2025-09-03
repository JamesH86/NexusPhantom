import Foundation
import Combine
import os.log

@MainActor
class AIOrchestrator: ObservableObject {
    @Published var activeModels: [String] = []
    @Published var isProcessing = false
    @Published var modelPerformance: [String: ModelMetrics] = [:]
    @Published var currentQuery: String = ""
    @Published var lastResponse: AIResponse?
    
    private var modelProviders: [String: AIModelProvider] = [:]
    private let logger = Logger(subsystem: "NexusPhantom", category: "AIOrchestrator")
    
    // Model configuration  
    private let supportedModels: [String: any AIModelProvider] = [
        "ChatGPT-5": ChatGPTProvider(),
        "Ollama": OllamaProvider(),
        "Groq": GroqProvider(),
        "Siri": SiriProvider(),
        "WRP": WRPProvider()
    ]
    
    init() {
        setupModelProviders()
    }
    
    func initializeModels() async {
        logger.info("🧠 Initializing AI model providers...")
        
        await withTaskGroup(of: (String, Bool).self) { group in
            for (modelName, provider) in supportedModels {
                group.addTask {
                    let success = await provider.initialize()
                    return (modelName, success)
                }
            }
            
            for await (modelName, success) in group {
                if success {
                    activeModels.append(modelName)
                    modelProviders[modelName] = supportedModels[modelName]
                    modelPerformance[modelName] = ModelMetrics()
                    logger.info("✅ \\(modelName) initialized successfully")
                } else {
                    logger.warning("❌ Failed to initialize \\(modelName)")
                }
            }
        }
        
        logger.info("🔥 AI Orchestrator ready with \\(activeModels.count) active models")
    }
    
    func processQuery(_ query: String, context: CyberSecurityContext) async -> AIResponse {
        isProcessing = true
        currentQuery = query
        defer { isProcessing = false }
        
        let startTime = Date()
        
        // Determine best model for this query type
        let selectedModel = selectOptimalModel(for: query, context: context)
        
        guard let provider = modelProviders[selectedModel] else {
            return AIResponse(
                content: "Model provider not available",
                model: selectedModel,
                confidence: 0.0,
                processingTime: 0.0,
                context: context
            )
        }
        
        logger.info("🎯 Routing query to \\(selectedModel): \\(query.prefix(50))...")
        
        do {
            let response = try await provider.processQuery(query, context: context)
            let processingTime = Date().timeIntervalSince(startTime)
            
            // Update performance metrics
            updateModelMetrics(for: selectedModel, responseTime: processingTime, success: true)
            
            let aiResponse = AIResponse(
                content: response.content,
                model: selectedModel,
                confidence: response.confidence,
                processingTime: processingTime,
                context: context,
                actions: response.suggestedActions
            )
            
            lastResponse = aiResponse
            return aiResponse
            
        } catch {
            logger.error("❌ Error processing query with \\(selectedModel): \\(error)")
            updateModelMetrics(for: selectedModel, responseTime: Date().timeIntervalSince(startTime), success: false)
            
            // Fallback to next best model
            return await fallbackProcessing(query, context: context, failedModel: selectedModel)
        }
    }
    
    private func selectOptimalModel(for query: String, context: CyberSecurityContext) -> String {
        let lowercaseQuery = query.lowercased()
        
        // Context-aware model selection
        if context.domain == .exploitation || context.domain == .penetrationTesting {
            // Prefer specialized models for technical cybersecurity tasks
            if activeModels.contains("ChatGPT-5") { return "ChatGPT-5" }
            if activeModels.contains("Ollama") { return "Ollama" }
        }
        
        if context.domain == .research || lowercaseQuery.contains("search") {
            // Prefer search-capable models
            if activeModels.contains("Perplexity") { return "Perplexity" }
        }
        
        if context.domain == .osint || lowercaseQuery.contains("intelligence") {
            // OSINT queries benefit from search capabilities
            if activeModels.contains("Perplexity") { return "Perplexity" }
            if activeModels.contains("WRP") { return "WRP" }
        }
        
        if lowercaseQuery.contains("code") || lowercaseQuery.contains("script") {
            // Code generation tasks
            if activeModels.contains("ChatGPT-5") { return "ChatGPT-5" }
            if activeModels.contains("GPT-J") { return "GPT-J" }
        }
        
        if context.isVoiceCommand {
            // Voice commands might benefit from Siri integration
            if activeModels.contains("Siri") { return "Siri" }
        }
        
        // Default to best performing model
        let bestModel = activeModels.min { model1, model2 in
            let metrics1 = modelPerformance[model1]?.avgResponseTime ?? Double.infinity
            let metrics2 = modelPerformance[model2]?.avgResponseTime ?? Double.infinity
            return metrics1 < metrics2
        }
        
        return bestModel ?? activeModels.first ?? "ChatGPT-5"
    }
    
    private func fallbackProcessing(_ query: String, context: CyberSecurityContext, failedModel: String) async -> AIResponse {
        let availableModels = activeModels.filter { $0 != failedModel }
        
        guard let fallbackModel = availableModels.first else {
            return AIResponse(
                content: "All AI models unavailable",
                model: "None",
                confidence: 0.0,
                processingTime: 0.0,
                context: context
            )
        }
        
        logger.info("🔄 Falling back to \(fallbackModel)")
        
        guard let provider = modelProviders[fallbackModel] else {
            return AIResponse(
                content: "Fallback model provider not available",
                model: fallbackModel,
                confidence: 0.0,
                processingTime: 0.0,
                context: context
            )
        }
        
        do {
            let startTime = Date()
            let response = try await provider.processQuery(query, context: context)
            let processingTime = Date().timeIntervalSince(startTime)
            
            updateModelMetrics(for: fallbackModel, responseTime: processingTime, success: true)
            
            return AIResponse(
                content: response.content,
                model: fallbackModel,
                confidence: response.confidence * 0.8, // Reduce confidence for fallback
                processingTime: processingTime,
                context: context,
                actions: response.suggestedActions
            )
        } catch {
            logger.error("❌ Fallback also failed: \(error)")
            return AIResponse(
                content: "Unable to process query - all models failed",
                model: fallbackModel,
                confidence: 0.0,
                processingTime: 0.0,
                context: context
            )
        }
    }
    
    private func updateModelMetrics(for model: String, responseTime: TimeInterval, success: Bool) {
        if modelPerformance[model] == nil {
            modelPerformance[model] = ModelMetrics()
        }
        
        modelPerformance[model]?.updateMetrics(responseTime: responseTime, success: success)
    }
    
    private func setupModelProviders() {
        // Initialize model providers with cybersecurity-specific configurations
        logger.info("Setting up AI model providers...")
    }
    
    func getModelStatus() -> [String: ModelStatus] {
        var status: [String: ModelStatus] = [:]
        
        for model in activeModels {
            let metrics = modelPerformance[model] ?? ModelMetrics()
            status[model] = ModelStatus(
                isActive: true,
                responseTime: metrics.avgResponseTime,
                successRate: metrics.successRate,
                lastUsed: metrics.lastUsed
            )
        }
        
        return status
    }
}

// MARK: - AI Model Provider Protocol
protocol AIModelProvider {
    func initialize() async -> Bool
    func processQuery(_ query: String, context: CyberSecurityContext) async throws -> ModelResponse
    func getCapabilities() -> [String]
    func isHealthy() async -> Bool
}

// MARK: - Model Implementations
class ChatGPTProvider: AIModelProvider {
    private var apiKey: String?
    
    func initialize() async -> Bool {
        // Initialize ChatGPT-5 connection
        // This would load API credentials securely from Keychain
        return true // Placeholder
    }
    
    func processQuery(_ query: String, context: CyberSecurityContext) async throws -> ModelResponse {
        // Implement ChatGPT-5 API integration
        // Enhanced with cybersecurity-specific prompts
        
        let enhancedPrompt = buildCyberSecPrompt(query, context: context)
        
        // Placeholder implementation
        return ModelResponse(
            content: "ChatGPT-5 response: \(query)",
            confidence: 0.9,
            suggestedActions: []
        )
    }
    
    func getCapabilities() -> [String] {
        return ["code_generation", "exploit_development", "report_writing", "natural_language"]
    }
    
    func isHealthy() async -> Bool {
        return true
    }
    
    private func buildCyberSecPrompt(_ query: String, context: CyberSecurityContext) -> String {
        var prompt = "You are NEXUS PHANTOM, an elite cybersecurity AI assistant. "
        
        switch context.domain {
        case .penetrationTesting:
            prompt += "Focus on authorized penetration testing and vulnerability assessment. "
        case .bugBounty:
            prompt += "Focus on responsible vulnerability disclosure and bug bounty research. "
        case .threatDetection:
            prompt += "Focus on threat analysis and security incident response. "
        case .compliance:
            prompt += "Focus on security compliance and audit frameworks. "
        case .osint:
            prompt += "Focus on open source intelligence gathering techniques. "
        case .exploitation:
            prompt += "Focus on exploit development and security research. "
        case .defense:
            prompt += "Focus on defensive cybersecurity measures. "
        case .research:
            prompt += "Focus on cybersecurity research and analysis. "
        }
        
        prompt += "\n\nUser Query: \(query)"
        return prompt
    }
}

class OllamaProvider: AIModelProvider {
    func initialize() async -> Bool {
        // Check if Ollama is running locally
        let process = Process()
        process.launchPath = "/usr/local/bin/ollama"
        process.arguments = ["list"]
        
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }
    
    func processQuery(_ query: String, context: CyberSecurityContext) async throws -> ModelResponse {
        // Implement Ollama local model integration
        return ModelResponse(
            content: "Ollama response: \(query)",
            confidence: 0.85,
            suggestedActions: []
        )
    }
    
    func getCapabilities() -> [String] {
        return ["local_processing", "privacy_focused", "code_analysis"]
    }
    
    func isHealthy() async -> Bool {
        return true
    }
}

class GPTJProvider: AIModelProvider {
    func initialize() async -> Bool {
        // Initialize GPT-J model
        return true
    }
    
    func processQuery(_ query: String, context: CyberSecurityContext) async throws -> ModelResponse {
        return ModelResponse(
            content: "GPT-J response: \(query)",
            confidence: 0.8,
            suggestedActions: []
        )
    }
    
    func getCapabilities() -> [String] {
        return ["text_generation", "analysis"]
    }
    
    func isHealthy() async -> Bool {
        return true
    }
}

class PerplexityProvider: AIModelProvider {
    func initialize() async -> Bool {
        // Initialize Perplexity API
        return true
    }
    
    func processQuery(_ query: String, context: CyberSecurityContext) async throws -> ModelResponse {
        return ModelResponse(
            content: "Perplexity search result: \(query)",
            confidence: 0.9,
            suggestedActions: []
        )
    }
    
    func getCapabilities() -> [String] {
        return ["web_search", "real_time_data", "research"]
    }
    
    func isHealthy() async -> Bool {
        return true
    }
}

class SiriProvider: AIModelProvider {
    func initialize() async -> Bool {
        // Initialize Siri integration
        return true
    }
    
    func processQuery(_ query: String, context: CyberSecurityContext) async throws -> ModelResponse {
        return ModelResponse(
            content: "Siri integration: \(query)",
            confidence: 0.7,
            suggestedActions: []
        )
    }
    
    func getCapabilities() -> [String] {
        return ["voice_interaction", "system_integration"]
    }
    
    func isHealthy() async -> Bool {
        return true
    }
}

class GroqProvider: AIModelProvider {
    func initialize() async -> Bool {
        // Initialize Groq API
        return true
    }
    
    func processQuery(_ query: String, context: CyberSecurityContext) async throws -> ModelResponse {
        return ModelResponse(
            content: "Groq response: \(query)",
            confidence: 0.88,
            suggestedActions: []
        )
    }
    
    func getCapabilities() -> [String] {
        return ["fast_inference", "coding", "analysis"]
    }
    
    func isHealthy() async -> Bool {
        return true
    }
}

class WRPProvider: AIModelProvider {
    func initialize() async -> Bool {
        // Initialize WRP integration
        return true
    }
    
    func processQuery(_ query: String, context: CyberSecurityContext) async throws -> ModelResponse {
        return ModelResponse(
            content: "WRP response: \(query)",
            confidence: 0.75,
            suggestedActions: []
        )
    }
    
    func getCapabilities() -> [String] {
        return ["specialized_analysis"]
    }
    
    func isHealthy() async -> Bool {
        return true
    }
}

// MARK: - Data Models
struct ModelResponse {
    let content: String
    let confidence: Double
    let suggestedActions: [CyberSecAction]
    let metadata: [String: Any]?
    
    init(content: String, confidence: Double, suggestedActions: [CyberSecAction], metadata: [String: Any]? = nil) {
        self.content = content
        self.confidence = confidence
        self.suggestedActions = suggestedActions
        self.metadata = metadata
    }
}

struct AIResponse: Identifiable {
    let id = UUID()
    let content: String
    let model: String
    let confidence: Double
    let processingTime: TimeInterval
    let timestamp = Date()
    let context: CyberSecurityContext
    let actions: [CyberSecAction]
    
    init(content: String, model: String, confidence: Double, processingTime: TimeInterval, context: CyberSecurityContext, actions: [CyberSecAction] = []) {
        self.content = content
        self.model = model
        self.confidence = confidence
        self.processingTime = processingTime
        self.context = context
        self.actions = actions
    }
}

class ModelMetrics: ObservableObject {
    @Published var avgResponseTime: Double = 0.0
    @Published var successRate: Double = 1.0
    @Published var totalQueries: Int = 0
    @Published var successfulQueries: Int = 0
    @Published var lastUsed: Date = Date()
    
    private var responseTimes: [Double] = []
    
    func updateMetrics(responseTime: TimeInterval, success: Bool) {
        totalQueries += 1
        lastUsed = Date()
        
        if success {
            successfulQueries += 1
            responseTimes.append(responseTime)
            
            // Keep only last 100 response times for average
            if responseTimes.count > 100 {
                responseTimes.removeFirst()
            }
            
            avgResponseTime = responseTimes.reduce(0, +) / Double(responseTimes.count)
        }
        
        successRate = Double(successfulQueries) / Double(totalQueries)
    }
}

struct ModelStatus {
    let isActive: Bool
    let responseTime: Double
    let successRate: Double
    let lastUsed: Date
}

// MARK: - Cybersecurity Context
struct CyberSecurityContext {
    let domain: CyberSecDomain
    let target: String?
    let urgency: UrgencyLevel
    let isVoiceCommand: Bool
    let requiredActions: [CyberSecAction]
    let userPermissions: [Permission]
    
    enum CyberSecDomain {
        case penetrationTesting
        case threatDetection
        case bugBounty
        case compliance
        case osint
        case exploitation
        case defense
        case research
    }
    
    enum UrgencyLevel {
        case immediate
        case high
        case normal
        case background
    }
    
    enum Permission {
        case rootAccess
        case networkScanning
        case fileSystemAccess
        case processMonitoring
        case exploitExecution
    }
}

// MARK: - Cybersecurity Actions
struct CyberSecAction: Identifiable {
    let id = UUID()
    let type: ActionType
    let description: String
    let parameters: [String: Any]
    let riskLevel: RiskLevel
    
    enum ActionType {
        case scan(tool: String)
        case exploit(framework: String)
        case report(format: String)
        case mitigate(technique: String)
        case research(platform: String)
    }
    
    enum RiskLevel {
        case safe
        case low
        case medium
        case high
        case critical
    }
}

enum AIError: Error {
    case modelNotAvailable
    case authenticationFailed
    case rateLimitExceeded
    case invalidResponse
    case networkError
}

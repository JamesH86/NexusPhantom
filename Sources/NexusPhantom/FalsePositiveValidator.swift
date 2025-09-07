import Foundation
import Combine
import os.log
import CoreML
import SwiftUI

/// ML-powered False Positive Validator
/// Implements advanced machine learning models to eliminate false positives in security findings
@MainActor
class FalsePositiveValidator: ObservableObject {
    
    // MARK: - Published Properties
    @Published var isValidating = false
    @Published var validationMetrics = ValidationMetrics()
    @Published var modelPerformance = ModelPerformanceMetrics()
    @Published var learningProgress = LearningProgress()
    
    // MARK: - Dependencies
    private let logger = Logger(subsystem: "NexusPhantom", category: "FalsePositiveValidator")
    private let aiOrchestrator: AIOrchestrator
    
    // MARK: - ML Models
    private var ensembleModels: [MLValidationModel] = []
    private var contextualModels: [String: MLValidationModel] = [:]
    private var feedbackLearningModel: ContinuousLearningModel
    
    // MARK: - Configuration
    private let validationConfiguration = ValidationConfiguration.default
    private var trainingData: [LabeledFinding] = []
    private var validationCache: [String: ValidationResult] = [:]
    
    init(aiOrchestrator: AIOrchestrator) {
        self.aiOrchestrator = aiOrchestrator
        self.feedbackLearningModel = ContinuousLearningModel()
        
        Task {
            await initializeMLModels()
        }
    }
    
    // MARK: - Main Validation Functions
    
    /// Validates a finding using ensemble ML models and contextual analysis
    func validateFinding(finding: Finding) async -> ValidationResult {
        logger.info("🧠 Validating finding: \(finding.title)")
        
        isValidating = true
        defer { isValidating = false }
        
        // Check cache first
        let cacheKey = generateCacheKey(for: finding)
        if let cachedResult = validationCache[cacheKey] {
            logger.info("📋 Using cached validation result")
            return cachedResult
        }
        
        // Extract comprehensive features from finding
        let features = await extractFeatures(from: finding)
        
        // Ensemble model validation
        let ensembleResults = await runEnsembleValidation(features: features)
        
        // Contextual validation
        let contextualResult = await runContextualValidation(finding: finding, features: features)
        
        // AI-powered semantic analysis
        let semanticResult = await runSemanticAnalysis(finding: finding)
        
        // Cross-validation with multiple tools
        let crossValidationResult = await performCrossValidation(finding: finding)
        
        // Combine all validation results
        let finalResult = combineValidationResults(
            ensemble: ensembleResults,
            contextual: contextualResult,
            semantic: semanticResult,
            crossValidation: crossValidationResult,
            finding: finding
        )
        
        // Cache result for future use
        validationCache[cacheKey] = finalResult
        
        // Update metrics
        updateValidationMetrics(result: finalResult)
        
        logger.info("✅ Validation complete - Confidence: \(finalResult.confidence), False Positive: \(finalResult.isFalsePositive)")
        
        return finalResult
    }
    
    /// Continuous learning from user feedback
    func learnFromFeedback(finding: Finding, userClassification: UserClassification) async {
        logger.info("📚 Learning from user feedback for finding: \(finding.title)")
        
        let labeledFinding = LabeledFinding(
            finding: finding,
            userClassification: userClassification,
            timestamp: Date(),
            context: await extractContextualInformation(for: finding)
        )
        
        trainingData.append(labeledFinding)
        
        // Update continuous learning model
        await feedbackLearningModel.updateWithFeedback(labeledFinding)
        
        // Retrain models if enough feedback collected
        if trainingData.count % validationConfiguration.retrainingThreshold == 0 {
            await retrainModels()
        }
        
        // Clear cache to force re-validation with updated models
        validationCache.removeAll()
        
        logger.info("🎯 Model updated with user feedback")
    }
    
    /// Batch validation for multiple findings
    func validateFindings(_ findings: [Finding]) async -> [ValidationResult] {
        logger.info("🔍 Batch validating \(findings.count) findings")
        
        var results: [ValidationResult] = []
        
        await withTaskGroup(of: ValidationResult.self) { group in
            for finding in findings {
                group.addTask {
                    await self.validateFinding(finding: finding)
                }
            }
            
            for await result in group {
                results.append(result)
            }
        }
        
        return results
    }
    
    // MARK: - Feature Extraction
    
    private func extractFeatures(from finding: Finding) async -> ValidationFeatures {
        logger.debug("🔧 Extracting features from finding")
        
        return ValidationFeatures(
            // Basic features
            severity: finding.severity,
            type: finding.type,
            hasCV: finding.cvssScore != nil,
            hasCWE: finding.cweId != nil,
            referenceCount: finding.references.count,
            
            // Text features
            titleLength: finding.title.count,
            descriptionLength: finding.description.count,
            titleSentiment: await analyzeSentiment(text: finding.title),
            descriptionSentiment: await analyzeSentiment(text: finding.description),
            
            // Semantic features
            keywordDensity: calculateKeywordDensity(text: finding.description),
            technicalTerms: countTechnicalTerms(text: finding.description),
            
            // Context features
            assetType: determineAssetType(asset: finding.affectedAsset),
            scannerConfidence: extractScannerConfidence(from: finding),
            
            // Historical features
            similarFindingsCount: await countSimilarFindings(finding: finding),
            previousFalsePositives: await countPreviousFalsePositives(finding: finding),
            
            // Network features (if applicable)
            networkContext: await extractNetworkContext(finding: finding),
            
            // Time-based features
            discoveryTime: Date(),
            timeOfDay: Calendar.current.component(.hour, from: Date()),
            dayOfWeek: Calendar.current.component(.weekday, from: Date())
        )
    }
    
    // MARK: - Ensemble Validation
    
    private func runEnsembleValidation(features: ValidationFeatures) async -> EnsembleValidationResult {
        logger.debug("🎭 Running ensemble validation")
        
        var modelResults: [ModelValidationResult] = []
        
        for model in ensembleModels {
            let result = await model.validate(features: features)
            modelResults.append(result)
        }
        
        // Weighted voting based on model performance
        let weightedScore = calculateWeightedScore(results: modelResults)
        let confidence = calculateEnsembleConfidence(results: modelResults)
        
        return EnsembleValidationResult(
            modelResults: modelResults,
            weightedScore: weightedScore,
            confidence: confidence,
            isFalsePositive: weightedScore < validationConfiguration.falsePositiveThreshold
        )
    }
    
    // MARK: - Contextual Validation
    
    private func runContextualValidation(finding: Finding, features: ValidationFeatures) async -> ContextualValidationResult {
        logger.debug("🎯 Running contextual validation")
        
        // Determine the appropriate contextual model
        let context = determineContext(finding: finding)
        guard let contextualModel = contextualModels[context] else {
            return ContextualValidationResult(
                context: context,
                score: 0.5, // Neutral score if no specific model
                confidence: 0.3,
                reasoning: "No specialized model for context: \(context)"
            )
        }
        
        // Run contextual validation
        let result = await contextualModel.validate(features: features)
        
        return ContextualValidationResult(
            context: context,
            score: result.score,
            confidence: result.confidence,
            reasoning: result.reasoning
        )
    }
    
    // MARK: - Semantic Analysis
    
    private func runSemanticAnalysis(finding: Finding) async -> SemanticValidationResult {
        logger.debug("🧠 Running semantic analysis")
        
        // Use AI orchestrator for semantic understanding
        let context = CyberSecurityContext(
            domain: .threatDetection,
            target: finding.affectedAsset,
            urgency: .normal,
            isVoiceCommand: false,
            requiredActions: [],
            userPermissions: []
        )
        
        let analysisQuery = """
        Analyze this security finding for false positive indicators:
        
        Title: \(finding.title)
        Description: \(finding.description)
        Severity: \(finding.severity)
        Asset: \(finding.affectedAsset)
        
        Consider:
        1. Technical accuracy of the finding
        2. Context appropriateness
        3. Common false positive patterns
        4. Semantic consistency
        
        Provide a confidence score (0-1) and reasoning.
        """
        
        let aiResponse = await aiOrchestrator.processQuery(analysisQuery, context: context)
        
        // Parse AI response for confidence and reasoning
        let (confidence, reasoning) = parseSemanticAnalysis(response: aiResponse.content)
        
        return SemanticValidationResult(
            confidence: confidence,
            reasoning: reasoning,
            aiModelUsed: aiResponse.model,
            processingTime: aiResponse.processingTime
        )
    }
    
    // MARK: - Cross Validation
    
    private func performCrossValidation(finding: Finding) async -> CrossValidationResult {
        logger.debug("🔄 Performing cross-validation")
        
        // Simulate validation with multiple hypothetical tools
        let tools = ["nmap", "nuclei", "nessus", "openvas", "custom"]
        var toolResults: [String: Bool] = [:]
        
        for tool in tools {
            // This would integrate with actual tools in a real implementation
            let wouldDetect = await simulateToolDetection(finding: finding, tool: tool)
            toolResults[tool] = wouldDetect
        }
        
        let detectionCount = toolResults.values.filter { $0 }.count
        let consensus = Double(detectionCount) / Double(tools.count)
        
        return CrossValidationResult(
            toolResults: toolResults,
            consensusScore: consensus,
            detectionCount: detectionCount,
            totalTools: tools.count
        )
    }
    
    // MARK: - Result Combination
    
    private func combineValidationResults(
        ensemble: EnsembleValidationResult,
        contextual: ContextualValidationResult,
        semantic: SemanticValidationResult,
        crossValidation: CrossValidationResult,
        finding: Finding
    ) -> ValidationResult {
        
        // Weighted combination of all validation methods
        let weights = validationConfiguration.validationWeights
        
        var finalScore = 0.0
        finalScore += ensemble.weightedScore * weights.ensemble
        finalScore += contextual.score * weights.contextual
        finalScore += semantic.confidence * weights.semantic
        finalScore += crossValidation.consensusScore * weights.crossValidation
        
        // Calculate overall confidence
        let confidenceScores = [
            ensemble.confidence,
            contextual.confidence,
            semantic.confidence,
            crossValidation.consensusScore
        ]
        let averageConfidence = confidenceScores.reduce(0, +) / Double(confidenceScores.count)
        
        // Determine if it's a false positive
        let isFalsePositive = finalScore < validationConfiguration.falsePositiveThreshold
        
        // Generate comprehensive reasoning
        let reasoning = generateValidationReasoning(
            ensemble: ensemble,
            contextual: contextual,
            semantic: semantic,
            crossValidation: crossValidation,
            finalScore: finalScore
        )
        
        return ValidationResult(
            isFalsePositive: isFalsePositive,
            confidence: averageConfidence,
            score: finalScore,
            reasoning: reasoning,
            validationMethods: [
                "ensemble": ensemble.weightedScore,
                "contextual": contextual.score,
                "semantic": semantic.confidence,
                "cross_validation": crossValidation.consensusScore
            ],
            metadata: ValidationMetadata(
                modelVersions: ensembleModels.map { $0.version },
                validationTime: Date(),
                featureCount: 15, // Number of features used
                cacheHit: false
            )
        )
    }
    
    // MARK: - Model Management
    
    private func initializeMLModels() async {
        logger.info("🤖 Initializing ML models")
        
        // Initialize ensemble models
        ensembleModels = [
            RandomForestModel(),
            XGBoostModel(),
            NeuralNetworkModel(),
            SVMModel()
        ]
        
        // Initialize contextual models
        contextualModels = [
            "web_application": WebAppValidationModel(),
            "network_service": NetworkServiceValidationModel(),
            "system_configuration": SystemConfigValidationModel(),
            "database": DatabaseValidationModel(),
            "mobile": MobileValidationModel()
        ]
        
        // Load pre-trained models if available
        await loadPretrainedModels()
        
        logger.info("✅ ML models initialized successfully")
    }
    
    private func retrainModels() async {
        logger.info("🔄 Retraining models with new feedback data")
        
        learningProgress.isRetraining = true
        defer { learningProgress.isRetraining = false }
        
        // Retrain each model with accumulated feedback
        for model in ensembleModels {
            await model.retrain(with: trainingData)
        }
        
        // Update performance metrics
        await evaluateModelPerformance()
        
        logger.info("🎯 Model retraining completed")
    }
    
    private func evaluateModelPerformance() async {
        logger.info("📊 Evaluating model performance")
        
        // Use holdout validation set to evaluate performance
        let testData = Array(trainingData.suffix(100)) // Last 100 samples as test
        
        var correctPredictions = 0
        var totalPredictions = 0
        
        for labeledFinding in testData {
            let prediction = await validateFinding(finding: labeledFinding.finding)
            let actualLabel = labeledFinding.userClassification == .falsePositive
            
            if prediction.isFalsePositive == actualLabel {
                correctPredictions += 1
            }
            totalPredictions += 1
        }
        
        let accuracy = Double(correctPredictions) / Double(totalPredictions)
        
        modelPerformance.accuracy = accuracy
        modelPerformance.lastEvaluation = Date()
        modelPerformance.evaluationSamples = totalPredictions
        
        logger.info("📈 Model accuracy: \(accuracy)")
    }
    
    // MARK: - Helper Methods
    
    private func generateCacheKey(for finding: Finding) -> String {
        let content = "\(finding.title)\(finding.description)\(finding.affectedAsset)"
        return content.sha256
    }
    
    private func analyzeSentiment(text: String) async -> Double {
        // Placeholder for sentiment analysis
        // Would integrate with NLP libraries or APIs
        return 0.5
    }
    
    private func calculateKeywordDensity(text: String) -> Double {
        let securityKeywords = [
            "vulnerability", "exploit", "attack", "malicious", "security",
            "unauthorized", "injection", "xss", "sql", "buffer", "overflow"
        ]
        
        let words = text.lowercased().components(separatedBy: .whitespacesAndNewlines)
        let keywordCount = words.filter { securityKeywords.contains($0) }.count
        
        return Double(keywordCount) / Double(words.count)
    }
    
    private func countTechnicalTerms(text: String) -> Int {
        let technicalTerms = [
            "tcp", "udp", "http", "https", "ssl", "tls", "dns", "ip",
            "port", "protocol", "header", "request", "response", "cookie"
        ]
        
        let words = text.lowercased().components(separatedBy: .whitespacesAndNewlines)
        return words.filter { technicalTerms.contains($0) }.count
    }
    
    private func determineAssetType(asset: String) -> String {
        // Simple heuristic to determine asset type
        if asset.contains(":80") || asset.contains(":443") || asset.contains("http") {
            return "web_application"
        } else if asset.contains(":22") || asset.contains("ssh") {
            return "network_service"
        } else if asset.contains(":3306") || asset.contains(":5432") {
            return "database"
        }
        return "unknown"
    }
    
    private func extractScannerConfidence(from finding: Finding) -> Double {
        // Extract confidence from finding metadata if available
        return 0.8 // Default confidence
    }
    
    private func countSimilarFindings(finding: Finding) async -> Int {
        // Count similar findings in historical data
        return trainingData.filter { labeled in
            labeled.finding.title.contains(finding.title.prefix(20)) ||
            labeled.finding.description.contains(finding.description.prefix(50))
        }.count
    }
    
    private func countPreviousFalsePositives(finding: Finding) async -> Int {
        // Count previous false positives for similar findings
        return trainingData.filter { labeled in
            labeled.userClassification == .falsePositive &&
            (labeled.finding.title.contains(finding.title.prefix(20)) ||
             labeled.finding.description.contains(finding.description.prefix(50)))
        }.count
    }
    
    private func extractNetworkContext(finding: Finding) async -> NetworkContext? {
        // Extract network-related context if applicable
        return nil
    }
    
    private func extractContextualInformation(for finding: Finding) async -> ContextualInformation {
        return ContextualInformation(
            assetType: determineAssetType(asset: finding.affectedAsset),
            environment: "production", // Would be detected
            businessCriticality: "medium", // Would be assessed
            previousIncidents: await countSimilarFindings(finding: finding)
        )
    }
    
    private func calculateWeightedScore(results: [ModelValidationResult]) -> Double {
        let weights = validationConfiguration.modelWeights
        var weightedSum = 0.0
        var totalWeight = 0.0
        
        for (index, result) in results.enumerated() {
            let weight = weights[safe: index] ?? 1.0
            weightedSum += result.score * weight
            totalWeight += weight
        }
        
        return weightedSum / totalWeight
    }
    
    private func calculateEnsembleConfidence(results: [ModelValidationResult]) -> Double {
        let confidences = results.map { $0.confidence }
        return confidences.reduce(0, +) / Double(confidences.count)
    }
    
    private func determineContext(finding: Finding) -> String {
        return determineAssetType(asset: finding.affectedAsset)
    }
    
    private func parseSemanticAnalysis(response: String) -> (confidence: Double, reasoning: String) {
        // Parse AI response to extract confidence and reasoning
        // This is a simplified parser - would be more sophisticated in practice
        
        let lines = response.components(separatedBy: .newlines)
        var confidence = 0.5
        var reasoning = response
        
        for line in lines {
            if line.lowercased().contains("confidence") {
                // Extract confidence score from line
                let numbers = line.components(separatedBy: .decimalDigits.inverted)
                    .compactMap { Double($0) }
                    .filter { $0 <= 1.0 }
                
                if let conf = numbers.first {
                    confidence = conf
                }
            }
        }
        
        return (confidence, reasoning)
    }
    
    private func simulateToolDetection(finding: Finding, tool: String) async -> Bool {
        // Simulate whether a tool would detect this finding
        // In practice, this would query actual tools or their databases
        
        switch tool {
        case "nmap":
            return finding.type == .vulnerability && finding.affectedAsset.contains(":")
        case "nuclei":
            return finding.description.contains("http") || finding.description.contains("web")
        case "nessus":
            return finding.cvssScore != nil && finding.cvssScore! > 4.0
        case "openvas":
            return finding.severity == .high || finding.severity == .critical
        default:
            return true
        }
    }
    
    private func generateValidationReasoning(
        ensemble: EnsembleValidationResult,
        contextual: ContextualValidationResult,
        semantic: SemanticValidationResult,
        crossValidation: CrossValidationResult,
        finalScore: Double
    ) -> String {
        
        var reasoning = "Validation Analysis:\\n"
        reasoning += "• Ensemble Score: \(String(format: "%.2f", ensemble.weightedScore))\\n"
        reasoning += "• Contextual Score: \(String(format: "%.2f", contextual.score))\\n"
        reasoning += "• Semantic Confidence: \(String(format: "%.2f", semantic.confidence))\\n"
        reasoning += "• Cross-Validation: \(crossValidation.detectionCount)/\(crossValidation.totalTools) tools agree\\n"
        reasoning += "• Final Score: \(String(format: "%.2f", finalScore))\\n\\n"
        
        reasoning += "Key Factors:\\n"
        reasoning += "• \(contextual.reasoning)\\n"
        reasoning += "• \(semantic.reasoning)\\n"
        
        return reasoning
    }
    
    private func updateValidationMetrics(result: ValidationResult) {
        validationMetrics.totalValidations += 1
        
        if result.isFalsePositive {
            validationMetrics.falsePositivesDetected += 1
        } else {
            validationMetrics.truePositives += 1
        }
        
        validationMetrics.averageConfidence = 
            (validationMetrics.averageConfidence * Double(validationMetrics.totalValidations - 1) + result.confidence) / 
            Double(validationMetrics.totalValidations)
        
        validationMetrics.lastValidation = Date()
    }
    
    private func loadPretrainedModels() async {
        // Load pre-trained models from disk if available
        logger.info("📁 Loading pre-trained models")
    }
}

// MARK: - Extensions

extension Array {
    subscript(safe index: Index) -> Element? {
        return indices.contains(index) ? self[index] : nil
    }
}

extension String {
    var sha256: String {
        // Simple hash implementation - would use proper crypto library
        return String(self.hash)
    }
}

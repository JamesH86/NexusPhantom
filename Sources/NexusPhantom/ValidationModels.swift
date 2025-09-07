import Foundation
import SwiftUI

// MARK: - Core Validation Models

struct ValidationResult: Identifiable, Codable {
    let id = UUID()
    let isFalsePositive: Bool
    let confidence: Double
    let score: Double
    let reasoning: String
    let validationMethods: [String: Double]
    let metadata: ValidationMetadata
    
    var riskLevel: RiskLevel {
        if isFalsePositive {
            return .safe
        } else if confidence > 0.9 {
            return .critical
        } else if confidence > 0.7 {
            return .high
        } else if confidence > 0.5 {
            return .medium
        } else {
            return .low
        }
    }
}

struct ValidationMetadata: Codable {
    let modelVersions: [String]
    let validationTime: Date
    let featureCount: Int
    let cacheHit: Bool
}

struct ValidationFeatures {
    // Basic features
    let severity: Finding.Severity
    let type: Finding.FindingType
    let hasCV: Bool
    let hasCWE: Bool
    let referenceCount: Int
    
    // Text features
    let titleLength: Int
    let descriptionLength: Int
    let titleSentiment: Double
    let descriptionSentiment: Double
    
    // Semantic features
    let keywordDensity: Double
    let technicalTerms: Int
    
    // Context features
    let assetType: String
    let scannerConfidence: Double
    
    // Historical features
    let similarFindingsCount: Int
    let previousFalsePositives: Int
    
    // Network features
    let networkContext: NetworkContext?
    
    // Time-based features
    let discoveryTime: Date
    let timeOfDay: Int
    let dayOfWeek: Int
    
    /// Convert features to array for ML model input
    func toArray() -> [Double] {
        var features: [Double] = []
        
        // Convert categorical features to numeric
        features.append(Double(severity.numericValue))
        features.append(Double(type.numericValue))
        features.append(hasCV ? 1.0 : 0.0)
        features.append(hasCWE ? 1.0 : 0.0)
        features.append(Double(referenceCount))
        
        // Text features
        features.append(Double(titleLength))
        features.append(Double(descriptionLength))
        features.append(titleSentiment)
        features.append(descriptionSentiment)
        
        // Semantic features
        features.append(keywordDensity)
        features.append(Double(technicalTerms))
        
        // Context features
        features.append(Double(assetType.hash % 1000) / 1000.0) // Simple hash encoding
        features.append(scannerConfidence)
        
        // Historical features
        features.append(Double(similarFindingsCount))
        features.append(Double(previousFalsePositives))
        
        // Time features
        features.append(Double(timeOfDay) / 24.0)
        features.append(Double(dayOfWeek) / 7.0)
        
        return features
    }
}

struct NetworkContext: Codable {
    let networkProtocol: String
    let port: Int?
    let service: String?
    let version: String?
    let banner: String?
}

// MARK: - Validation Configuration

struct ValidationConfiguration {
    let falsePositiveThreshold: Double
    let retrainingThreshold: Int
    let cacheEnabled: Bool
    let maxCacheSize: Int
    let validationWeights: ValidationWeights
    let modelWeights: [Double]
    
    static let `default` = ValidationConfiguration(
        falsePositiveThreshold: 0.5,
        retrainingThreshold: 50,
        cacheEnabled: true,
        maxCacheSize: 1000,
        validationWeights: ValidationWeights(
            ensemble: 0.4,
            contextual: 0.25,
            semantic: 0.2,
            crossValidation: 0.15
        ),
        modelWeights: [0.3, 0.25, 0.25, 0.2] // Random Forest, XGBoost, Neural Network, SVM
    )
}

struct ValidationWeights {
    let ensemble: Double
    let contextual: Double
    let semantic: Double
    let crossValidation: Double
    
    var total: Double {
        return ensemble + contextual + semantic + crossValidation
    }
    
    var normalized: ValidationWeights {
        let sum = total
        return ValidationWeights(
            ensemble: ensemble / sum,
            contextual: contextual / sum,
            semantic: semantic / sum,
            crossValidation: crossValidation / sum
        )
    }
}

// MARK: - Validation Results

struct EnsembleValidationResult {
    let modelResults: [ModelValidationResult]
    let weightedScore: Double
    let confidence: Double
    let isFalsePositive: Bool
}

struct ContextualValidationResult {
    let context: String
    let score: Double
    let confidence: Double
    let reasoning: String
}

struct SemanticValidationResult {
    let confidence: Double
    let reasoning: String
    let aiModelUsed: String
    let processingTime: TimeInterval
}

struct CrossValidationResult {
    let toolResults: [String: Bool]
    let consensusScore: Double
    let detectionCount: Int
    let totalTools: Int
}

struct ModelValidationResult {
    let modelName: String
    let score: Double
    let confidence: Double
    let reasoning: String
    let features: [String: Double]
}

// MARK: - Learning and Training Models

struct LabeledFinding: Identifiable, Codable {
    let id = UUID()
    let finding: Finding
    let userClassification: UserClassification
    let timestamp: Date
    let context: ContextualInformation
}

enum UserClassification: String, Codable, CaseIterable {
    case truePositive = "true_positive"
    case falsePositive = "false_positive"
    case uncertain = "uncertain"
    case needsReview = "needs_review"
}

struct ContextualInformation: Codable {
    let assetType: String
    let environment: String
    let businessCriticality: String
    let previousIncidents: Int
}

// MARK: - Performance Metrics

class ValidationMetrics: ObservableObject, Codable {
    @Published var totalValidations: Int = 0
    @Published var falsePositivesDetected: Int = 0
    @Published var truePositives: Int = 0
    @Published var averageConfidence: Double = 0.0
    @Published var lastValidation: Date?
    
    init() {}
    
    init(totalValidations: Int = 0, falsePositivesDetected: Int = 0, truePositives: Int = 0, averageConfidence: Double = 0.0, lastValidation: Date? = nil) {
        self.totalValidations = totalValidations
        self.falsePositivesDetected = falsePositivesDetected
        self.truePositives = truePositives
        self.averageConfidence = averageConfidence
        self.lastValidation = lastValidation
    }
    
    var falsePositiveRate: Double {
        guard totalValidations > 0 else { return 0.0 }
        return Double(falsePositivesDetected) / Double(totalValidations)
    }
    
    var truePositiveRate: Double {
        guard totalValidations > 0 else { return 0.0 }
        return Double(truePositives) / Double(totalValidations)
    }
    
    // Codable conformance
    enum CodingKeys: CodingKey {
        case totalValidations, falsePositivesDetected, truePositives, averageConfidence, lastValidation
    }
    
    required init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        totalValidations = try container.decode(Int.self, forKey: .totalValidations)
        falsePositivesDetected = try container.decode(Int.self, forKey: .falsePositivesDetected)
        truePositives = try container.decode(Int.self, forKey: .truePositives)
        averageConfidence = try container.decode(Double.self, forKey: .averageConfidence)
        lastValidation = try container.decodeIfPresent(Date.self, forKey: .lastValidation)
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(totalValidations, forKey: .totalValidations)
        try container.encode(falsePositivesDetected, forKey: .falsePositivesDetected)
        try container.encode(truePositives, forKey: .truePositives)
        try container.encode(averageConfidence, forKey: .averageConfidence)
        try container.encodeIfPresent(lastValidation, forKey: .lastValidation)
    }
}

class ModelPerformanceMetrics: ObservableObject, Codable {
    @Published var accuracy: Double = 0.0
    @Published var precision: Double = 0.0
    @Published var recall: Double = 0.0
    @Published var f1Score: Double = 0.0
    @Published var lastEvaluation: Date?
    @Published var evaluationSamples: Int = 0
    
    init() {}
    
    init(accuracy: Double = 0.0, precision: Double = 0.0, recall: Double = 0.0, f1Score: Double = 0.0, lastEvaluation: Date? = nil, evaluationSamples: Int = 0) {
        self.accuracy = accuracy
        self.precision = precision
        self.recall = recall
        self.f1Score = f1Score
        self.lastEvaluation = lastEvaluation
        self.evaluationSamples = evaluationSamples
    }
    
    var isPerformanceGood: Bool {
        return accuracy > 0.9 && precision > 0.85 && recall > 0.85
    }
    
    // Codable conformance
    enum CodingKeys: CodingKey {
        case accuracy, precision, recall, f1Score, lastEvaluation, evaluationSamples
    }
    
    required init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        accuracy = try container.decode(Double.self, forKey: .accuracy)
        precision = try container.decode(Double.self, forKey: .precision)
        recall = try container.decode(Double.self, forKey: .recall)
        f1Score = try container.decode(Double.self, forKey: .f1Score)
        lastEvaluation = try container.decodeIfPresent(Date.self, forKey: .lastEvaluation)
        evaluationSamples = try container.decode(Int.self, forKey: .evaluationSamples)
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(accuracy, forKey: .accuracy)
        try container.encode(precision, forKey: .precision)
        try container.encode(recall, forKey: .recall)
        try container.encode(f1Score, forKey: .f1Score)
        try container.encodeIfPresent(lastEvaluation, forKey: .lastEvaluation)
        try container.encode(evaluationSamples, forKey: .evaluationSamples)
    }
}

class LearningProgress: ObservableObject, Codable {
    @Published var isRetraining: Bool = false
    @Published var trainingProgress: Double = 0.0
    @Published var samplesProcessed: Int = 0
    @Published var totalSamples: Int = 0
    @Published var lastTraining: Date?
    @Published var trainingLoss: Double = 0.0
    @Published var validationLoss: Double = 0.0
    
    init() {}
    
    init(isRetraining: Bool = false, trainingProgress: Double = 0.0, samplesProcessed: Int = 0, totalSamples: Int = 0, lastTraining: Date? = nil, trainingLoss: Double = 0.0, validationLoss: Double = 0.0) {
        self.isRetraining = isRetraining
        self.trainingProgress = trainingProgress
        self.samplesProcessed = samplesProcessed
        self.totalSamples = totalSamples
        self.lastTraining = lastTraining
        self.trainingLoss = trainingLoss
        self.validationLoss = validationLoss
    }
    
    var isTrainingEffective: Bool {
        return trainingLoss < validationLoss * 1.1 // Not overfitting
    }
    
    // Codable conformance
    enum CodingKeys: CodingKey {
        case isRetraining, trainingProgress, samplesProcessed, totalSamples, lastTraining, trainingLoss, validationLoss
    }
    
    required init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        isRetraining = try container.decode(Bool.self, forKey: .isRetraining)
        trainingProgress = try container.decode(Double.self, forKey: .trainingProgress)
        samplesProcessed = try container.decode(Int.self, forKey: .samplesProcessed)
        totalSamples = try container.decode(Int.self, forKey: .totalSamples)
        lastTraining = try container.decodeIfPresent(Date.self, forKey: .lastTraining)
        trainingLoss = try container.decode(Double.self, forKey: .trainingLoss)
        validationLoss = try container.decode(Double.self, forKey: .validationLoss)
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(isRetraining, forKey: .isRetraining)
        try container.encode(trainingProgress, forKey: .trainingProgress)
        try container.encode(samplesProcessed, forKey: .samplesProcessed)
        try container.encode(totalSamples, forKey: .totalSamples)
        try container.encodeIfPresent(lastTraining, forKey: .lastTraining)
        try container.encode(trainingLoss, forKey: .trainingLoss)
        try container.encode(validationLoss, forKey: .validationLoss)
    }
}

// MARK: - ML Model Protocols

protocol MLValidationModel {
    var name: String { get }
    var version: String { get }
    var isLoaded: Bool { get }
    
    func validate(features: ValidationFeatures) async -> ModelValidationResult
    func retrain(with data: [LabeledFinding]) async
    func save() async throws
    func load() async throws
}

class ContinuousLearningModel {
    private var learningRate: Double = 0.01
    private var momentum: Double = 0.9
    private var batchSize: Int = 32
    
    func updateWithFeedback(_ labeledFinding: LabeledFinding) async {
        // Implement online learning update
        // This would update model weights based on new feedback
    }
    
    func adaptLearningRate(based on: [LabeledFinding]) async {
        // Adaptive learning rate based on recent performance
    }
}

// MARK: - Specific ML Model Implementations

class RandomForestModel: MLValidationModel {
    let name = "RandomForest"
    let version = "1.0.0"
    private(set) var isLoaded = false
    
    func validate(features: ValidationFeatures) async -> ModelValidationResult {
        // Simulate Random Forest prediction
        let featureArray = features.toArray()
        let score = calculateRandomForestScore(features: featureArray)
        
        return ModelValidationResult(
            modelName: name,
            score: score,
            confidence: 0.85,
            reasoning: "Random Forest decision tree ensemble prediction",
            features: [
                "feature_importance": 0.8,
                "tree_count": 100,
                "depth": 10
            ]
        )
    }
    
    func retrain(with data: [LabeledFinding]) async {
        // Retrain Random Forest with new data
    }
    
    func save() async throws {
        // Save model to disk
    }
    
    func load() async throws {
        // Load model from disk
        isLoaded = true
    }
    
    private func calculateRandomForestScore(features: [Double]) -> Double {
        // Simplified Random Forest calculation
        let weightedSum = features.enumerated().map { index, feature in
            let weight = 1.0 / Double(features.count)
            return feature * weight
        }.reduce(0.0) { $0 + $1 }
        
        return min(max(weightedSum, 0.0), 1.0)
    }
}

class XGBoostModel: MLValidationModel {
    let name = "XGBoost"
    let version = "1.0.0"
    private(set) var isLoaded = false
    
    func validate(features: ValidationFeatures) async -> ModelValidationResult {
        // Simulate XGBoost prediction
        let featureArray = features.toArray()
        let score = calculateXGBoostScore(features: featureArray)
        
        return ModelValidationResult(
            modelName: name,
            score: score,
            confidence: 0.9,
            reasoning: "XGBoost gradient boosting prediction",
            features: [
                "gain": 0.7,
                "cover": 0.8,
                "frequency": 0.6
            ]
        )
    }
    
    func retrain(with data: [LabeledFinding]) async {
        // Retrain XGBoost with new data
    }
    
    func save() async throws {
        // Save model to disk
    }
    
    func load() async throws {
        // Load model from disk
        isLoaded = true
    }
    
    private func calculateXGBoostScore(features: [Double]) -> Double {
        // Simplified XGBoost calculation with boosting simulation
        var score = 0.0
        var weight = 1.0
        
        for feature in features {
            score += feature * weight
            weight *= 0.95 // Diminishing weight for boosting effect
        }
        
        return 1.0 / (1.0 + exp(-score)) // Sigmoid activation
    }
}

class NeuralNetworkModel: MLValidationModel {
    let name = "NeuralNetwork"
    let version = "1.0.0"
    private(set) var isLoaded = false
    
    func validate(features: ValidationFeatures) async -> ModelValidationResult {
        // Simulate Neural Network prediction
        let featureArray = features.toArray()
        let score = calculateNeuralNetworkScore(features: featureArray)
        
        return ModelValidationResult(
            modelName: name,
            score: score,
            confidence: 0.88,
            reasoning: "Deep neural network prediction",
            features: [
                "hidden_layers": 3,
                "neurons": 128,
                "activation": 1.0
            ]
        )
    }
    
    func retrain(with data: [LabeledFinding]) async {
        // Retrain Neural Network with new data
    }
    
    func save() async throws {
        // Save model to disk
    }
    
    func load() async throws {
        // Load model from disk
        isLoaded = true
    }
    
    private func calculateNeuralNetworkScore(features: [Double]) -> Double {
        // Simplified neural network forward pass
        var hiddenLayer = features.map { relu($0) }
        
        // Hidden layer 1
        hiddenLayer = hiddenLayer.map { $0 * 0.8 + 0.1 }
        
        // Hidden layer 2
        hiddenLayer = hiddenLayer.map { relu($0 * 0.6 + 0.2) }
        
        // Output layer
        let output = hiddenLayer.reduce(0, +) / Double(hiddenLayer.count)
        
        return 1.0 / (1.0 + exp(-output)) // Sigmoid output
    }
    
    private func relu(_ x: Double) -> Double {
        return max(0, x)
    }
}

class SVMModel: MLValidationModel {
    let name = "SVM"
    let version = "1.0.0"
    private(set) var isLoaded = false
    
    func validate(features: ValidationFeatures) async -> ModelValidationResult {
        // Simulate SVM prediction
        let featureArray = features.toArray()
        let score = calculateSVMScore(features: featureArray)
        
        return ModelValidationResult(
            modelName: name,
            score: score,
            confidence: 0.82,
            reasoning: "Support Vector Machine classification",
            features: [
                "support_vectors": 50,
                "kernel": 1.0,
                "margin": 0.8
            ]
        )
    }
    
    func retrain(with data: [LabeledFinding]) async {
        // Retrain SVM with new data
    }
    
    func save() async throws {
        // Save model to disk
    }
    
    func load() async throws {
        // Load model from disk
        isLoaded = true
    }
    
    private func calculateSVMScore(features: [Double]) -> Double {
        // Simplified SVM calculation with RBF kernel simulation
        let gamma = 0.5
        var kernelSum = 0.0
        
        for i in 0..<features.count {
            let distance = features[i] - 0.5 // Distance from center
            kernelSum += exp(-gamma * distance * distance)
        }
        
        let decision = kernelSum / Double(features.count) - 0.5
        return 1.0 / (1.0 + exp(-decision))
    }
}

// MARK: - Contextual Validation Models

class WebAppValidationModel: MLValidationModel {
    let name = "WebAppValidator"
    let version = "1.0.0"
    private(set) var isLoaded = false
    
    func validate(features: ValidationFeatures) async -> ModelValidationResult {
        // Specialized validation for web applications
        var score = 0.5
        
        // Web-specific checks
        if features.technicalTerms > 3 {
            score += 0.2
        }
        
        if features.keywordDensity > 0.1 {
            score += 0.1
        }
        
        // Check for common web false positives
        if features.previousFalsePositives > 0 {
            score -= 0.3
        }
        
        return ModelValidationResult(
            modelName: name,
            score: max(min(score, 1.0), 0.0),
            confidence: 0.85,
            reasoning: "Web application specific validation",
            features: [:]
        )
    }
    
    func retrain(with data: [LabeledFinding]) async {}
    func save() async throws {}
    func load() async throws { isLoaded = true }
}

class NetworkServiceValidationModel: MLValidationModel {
    let name = "NetworkServiceValidator"
    let version = "1.0.0"
    private(set) var isLoaded = false
    
    func validate(features: ValidationFeatures) async -> ModelValidationResult {
        // Specialized validation for network services
        var score = 0.5
        
        // Network service specific checks
        if features.networkContext != nil {
            score += 0.2
        }
        
        if features.scannerConfidence > 0.8 {
            score += 0.2
        }
        
        return ModelValidationResult(
            modelName: name,
            score: max(min(score, 1.0), 0.0),
            confidence: 0.8,
            reasoning: "Network service specific validation",
            features: [:]
        )
    }
    
    func retrain(with data: [LabeledFinding]) async {}
    func save() async throws {}
    func load() async throws { isLoaded = true }
}

class SystemConfigValidationModel: MLValidationModel {
    let name = "SystemConfigValidator"
    let version = "1.0.0"
    private(set) var isLoaded = false
    
    func validate(features: ValidationFeatures) async -> ModelValidationResult {
        return ModelValidationResult(
            modelName: name,
            score: 0.6,
            confidence: 0.7,
            reasoning: "System configuration validation",
            features: [:]
        )
    }
    
    func retrain(with data: [LabeledFinding]) async {}
    func save() async throws {}
    func load() async throws { isLoaded = true }
}

class DatabaseValidationModel: MLValidationModel {
    let name = "DatabaseValidator"
    let version = "1.0.0"
    private(set) var isLoaded = false
    
    func validate(features: ValidationFeatures) async -> ModelValidationResult {
        return ModelValidationResult(
            modelName: name,
            score: 0.7,
            confidence: 0.75,
            reasoning: "Database security validation",
            features: [:]
        )
    }
    
    func retrain(with data: [LabeledFinding]) async {}
    func save() async throws {}
    func load() async throws { isLoaded = true }
}

class MobileValidationModel: MLValidationModel {
    let name = "MobileValidator"
    let version = "1.0.0"
    private(set) var isLoaded = false
    
    func validate(features: ValidationFeatures) async -> ModelValidationResult {
        return ModelValidationResult(
            modelName: name,
            score: 0.65,
            confidence: 0.73,
            reasoning: "Mobile application validation",
            features: [:]
        )
    }
    
    func retrain(with data: [LabeledFinding]) async {}
    func save() async throws {}
    func load() async throws { isLoaded = true }
}

// MARK: - Extensions for Finding Model

extension Finding.Severity {
    var numericValue: Int {
        switch self {
        case .critical: return 5
        case .high: return 4
        case .medium: return 3
        case .low: return 2
        case .info: return 1
        }
    }
}

extension Finding.FindingType {
    var numericValue: Int {
        switch self {
        case .vulnerability: return 3
        case .configuration: return 2
        case .information: return 1
        }
    }
}

enum RiskLevel: String, CaseIterable {
    case critical = "Critical"
    case high = "High"
    case medium = "Medium"
    case low = "Low"
    case safe = "Safe"
    
    var color: Color {
        switch self {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .blue
        case .safe: return .green
        }
    }
}

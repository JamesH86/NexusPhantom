import SwiftUI
import Foundation
import Network
import Combine
import CryptoKit
import os.log

// MARK: - Critical Infrastructure Protection Module
@MainActor
class CriticalInfrastructureModule: ObservableObject {
    @Published var scadaSystems: [SCADASystem] = []
    @Published var activeThreats: [InfrastructureThreat] = []
    @Published var powerGridStatus: PowerGridStatus = .normal
    @Published var complianceScore: Double = 0.0
    @Published var isMonitoring = false
    @Published var realTimeAlerts: [CriticalAlert] = []
    @Published var networkTopology: InfrastructureGraph = InfrastructureGraph()
    
    // Nation-State Threat Detection
    @Published var nationStateActivity: [NationStateThreat] = []
    @Published var threatLevel: ThreatLevel = .green
    @Published var attributionConfidence: Double = 0.0
    
    // Compliance Frameworks
    @Published var nercCIPCompliance: ComplianceStatus = ComplianceStatus(framework: "NERC CIP", score: 0.0, lastAssessed: Date(), criticalFindings: [])
    @Published var nistCSFCompliance: ComplianceStatus = ComplianceStatus(framework: "NIST CSF", score: 0.0, lastAssessed: Date(), criticalFindings: [])
    @Published var iec62443Compliance: ComplianceStatus = ComplianceStatus(framework: "IEC 62443", score: 0.0, lastAssessed: Date(), criticalFindings: [])
    
    private let logger = Logger(subsystem: "NexusPhantom", category: "CriticalInfrastructure")
    private var protocolAnalyzers: [String: ProtocolAnalyzer] = [:]
    private var quantumCrypto = QuantumSafeCryptoEngine()
    private var incidentOrchestrator = AutonomousIncidentResponse()
    
    // Public accessors
    func getQuantumEngine() -> QuantumSafeCryptoEngine {
        return quantumCrypto
    }
    
    func getIncidentOrchestrator() -> AutonomousIncidentResponse {
        return incidentOrchestrator
    }
    
    init() {
        setupProtocolAnalyzers()
        loadMockData()
    }
    
    // MARK: - Core Infrastructure Protection
    func startCriticalMonitoring() async {
        logger.info("🏭 Starting Critical Infrastructure Protection")
        isMonitoring = true
        
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.monitorSCADAProtocols() }
            group.addTask { await self.detectNationStateThreats() }
            group.addTask { await self.analyzeComplianceStatus() }
            group.addTask { await self.mapInfrastructureDependencies() }
            group.addTask { await self.monitorQuantumThreats() }
        }
    }
    
    func stopCriticalMonitoring() {
        logger.info("🛑 Stopping Critical Infrastructure Protection")
        isMonitoring = false
        realTimeAlerts.removeAll()
    }
    
    // MARK: - SCADA/ICS Protocol Analysis
    private func setupProtocolAnalyzers() {
        protocolAnalyzers = [
            "Modbus": ModbusAnalyzer(),
            "DNP3": DNP3Analyzer(),
            "OPC_UA": OPCUAAnalyzer(),
            "IEC_104": IEC104Analyzer(),
            "BACnet": BACnetAnalyzer(),
            "C37.118": SynchrophasorAnalyzer(),
            "ProfiNet": ProfiNetAnalyzer()
        ]
    }
    
    private func monitorSCADAProtocols() async {
        while isMonitoring {
            for (protocolName, analyzer) in protocolAnalyzers {
                let anomalies = await analyzer.detectAnomalies()
                
                for anomaly in anomalies {
                    await handleProtocolAnomaly(protocol: protocolName, anomaly: anomaly)
                }
            }
            
            try? await Task.sleep(nanoseconds: 5_000_000_000) // 5 seconds
        }
    }
    
    private func handleProtocolAnomaly(protocol protocolName: String, anomaly: ProtocolAnomaly) async {
        let threat = InfrastructureThreat(
            id: UUID(),
            type: .protocolAnomaly,
            severity: anomaly.severity,
            networkProtocol: protocolName,
            description: anomaly.description,
            timestamp: Date(),
            mitigationSuggestion: "Isolate affected systems and review protocol configurations"
        )
        
        activeThreats.append(threat)
        
        if threat.severity >= .high {
            await triggerCriticalAlert(threat: threat)
            await incidentOrchestrator.evaluateResponse(threat: threat)
        }
    }
    
    // MARK: - Nation-State Threat Detection
    private func detectNationStateThreats() async {
        while isMonitoring {
            let techniques = await analyzeTTPPatterns()
            let _ = await correlateWithThreatIntel()
            
            for technique in techniques {
                if let attribution = await attributeToNationState(technique: technique) {
                    let threat = NationStateThreat(
                        id: UUID(),
                        actor: attribution.actor,
                        confidence: attribution.confidence,
                        techniques: [technique],
                        timestamp: Date(),
                        campaign: attribution.campaign
                    )
                    
                    nationStateActivity.append(threat)
                    await updateThreatLevel(basedOn: threat)
                }
            }
            
            try? await Task.sleep(nanoseconds: 10_000_000_000) // 10 seconds
        }
    }
    
    private func analyzeTTPPatterns() async -> [MITRETechnique] {
        // Simulate detection of MITRE ATT&CK for ICS techniques
        let icsTechniques: [MITRETechnique] = [
            MITRETechnique(id: "T0800", name: "Activate Firmware Update Mode"),
            MITRETechnique(id: "T0801", name: "Monitor Process State"),
            MITRETechnique(id: "T0802", name: "Automated Collection"),
            MITRETechnique(id: "T0803", name: "Block Command Message"),
            MITRETechnique(id: "T0804", name: "Block Reporting Message"),
            MITRETechnique(id: "T0805", name: "Block Serial COM"),
            MITRETechnique(id: "T0806", name: "Brute Force I/O"),
            MITRETechnique(id: "T0807", name: "Command-Line Interface"),
            MITRETechnique(id: "T0808", name: "Control Device Identification"),
            MITRETechnique(id: "T0809", name: "Data from Information Repositories")
        ]
        
        return icsTechniques.filter { _ in Bool.random() && Bool.random() } // Simulate detection
    }
    
    // MARK: - Real-Time Infrastructure Mapping
    private func mapInfrastructureDependencies() async {
        while isMonitoring {
            await updateNetworkTopology()
            await calculateBlastRadius()
            await assessCascadingRisks()
            
            try? await Task.sleep(nanoseconds: 15_000_000_000) // 15 seconds
        }
    }
    
    private func updateNetworkTopology() async {
        // Update the infrastructure graph with real-time data
        let newNodes = await discoverInfrastructureAssets()
        let dependencies = await analyzeDependencies(nodes: newNodes)
        
        networkTopology.updateGraph(nodes: newNodes, edges: dependencies)
    }
    
    private func calculateBlastRadius() async {
        for node in networkTopology.criticalNodes {
            let impact = await simulateNodeFailure(node: node)
            node.blastRadius = impact.affectedSystems
            node.riskScore = impact.calculateRiskScore()
        }
    }
    
    private func assessCascadingRisks() async {
        // Analyze cascading failure risks across interconnected systems
        for dependency in networkTopology.edges {
            if dependency.strength > 0.8 {
                // High-strength dependency creates cascading risk
                // This would trigger additional monitoring and protection
            }
        }
    }
    
    // MARK: - Quantum-Safe Cryptography
    private func monitorQuantumThreats() async {
        while isMonitoring {
            let quantumReadiness = await quantumCrypto.assessQuantumReadiness()
            
            if quantumReadiness.riskLevel > 0.7 {
                let alert = CriticalAlert(
                    id: UUID(),
                    title: "🔬 QUANTUM THREAT DETECTED",
                    message: "Post-quantum cryptography upgrade required",
                    severity: .critical,
                    category: .quantumThreat,
                    timestamp: Date()
                )
                
                realTimeAlerts.append(alert)
            }
            
            try? await Task.sleep(nanoseconds: 30_000_000_000) // 30 seconds
        }
    }
    
    // MARK: - Compliance Monitoring
    private func analyzeComplianceStatus() async {
        while isMonitoring {
            await updateNERCCIPCompliance()
            await updateNISTCSFCompliance()
            await updateIEC62443Compliance()
            
            complianceScore = calculateOverallCompliance()
            
            try? await Task.sleep(nanoseconds: 60_000_000_000) // 1 minute
        }
    }
    
    private func updateNERCCIPCompliance() async {
        // Simulate NERC CIP compliance checking
        let controls = await evaluateNERCControls()
        let passedControls = controls.filter { $0.status == .compliant }.count
        let totalControls = controls.count
        
        let compliancePercentage = Double(passedControls) / Double(totalControls)
        
        nercCIPCompliance = ComplianceStatus(
            framework: "NERC CIP",
            score: compliancePercentage,
            lastAssessed: Date(),
            criticalFindings: controls.filter { $0.status == .nonCompliant && $0.criticality == .high }
        )
    }
    
    // MARK: - Alert System
    private func triggerCriticalAlert(threat: InfrastructureThreat) async {
        let alert = CriticalAlert(
            id: UUID(),
            title: "🚨 CRITICAL INFRASTRUCTURE THREAT",
            message: threat.description,
            severity: threat.severity,
            category: .infrastructureThreat,
            timestamp: Date(),
            threat: threat
        )
        
        realTimeAlerts.insert(alert, at: 0)
        
        // Limit alerts to prevent memory issues
        if realTimeAlerts.count > 100 {
            realTimeAlerts = Array(realTimeAlerts.prefix(100))
        }
        
        logger.critical("🚨 Critical Alert: \(alert.title) - \(alert.message)")
    }
    
    // MARK: - Mock Data for Demo
    private func loadMockData() {
        scadaSystems = createMockSCADASystems()
        activeThreats = createMockThreats()
        nationStateActivity = createMockNationStateThreats()
        realTimeAlerts = createMockAlerts()
    }
    
    // MARK: - Helper Functions
    private func generateMitigation(for anomaly: ProtocolAnomaly) -> String {
        switch anomaly.type {
        case .unauthorizedAccess:
            return "Implement multi-factor authentication and network segmentation"
        case .protocolViolation:
            return "Update protocol parsers and implement strict validation"
        case .abnormalTraffic:
            return "Deploy traffic shaping and anomaly detection rules"
        case .firmwareManipulation:
            return "Enable secure boot and firmware integrity monitoring"
        }
    }
    
    private func correlateWithThreatIntel() async -> [ThreatIOC] {
        // Simulate threat intelligence correlation
        return []
    }
    
    private func attributeToNationState(technique: MITRETechnique) async -> NationStateAttribution? {
        // Simulate nation-state attribution logic
        let actors = ["APT1", "APT28", "APT29", "Lazarus", "Equation Group", "Sandworm"]
        
        if Bool.random() {
            return NationStateAttribution(
                actor: actors.randomElement() ?? "Unknown",
                confidence: Double.random(in: 0.6...0.95),
                campaign: "Operation \(["GridStorm", "PowerOutage", "DarkEnergy", "NightDragon"].randomElement() ?? "Unknown")"
            )
        }
        
        return nil
    }
    
    private func updateThreatLevel(basedOn threat: NationStateThreat) async {
        if threat.confidence > 0.8 {
            threatLevel = .red
        } else if threat.confidence > 0.6 {
            threatLevel = .orange
        } else {
            threatLevel = .yellow
        }
    }
    
    private func discoverInfrastructureAssets() async -> [InfrastructureNode] {
        // Mock discovery of infrastructure assets
        return [
            InfrastructureNode(id: UUID(), name: "Primary Substation", type: .powerSubstation, criticality: .critical),
            InfrastructureNode(id: UUID(), name: "Water Treatment Plant", type: .waterTreatment, criticality: .high),
            InfrastructureNode(id: UUID(), name: "Gas Distribution Hub", type: .gasDistribution, criticality: .high),
            InfrastructureNode(id: UUID(), name: "Communications Tower", type: .telecommunications, criticality: .medium)
        ]
    }
    
    private func analyzeDependencies(nodes: [InfrastructureNode]) async -> [InfrastructureDependency] {
        var dependencies: [InfrastructureDependency] = []
        
        for i in 0..<nodes.count {
            for j in i+1..<nodes.count {
                if Bool.random() { // Simulate dependency discovery
                    dependencies.append(InfrastructureDependency(
                        from: nodes[i].id,
                        to: nodes[j].id,
                        type: .electrical,
                        strength: Double.random(in: 0.3...1.0)
                    ))
                }
            }
        }
        
        return dependencies
    }
    
    private func simulateNodeFailure(node: InfrastructureNode) async -> FailureImpactAnalysis {
        return FailureImpactAnalysis(
            affectedSystems: Int.random(in: 10...100),
            estimatedDowntime: TimeInterval.random(in: 3600...86400),
            economicImpact: Double.random(in: 100_000...10_000_000)
        )
    }
    
    private func evaluateNERCControls() async -> [ComplianceControl] {
        let controls = [
            "CIP-002 - Cyber Security — BES Cyber System Categorization",
            "CIP-003 - Cyber Security — Security Management Controls",
            "CIP-004 - Cyber Security — Personnel & Training",
            "CIP-005 - Cyber Security — Electronic Security Perimeters",
            "CIP-006 - Cyber Security — Physical Security of BES Cyber Systems",
            "CIP-007 - Cyber Security — System Security Management",
            "CIP-008 - Cyber Security — Incident Reporting and Response Planning",
            "CIP-009 - Cyber Security — Recovery Plans for BES Cyber Systems",
            "CIP-010 - Cyber Security — Configuration Change Management",
            "CIP-011 - Cyber Security — Information Protection",
            "CIP-013 - Cyber Security — Supply Chain Risk Management"
        ]
        
        return controls.map { control in
            ComplianceControl(
                name: control,
                status: Bool.random() ? .compliant : .nonCompliant,
                criticality: Bool.random() ? .high : .medium,
                lastAssessed: Date()
            )
        }
    }
    
    private func calculateOverallCompliance() -> Double {
        let scores = [nercCIPCompliance.score, nistCSFCompliance.score, iec62443Compliance.score]
        return scores.reduce(0, +) / Double(scores.count)
    }
    
    private func updateNISTCSFCompliance() async {
        nistCSFCompliance = ComplianceStatus(
            framework: "NIST CSF",
            score: Double.random(in: 0.7...0.95),
            lastAssessed: Date(),
            criticalFindings: []
        )
    }
    
    private func updateIEC62443Compliance() async {
        iec62443Compliance = ComplianceStatus(
            framework: "IEC 62443",
            score: Double.random(in: 0.65...0.9),
            lastAssessed: Date(),
            criticalFindings: []
        )
    }
}

// MARK: - Supporting Data Models
struct SCADASystem: Identifiable {
    let id = UUID()
    let name: String
    let type: SCADAType
    let status: SystemStatus
    let lastUpdate: Date
    let criticalityLevel: CriticalityLevel
    let securityScore: Double
}

enum SCADAType: String, CaseIterable {
    case powerGrid = "Power Grid"
    case waterTreatment = "Water Treatment"
    case gasDistribution = "Gas Distribution"
    case nuclearPlant = "Nuclear Plant"
    case chemicalProcessing = "Chemical Processing"
    case telecommunications = "Telecommunications"
    case transportation = "Transportation"
}

enum SystemStatus: String {
    case operational = "Operational"
    case degraded = "Degraded"
    case offline = "Offline"
    case compromised = "Compromised"
    case maintenance = "Maintenance"
    
    var color: Color {
        switch self {
        case .operational: return .green
        case .degraded: return .yellow
        case .offline: return .red
        case .compromised: return .purple
        case .maintenance: return .orange
        }
    }
}

enum CriticalityLevel: String {
    case critical = "Critical"
    case high = "High"
    case medium = "Medium"
    case low = "Low"
    
    var color: Color {
        switch self {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .green
        }
    }
}

enum PowerGridStatus: String {
    case normal = "Normal"
    case elevated = "Elevated Alert"
    case critical = "Critical"
    case emergency = "Emergency"
    
    var color: Color {
        switch self {
        case .normal: return .green
        case .elevated: return .yellow
        case .critical: return .orange
        case .emergency: return .red
        }
    }
}

struct InfrastructureThreat: Identifiable {
    let id: UUID
    let type: ThreatType
    let severity: ThreatSeverity
    let networkProtocol: String?
    let description: String
    let timestamp: Date
    let mitigationSuggestion: String
}

enum ThreatType {
    case protocolAnomaly
    case unauthorizedAccess
    case malwareDetection
    case physicalTamper
    case networkIntrusion
    case firmwareManipulation
}

enum ThreatSeverity: String, Comparable {
    case low = "Low"
    case medium = "Medium"
    case high = "High"
    case critical = "Critical"
    
    static func < (lhs: ThreatSeverity, rhs: ThreatSeverity) -> Bool {
        let order: [ThreatSeverity] = [.low, .medium, .high, .critical]
        guard let lhsIndex = order.firstIndex(of: lhs),
              let rhsIndex = order.firstIndex(of: rhs) else {
            return false
        }
        return lhsIndex < rhsIndex
    }
    
    var color: Color {
        switch self {
        case .low: return .green
        case .medium: return .yellow
        case .high: return .orange
        case .critical: return .red
        }
    }
}

enum ThreatLevel: String {
    case green = "Green - Normal"
    case yellow = "Yellow - Elevated"
    case orange = "Orange - High"
    case red = "Red - Severe"
    
    var color: Color {
        switch self {
        case .green: return .green
        case .yellow: return .yellow
        case .orange: return .orange
        case .red: return .red
        }
    }
}

struct NationStateThreat: Identifiable {
    let id: UUID
    let actor: String
    let confidence: Double
    let techniques: [MITRETechnique]
    let timestamp: Date
    let campaign: String
}

struct MITRETechnique: Identifiable {
    let id: String // T0800, etc.
    let name: String
}

struct NationStateAttribution {
    let actor: String
    let confidence: Double
    let campaign: String
}

struct CriticalAlert: Identifiable {
    let id: UUID
    let title: String
    let message: String
    let severity: ThreatSeverity
    let category: AlertCategory
    let timestamp: Date
    let threat: InfrastructureThreat?
    
    init(id: UUID, title: String, message: String, severity: ThreatSeverity, category: AlertCategory, timestamp: Date, threat: InfrastructureThreat? = nil) {
        self.id = id
        self.title = title
        self.message = message
        self.severity = severity
        self.category = category
        self.timestamp = timestamp
        self.threat = threat
    }
}

enum AlertCategory: String {
    case infrastructureThreat = "Infrastructure Threat"
    case complianceViolation = "Compliance Violation"
    case quantumThreat = "Quantum Threat"
    case nationStateActivity = "Nation-State Activity"
    case systemFailure = "System Failure"
}

struct ComplianceStatus {
    let framework: String
    let score: Double
    let lastAssessed: Date
    let criticalFindings: [ComplianceControl]
}

struct ComplianceControl {
    let name: String
    let status: ComplianceControlStatus
    let criticality: CriticalityLevel
    let lastAssessed: Date
}

enum ComplianceControlStatus {
    case compliant
    case nonCompliant
    case notApplicable
    case underReview
}

// MARK: - Protocol Analyzers
protocol ProtocolAnalyzer {
    func detectAnomalies() async -> [ProtocolAnomaly]
}

struct ProtocolAnomaly {
    let type: AnomalyType
    let severity: ThreatSeverity
    let description: String
    let timestamp: Date
}

enum AnomalyType {
    case unauthorizedAccess
    case protocolViolation
    case abnormalTraffic
    case firmwareManipulation
}

struct ModbusAnalyzer: ProtocolAnalyzer {
    func detectAnomalies() async -> [ProtocolAnomaly] {
        if Bool.random() && Bool.random() {
            return [ProtocolAnomaly(
                type: .protocolViolation,
                severity: .high,
                description: "Unauthorized Modbus function code 0x06 detected",
                timestamp: Date()
            )]
        }
        return []
    }
}

struct DNP3Analyzer: ProtocolAnalyzer {
    func detectAnomalies() async -> [ProtocolAnomaly] {
        if Bool.random() && Bool.random() && Bool.random() {
            return [ProtocolAnomaly(
                type: .unauthorizedAccess,
                severity: .critical,
                description: "DNP3 authentication bypass attempt detected",
                timestamp: Date()
            )]
        }
        return []
    }
}

struct OPCUAAnalyzer: ProtocolAnalyzer {
    func detectAnomalies() async -> [ProtocolAnomaly] {
        return []
    }
}

struct IEC104Analyzer: ProtocolAnalyzer {
    func detectAnomalies() async -> [ProtocolAnomaly] {
        return []
    }
}

struct BACnetAnalyzer: ProtocolAnalyzer {
    func detectAnomalies() async -> [ProtocolAnomaly] {
        return []
    }
}

struct SynchrophasorAnalyzer: ProtocolAnalyzer {
    func detectAnomalies() async -> [ProtocolAnomaly] {
        return []
    }
}

struct ProfiNetAnalyzer: ProtocolAnalyzer {
    func detectAnomalies() async -> [ProtocolAnomaly] {
        return []
    }
}

// MARK: - Infrastructure Graph
class InfrastructureGraph: ObservableObject {
    @Published var nodes: [InfrastructureNode] = []
    @Published var edges: [InfrastructureDependency] = []
    
    var criticalNodes: [InfrastructureNode] {
        return nodes.filter { $0.criticality == .critical }
    }
    
    func updateGraph(nodes: [InfrastructureNode], edges: [InfrastructureDependency]) {
        self.nodes = nodes
        self.edges = edges
    }
}

class InfrastructureNode: ObservableObject, Identifiable {
    let id: UUID
    let name: String
    let type: InfrastructureType
    let criticality: CriticalityLevel
    @Published var blastRadius: Int = 0
    @Published var riskScore: Double = 0.0
    
    init(id: UUID, name: String, type: InfrastructureType, criticality: CriticalityLevel) {
        self.id = id
        self.name = name
        self.type = type
        self.criticality = criticality
    }
}

enum InfrastructureType {
    case powerSubstation
    case waterTreatment
    case gasDistribution
    case telecommunications
    case transportation
    case healthcare
}

struct InfrastructureDependency: Identifiable {
    let id = UUID()
    let from: UUID
    let to: UUID
    let type: DependencyType
    let strength: Double
}

enum DependencyType {
    case electrical
    case network
    case physical
    case logical
}

struct FailureImpactAnalysis {
    let affectedSystems: Int
    let estimatedDowntime: TimeInterval
    let economicImpact: Double
    
    func calculateRiskScore() -> Double {
        let systemsWeight = Double(affectedSystems) / 100.0
        let downtimeWeight = estimatedDowntime / 86400.0 // Days
        let economicWeight = economicImpact / 10_000_000.0 // Millions
        
        return min((systemsWeight + downtimeWeight + economicWeight) / 3.0, 1.0)
    }
}

// MARK: - Quantum-Safe Cryptography
class QuantumSafeCryptoEngine: ObservableObject {
    @Published var quantumReadiness: Double = 0.8
    
    func assessQuantumReadiness() async -> QuantumThreatAssessment {
        let riskLevel = 1.0 - quantumReadiness
        return QuantumThreatAssessment(riskLevel: riskLevel, recommendation: generateRecommendation(riskLevel: riskLevel))
    }
    
    private func generateRecommendation(riskLevel: Double) -> String {
        if riskLevel > 0.8 {
            return "Immediate post-quantum cryptography migration required"
        } else if riskLevel > 0.5 {
            return "Plan post-quantum cryptography transition within 6 months"
        } else {
            return "Monitor quantum computing developments"
        }
    }
}

struct QuantumThreatAssessment {
    let riskLevel: Double
    let recommendation: String
}

// MARK: - Autonomous Incident Response
class AutonomousIncidentResponse: ObservableObject {
    @Published var autonomyMode: AutonomyMode = .advisory
    @Published var activePlaybooks: [ResponsePlaybook] = []
    
    func evaluateResponse(threat: InfrastructureThreat) async {
        let playbook = selectPlaybook(for: threat)
        
        switch autonomyMode {
        case .advisory:
            // Only suggest actions
            break
        case .supervised:
            // Execute with human approval
            break
        case .autonomous:
            // Execute automatically
            await executePlaybook(playbook)
        }
    }
    
    private func selectPlaybook(for threat: InfrastructureThreat) -> ResponsePlaybook {
        return ResponsePlaybook(
            id: UUID(),
            name: "Standard Containment",
            actions: [
                "Isolate affected system",
                "Notify security team",
                "Begin forensic collection",
                "Implement emergency procedures"
            ]
        )
    }
    
    private func executePlaybook(_ playbook: ResponsePlaybook) async {
        activePlaybooks.append(playbook)
        // Execute containment actions
    }
}

enum AutonomyMode: String, CaseIterable {
    case advisory = "Advisory"
    case supervised = "Supervised"
    case autonomous = "Autonomous"
}

struct ResponsePlaybook: Identifiable {
    let id: UUID
    let name: String
    let actions: [String]
}

struct ThreatIOC: Identifiable {
    let id = UUID()
    let type: String
    let value: String
    let source: String
}

// MARK: - Mock Data Generators
extension CriticalInfrastructureModule {
    private func createMockSCADASystems() -> [SCADASystem] {
        return [
            SCADASystem(name: "Primary Power Grid", type: .powerGrid, status: .operational, lastUpdate: Date(), criticalityLevel: .critical, securityScore: 0.92),
            SCADASystem(name: "Water Treatment Facility #1", type: .waterTreatment, status: .operational, lastUpdate: Date(), criticalityLevel: .high, securityScore: 0.87),
            SCADASystem(name: "Natural Gas Distribution", type: .gasDistribution, status: .degraded, lastUpdate: Date(), criticalityLevel: .high, securityScore: 0.74),
            SCADASystem(name: "Nuclear Reactor Control", type: .nuclearPlant, status: .operational, lastUpdate: Date(), criticalityLevel: .critical, securityScore: 0.96),
            SCADASystem(name: "Chemical Processing Plant", type: .chemicalProcessing, status: .maintenance, lastUpdate: Date(), criticalityLevel: .medium, securityScore: 0.81),
            SCADASystem(name: "5G Network Infrastructure", type: .telecommunications, status: .operational, lastUpdate: Date(), criticalityLevel: .high, securityScore: 0.89)
        ]
    }
    
    private func createMockThreats() -> [InfrastructureThreat] {
        return [
            InfrastructureThreat(
                id: UUID(),
                type: .protocolAnomaly,
                severity: .high,
                networkProtocol: "Modbus",
                description: "Unauthorized write operations detected on critical control registers",
                timestamp: Date().addingTimeInterval(-300),
                mitigationSuggestion: "Implement write protection and access control lists"
            ),
            InfrastructureThreat(
                id: UUID(),
                type: .networkIntrusion,
                severity: .critical,
                networkProtocol: "DNP3",
                description: "Potential nation-state actor attempting authentication bypass",
                timestamp: Date().addingTimeInterval(-600),
                mitigationSuggestion: "Isolate affected network segment and enable enhanced monitoring"
            )
        ]
    }
    
    private func createMockNationStateThreats() -> [NationStateThreat] {
        return [
            NationStateThreat(
                id: UUID(),
                actor: "APT28 (Fancy Bear)",
                confidence: 0.89,
                techniques: [
                    MITRETechnique(id: "T0800", name: "Activate Firmware Update Mode"),
                    MITRETechnique(id: "T0802", name: "Automated Collection")
                ],
                timestamp: Date().addingTimeInterval(-1800),
                campaign: "Operation GridStorm"
            )
        ]
    }
    
    private func createMockAlerts() -> [CriticalAlert] {
        return [
            CriticalAlert(
                id: UUID(),
                title: "🚨 CRITICAL INFRASTRUCTURE COMPROMISE",
                message: "Unauthorized access detected in power grid control systems",
                severity: .critical,
                category: .infrastructureThreat,
                timestamp: Date().addingTimeInterval(-120)
            ),
            CriticalAlert(
                id: UUID(),
                title: "⚠️ COMPLIANCE VIOLATION",
                message: "NERC CIP-007 security control failure detected",
                severity: .high,
                category: .complianceViolation,
                timestamp: Date().addingTimeInterval(-300)
            )
        ]
    }
}

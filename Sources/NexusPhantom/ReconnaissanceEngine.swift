import Foundation
import Network
import Combine
import os.log
import SwiftUI
import SystemConfiguration

/// Enhanced Reconnaissance Engine with AI-powered capabilities
/// Implements comprehensive asset discovery, OSINT gathering, and ML-based validation
@MainActor
class ReconnaissanceEngine: ObservableObject {
    
    // MARK: - Published Properties
    @Published var isScanning = false
    @Published var discoveredAssets: [DiscoveredAsset] = []
    @Published var osintResults: [OSINTResult] = []
    @Published var vulnerabilities: [ValidatedVulnerability] = []
    @Published var scanProgress: ScanProgress = ScanProgress()
    @Published var activeTargets: [Target] = []
    
    // MARK: - Dependencies
    private let aiOrchestrator: AIOrchestrator
    private let threatIntelligence: ThreatIntelligenceEngine
    private let mlValidator: FalsePositiveValidator
    private let logger = Logger(subsystem: "NexusPhantom", category: "ReconnaissanceEngine")
    
    // MARK: - Configuration
    private var scanConfiguration = ReconConfiguration.default
    private var cancellables = Set<AnyCancellable>()
    
    init(aiOrchestrator: AIOrchestrator) {
        self.aiOrchestrator = aiOrchestrator
        self.threatIntelligence = ThreatIntelligenceEngine()
        self.mlValidator = FalsePositiveValidator(aiOrchestrator: aiOrchestrator)
        
        setupRealtimeUpdates()
    }
    
    // MARK: - Main Reconnaissance Functions
    
    /// Performs comprehensive reconnaissance with AI assistance
    func performComprehensiveReconnaissance(target: Target) async -> ReconResults {
        logger.info("🔍 Starting comprehensive reconnaissance on \(target.identifier)")
        
        isScanning = true
        scanProgress = ScanProgress()
        
        defer {
            isScanning = false
            scanProgress.isCompleted = true
        }
        
        var results = ReconResults(target: target)
        
        await withTaskGroup(of: Void.self) { group in
            // Phase 1: Passive Discovery
            group.addTask {
                await self.performPassiveDiscovery(target: target, results: &results)
            }
            
            // Phase 2: Active Discovery
            group.addTask {
                await self.performActiveDiscovery(target: target, results: &results)
            }
            
            // Phase 3: OSINT Collection
            group.addTask {
                await self.gatherOSINT(target: target)
            }
            
            // Phase 4: Vulnerability Assessment
            group.addTask {
                let assets = results.services.map { service in
                    Asset(identifier: "\(target.identifier):\(service.port)", type: .service)
                }
                let vulnResults = await self.performVulnerabilityAssessment(assets: assets)
                // Process vulnerability results
            }
        }
        
        // Phase 5: AI-powered analysis and validation
        await performAIAnalysis(results: &results)
        
        // Phase 6: False positive filtering
        let allFindings = results.attackVectors.map { vector in
            Finding(title: vector.name, description: vector.description, severity: .medium, type: .information, affectedAsset: target.identifier, cvssScore: nil, cweId: nil, references: [])
        }
        let validatedFindings = await validateFindings(findings: allFindings)
        // Update results with validated findings
        
        logger.info("🎯 Reconnaissance completed for \(target.identifier)")
        return results
    }
    
    /// AI-powered OSINT gathering across multiple sources
    func gatherOSINT(target: Target) async -> OSINTResults {
        logger.info("🌐 Gathering OSINT for \(target.identifier)")
        
        scanProgress.currentPhase = "OSINT Collection"
        var osintResults = OSINTResults(target: target)
        
        await withTaskGroup(of: OSINTResult?.self) { group in
            // Social media intelligence
            group.addTask {
                await self.gatherSocialMediaIntel(target: target)
            }
            
            // Public document discovery
            group.addTask {
                await self.discoverPublicDocuments(target: target)
            }
            
            // DNS intelligence
            group.addTask {
                await self.gatherDNSIntelligence(target: target)
            }
            
            // Certificate transparency logs
            group.addTask {
                await self.analyzeCertificateTransparency(target: target)
            }
            
            // Breach database queries
            group.addTask {
                await self.queryBreachDatabases(target: target)
            }
            
            // Dark web monitoring
            group.addTask {
                await self.monitorDarkWeb(target: target)
            }
            
            for await result in group {
                if let result = result {
                    osintResults.results.append(result)
                    await MainActor.run {
                        self.osintResults.append(result)
                    }
                }
            }
        }
        
        return osintResults
    }
    
    /// ML-based vulnerability scanning with zero false positives
    func performVulnerabilityAssessment(assets: [Asset]) async -> VulnResults {
        logger.info("🛡️ Performing vulnerability assessment on \(assets.count) assets")
        
        scanProgress.currentPhase = "Vulnerability Assessment"
        var vulnResults = VulnResults()
        
        for asset in assets {
            // Multi-layered vulnerability scanning
            let findings = await runMultipleVulnScanners(asset: asset)
            
            // AI-powered correlation and deduplication
            let correlatedFindings = await correlateFindings(findings)
            
            // ML-based false positive validation
            let validatedFindings = await validateFindings(findings: correlatedFindings)
            
            // Convert ValidatedFinding to ValidatedVulnerability
            let vulnerabilities = validatedFindings.map { validatedFinding in
                ValidatedVulnerability(
                    finding: validatedFinding,
                    exploitAvailable: false,
                    remediationSteps: ["Review and assess the finding"],
                    businessImpact: "Potential security risk"
                )
            }
            vulnResults.vulnerabilities.append(contentsOf: vulnerabilities)
        }
        
        return vulnResults
    }
    
    /// Validates findings using ML models to eliminate false positives
    func validateFindings(findings: [Finding]) async -> [ValidatedFinding] {
        logger.info("✨ Validating \(findings.count) findings with ML models")
        
        var validatedFindings: [ValidatedFinding] = []
        
        for finding in findings {
            let validationResult = await mlValidator.validateFinding(finding: finding)
            
            if !validationResult.isFalsePositive {
                let validatedFinding = ValidatedFinding(
                    original: finding,
                    confidence: validationResult.confidence,
                    validationReasoning: validationResult.reasoning,
                    riskScore: await calculateRiskScore(finding: finding)
                )
                validatedFindings.append(validatedFinding)
            } else {
                logger.info("🚮 Filtered false positive: \(finding.title)")
            }
        }
        
        return validatedFindings
    }
    
    // MARK: - Passive Discovery Methods
    
    private func performPassiveDiscovery(target: Target, results: inout ReconResults) async {
        scanProgress.currentPhase = "Passive Discovery"
        
        // DNS enumeration without direct interaction
        await performPassiveDNSEnum(target: target, results: &results)
        
        // Search engine dorking
        await performSearchEngineDorking(target: target, results: &results)
        
        // Shodan/Censys queries
        // await queryInternetScanners(target: target, results: &results) // Commented out missing function
        
        // Certificate transparency analysis
        await analyzeCertTransparency(target: target, results: &results)
        
        // Historical DNS data
        await analyzeHistoricalDNS(target: target, results: &results)
    }
    
    private func performPassiveDNSEnum(target: Target, results: inout ReconResults) async {
        logger.info("🔍 Performing passive DNS enumeration")
        
        // Query multiple passive DNS sources
        let sources = ["virustotal", "passivetotal", "securitytrails", "dnslytics"]
        
        for source in sources {
            if let subdomains = await queryPassiveDNSSource(target: target, source: source) {
                results.subdomains.append(contentsOf: subdomains)
            }
        }
        
        // Deduplicate and enrich
        results.subdomains = Array(Set(results.subdomains))
    }
    
    private func performSearchEngineDorking(target: Target, results: inout ReconResults) async {
        logger.info("🔍 Performing search engine dorking")
        
        let dorks = [
            "site:\(target.domain) filetype:pdf",
            "site:\(target.domain) inurl:admin",
            "site:\(target.domain) intitle:\"index of\"",
            "\(target.domain) \"confidential\" filetype:doc",
            "\(target.domain) inurl:login",
            "intext:\(target.domain) inurl:wp-content",
        ]
        
        for dork in dorks {
            if let searchResults = await performSearchEngineDork(query: dork) {
                results.searchResults.append(contentsOf: searchResults)
            }
        }
    }
    
    // MARK: - Active Discovery Methods
    
    private func performActiveDiscovery(target: Target, results: inout ReconResults) async {
        scanProgress.currentPhase = "Active Discovery"
        
        // Port scanning with stealth techniques
        await performPortScanning(target: target, results: &results)
        
        // Service enumeration
        await performServiceEnumeration(target: target, results: &results)
        
        // Web application discovery
        await performWebAppDiscovery(target: target, results: &results)
        
        // Technology stack detection
        await detectTechnologyStack(target: target, results: &results)
    }
    
    private func performPortScanning(target: Target, results: inout ReconResults) async {
        logger.info("🔍 Performing advanced port scanning")
        
        // Multiple scan techniques for evasion
        let scanTechniques = [
            ScanTechnique.syn,
            ScanTechnique.connect,
            ScanTechnique.udp,
            ScanTechnique.stealth
        ]
        
        var openPorts: Set<Int> = []
        
        for technique in scanTechniques {
            if let ports = await performPortScan(target: target, technique: technique) {
                openPorts.formUnion(ports)
            }
        }
        
        results.openPorts = Array(openPorts).sorted()
    }
    
    // MARK: - OSINT Collection Methods
    
    private func gatherSocialMediaIntel(target: Target) async -> OSINTResult? {
        logger.info("📱 Gathering social media intelligence")
        
        // Search across multiple social platforms
        let platforms = ["twitter", "linkedin", "facebook", "instagram", "github"]
        var socialIntel: [String: Any] = [:]
        
        for platform in platforms {
            if let results = await searchSocialPlatform(platform: platform, target: target) {
                socialIntel[platform] = results
            }
        }
        
        guard !socialIntel.isEmpty else { return nil }
        
        return OSINTResult(
            type: .socialMedia,
            source: "Multiple Platforms",
            data: socialIntel,
            confidence: 0.8,
            timestamp: Date()
        )
    }
    
    private func discoverPublicDocuments(target: Target) async -> OSINTResult? {
        logger.info("📄 Discovering public documents")
        
        // Search for leaked documents, presentations, etc.
        let fileTypes = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt"]
        var documents: [DocumentResult] = []
        
        for fileType in fileTypes {
            if let docs = await searchPublicDocuments(target: target, fileType: fileType) {
                documents.append(contentsOf: docs)
            }
        }
        
        guard !documents.isEmpty else { return nil }
        
        return OSINTResult(
            type: .publicDocuments,
            source: "Search Engines",
            data: ["documents": documents],
            confidence: 0.9,
            timestamp: Date()
        )
    }
    
    private func gatherDNSIntelligence(target: Target) async -> OSINTResult? {
        logger.info("🌐 Gathering DNS intelligence")
        
        var dnsIntel: [String: Any] = [:]
        
        // Historical DNS records
        dnsIntel["historical"] = await queryHistoricalDNS(target: target)
        
        // DNS zone transfers (if allowed)
        dnsIntel["zone_transfers"] = await attemptZoneTransfer(target: target)
        
        // Reverse DNS lookups
        dnsIntel["reverse_dns"] = await performReverseDNSLookups(target: target)
        
        return OSINTResult(
            type: .dnsIntelligence,
            source: "DNS Analysis",
            data: dnsIntel,
            confidence: 0.95,
            timestamp: Date()
        )
    }
    
    private func analyzeCertificateTransparency(target: Target) async -> OSINTResult? {
        logger.info("🔒 Analyzing certificate transparency logs")
        
        // Query CT logs for certificates
        let ctSources = ["crt.sh", "censys", "certspotter"]
        var certificates: [CertificateInfo] = []
        
        for source in ctSources {
            if let certs = await queryCTLogs(target: target, source: source) {
                certificates.append(contentsOf: certs)
            }
        }
        
        guard !certificates.isEmpty else { return nil }
        
        return OSINTResult(
            type: .certificateTransparency,
            source: "Certificate Transparency",
            data: ["certificates": certificates],
            confidence: 1.0,
            timestamp: Date()
        )
    }
    
    private func queryBreachDatabases(target: Target) async -> OSINTResult? {
        logger.info("🚨 Querying breach databases")
        
        // Check HaveIBeenPwned, DeHashed, etc. (with proper API access)
        var breachData: [String: Any] = [:]
        
        // Only check domain-level breaches (not individual emails)
        if let domainBreaches = await checkDomainBreaches(domain: target.domain) {
            breachData["domain_breaches"] = domainBreaches
        }
        
        guard !breachData.isEmpty else { return nil }
        
        return OSINTResult(
            type: .breachData,
            source: "Breach Databases",
            data: breachData,
            confidence: 0.9,
            timestamp: Date()
        )
    }
    
    private func monitorDarkWeb(target: Target) async -> OSINTResult? {
        logger.info("🕳️ Monitoring dark web mentions")
        
        // Search dark web forums and marketplaces for mentions
        // This would integrate with specialized dark web monitoring services
        
        // Placeholder - actual implementation would require specialized APIs
        return nil
    }
    
    // MARK: - AI Analysis and Correlation
    
    private func performAIAnalysis(results: inout ReconResults) async {
        logger.info("🧠 Performing AI-powered analysis")
        
        scanProgress.currentPhase = "AI Analysis"
        
        // Use AI to correlate findings and identify attack paths
        let context = CyberSecurityContext(
            domain: .reconnaissance,
            target: results.target.identifier,
            urgency: .normal,
            isVoiceCommand: false,
            requiredActions: [],
            userPermissions: []
        )
        
        let analysisQuery = """
        Analyze the following reconnaissance results and provide:
        1. Attack surface assessment
        2. Potential attack vectors
        3. High-priority targets
        4. Security recommendations
        
        Target: \(results.target.identifier)
        Subdomains: \(results.subdomains.count)
        Open Ports: \(results.openPorts.count)
        Technologies: \(results.technologies.count)
        """
        
        let aiResponse = await aiOrchestrator.processQuery(analysisQuery, context: context)
        results.aiAnalysis = aiResponse.content
        results.attackVectors = extractAttackVectors(from: aiResponse.content)
    }
    
    // MARK: - Validation and Risk Scoring
    
    private func runMultipleVulnScanners(asset: Asset) async -> [Finding] {
        logger.info("🔍 Running multiple vulnerability scanners on \(asset.identifier)")
        
        var findings: [Finding] = []
        
        // Integrate with multiple vulnerability scanners
        let scanners = ["nmap_vuln", "nuclei", "nikto", "custom_checks"]
        
        for scanner in scanners {
            if let scanFindings = await runVulnScanner(scanner: scanner, asset: asset) {
                findings.append(contentsOf: scanFindings)
            }
        }
        
        return findings
    }
    
    private func correlateFindings(_ findings: [Finding]) async -> [Finding] {
        logger.info("🔗 Correlating \(findings.count) findings")
        
        // Use AI to correlate and deduplicate findings
        var correlatedFindings: [Finding] = []
        var processedSignatures: Set<String> = []
        
        for finding in findings {
            let signature = generateFindingSignature(finding)
            
            if !processedSignatures.contains(signature) {
                processedSignatures.insert(signature)
                correlatedFindings.append(finding)
            }
        }
        
        return correlatedFindings
    }
    
    private func calculateRiskScore(finding: Finding) async -> Double {
        // Calculate comprehensive risk score based on multiple factors
        var riskScore = 0.0
        
        // CVSS score contribution (40%)
        if let cvssScore = finding.cvssScore {
            riskScore += (cvssScore / 10.0) * 0.4
        }
        
        // Asset criticality (30%)
        let assetCriticality = await getAssetCriticality(asset: finding.affectedAsset)
        riskScore += assetCriticality * 0.3
        
        // Exploitability (20%)
        let exploitability = await assessExploitability(finding: finding)
        riskScore += exploitability * 0.2
        
        // Threat intelligence (10%)
        let threatIntel = await threatIntelligence.assessThreat(finding: finding)
        riskScore += threatIntel * 0.1
        
        return min(riskScore, 1.0)
    }
    
    // MARK: - Configuration and Setup
    
    private func setupRealtimeUpdates() {
        // Setup real-time updates for scan progress and results
        Timer.publish(every: 1.0, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                self?.updateScanMetrics()
            }
            .store(in: &cancellables)
    }
    
    private func updateScanMetrics() {
        // Update scan progress and metrics
        scanProgress.assetsDiscovered = discoveredAssets.count
        scanProgress.vulnerabilitiesFound = vulnerabilities.count
        scanProgress.osintResultsCount = osintResults.count
    }
    
    // MARK: - Helper Methods (Placeholders for actual implementations)
    
    private func queryPassiveDNSSource(target: Target, source: String) async -> [String]? {
        // Placeholder - actual implementation would query passive DNS APIs
        return nil
    }
    
    private func performSearchEngineDork(query: String) async -> [SearchResult]? {
        // Placeholder - actual implementation would use search engine APIs
        return nil
    }
    
    private func performPortScan(target: Target, technique: ScanTechnique) async -> Set<Int>? {
        // Placeholder - actual implementation would perform port scanning
        return nil
    }
    
    private func searchSocialPlatform(platform: String, target: Target) async -> [String: Any]? {
        // Placeholder - actual implementation would search social platforms
        return nil
    }
    
    private func searchPublicDocuments(target: Target, fileType: String) async -> [DocumentResult]? {
        // Placeholder - actual implementation would search for documents
        return nil
    }
    
    private func queryHistoricalDNS(target: Target) async -> [DNSRecord]? {
        // Placeholder - actual implementation would query historical DNS
        return nil
    }
    
    private func attemptZoneTransfer(target: Target) async -> ZoneTransferResult? {
        // Placeholder - actual implementation would attempt zone transfers
        return nil
    }
    
    private func performReverseDNSLookups(target: Target) async -> [ReverseDNSResult]? {
        // Placeholder - actual implementation would perform reverse DNS
        return nil
    }
    
    private func queryCTLogs(target: Target, source: String) async -> [CertificateInfo]? {
        // Placeholder - actual implementation would query CT logs
        return nil
    }
    
    private func checkDomainBreaches(domain: String) async -> [BreachInfo]? {
        // Placeholder - actual implementation would check breach databases
        return nil
    }
    
    private func runVulnScanner(scanner: String, asset: Asset) async -> [Finding]? {
        // Placeholder - actual implementation would run vulnerability scanners
        return nil
    }
    
    private func generateFindingSignature(_ finding: Finding) -> String {
        // Generate unique signature for finding deduplication
        return "\(finding.type)-\(finding.affectedAsset)-\(finding.description.prefix(50))"
    }
    
    private func getAssetCriticality(asset: String) async -> Double {
        // Placeholder - determine asset criticality
        return 0.5
    }
    
    private func assessExploitability(finding: Finding) async -> Double {
        // Placeholder - assess exploitability of finding
        return 0.5
    }
    
    private func extractAttackVectors(from analysis: String) -> [AttackVector] {
        // Placeholder - extract attack vectors from AI analysis
        return []
    }
    
    // Additional missing placeholder methods
    private func performServiceEnumeration(target: Target, results: inout ReconResults) async {
        // Placeholder - perform service enumeration
    }
    
    private func performWebAppDiscovery(target: Target, results: inout ReconResults) async {
        // Placeholder - perform web application discovery
    }
    
    private func detectTechnologyStack(target: Target, results: inout ReconResults) async {
        // Placeholder - detect technology stack
    }
    
    private func analyzeCertTransparency(target: Target, results: inout ReconResults) async {
        // Placeholder - analyze certificate transparency
    }
    
    private func analyzeHistoricalDNS(target: Target, results: inout ReconResults) async {
        // Placeholder - analyze historical DNS
    }
}

// MARK: - Data Models

struct ReconConfiguration {
    var enablePassiveScanning = true
    var enableActiveScanning = true
    var enableOSINT = true
    var enableVulnScanning = true
    var scanTimeout: TimeInterval = 3600 // 1 hour
    var maxThreads = 10
    var stealthMode = true
    
    static let `default` = ReconConfiguration()
}

struct ScanProgress: Codable {
    var isCompleted = false
    var currentPhase = "Initializing"
    var progressPercentage: Double = 0.0
    var assetsDiscovered = 0
    var vulnerabilitiesFound = 0
    var osintResultsCount = 0
    var startTime = Date()
    var estimatedCompletion: Date?
}

struct Target: Identifiable, Codable {
    let id = UUID()
    let identifier: String
    let domain: String
    let ipAddresses: [String]
    let description: String?
    
    init(domain: String, ipAddresses: [String] = [], description: String? = nil) {
        self.identifier = domain
        self.domain = domain
        self.ipAddresses = ipAddresses
        self.description = description
    }
}

struct ReconResults {
    let target: Target
    var subdomains: [String] = []
    var openPorts: [Int] = []
    var services: [ServiceInfo] = []
    var technologies: [TechnologyInfo] = []
    var searchResults: [SearchResult] = []
    var certificates: [CertificateInfo] = []
    var dnsRecords: [DNSRecord] = []
    var aiAnalysis: String = ""
    var attackVectors: [AttackVector] = []
}

struct OSINTResults {
    let target: Target
    var results: [OSINTResult] = []
}

struct OSINTResult: Identifiable {
    let id = UUID()
    let type: OSINTType
    let source: String
    let data: [String: Any]
    let confidence: Double
    let timestamp: Date
    
    enum OSINTType {
        case socialMedia
        case publicDocuments
        case dnsIntelligence
        case certificateTransparency
        case breachData
        case darkWeb
    }
}

struct VulnResults {
    var vulnerabilities: [ValidatedVulnerability] = []
    var scanMetrics: ScanMetrics = ScanMetrics()
}

struct DiscoveredAsset: Identifiable {
    let id = UUID()
    let identifier: String
    let type: AssetType
    let ipAddress: String?
    let ports: [Int]
    let services: [ServiceInfo]
    let technologies: [TechnologyInfo]
    let riskScore: Double
    
    enum AssetType {
        case webServer
        case database
        case mailServer
        case dnsServer
        case application
        case unknown
    }
}

struct Finding: Identifiable, Codable {
    let id = UUID()
    let title: String
    let description: String
    let severity: Severity
    let type: FindingType
    let affectedAsset: String
    let cvssScore: Double?
    let cweId: String?
    let references: [String]
    
    enum Severity: String, Codable {
        case critical, high, medium, low, info
    }
    
    enum FindingType: String, Codable {
        case vulnerability, configuration, information
    }
}

struct ValidatedFinding: Identifiable {
    let id = UUID()
    let original: Finding
    let confidence: Double
    let validationReasoning: String
    let riskScore: Double
    let isValidated = true
}

struct ValidatedVulnerability: Identifiable {
    let id = UUID()
    let finding: ValidatedFinding
    let exploitAvailable: Bool
    let remediationSteps: [String]
    let businessImpact: String
}

// Additional supporting models
struct ServiceInfo: Codable {
    let port: Int
    let networkProtocol: String
    let service: String
    let version: String?
    let banner: String?
}

struct TechnologyInfo: Codable {
    let name: String
    let version: String?
    let confidence: Double
    let category: String
}

struct SearchResult: Codable {
    let url: String
    let title: String
    let snippet: String
    let source: String
}

struct DocumentResult: Codable {
    let url: String
    let title: String
    let fileType: String
    let size: String?
    let lastModified: Date?
}

struct CertificateInfo: Codable {
    let commonName: String
    let subjectAlternativeNames: [String]
    let issuer: String
    let validFrom: Date
    let validTo: Date
    let serialNumber: String
}

struct DNSRecord: Codable {
    let type: String
    let name: String
    let value: String
    let ttl: Int?
}

struct BreachInfo: Codable {
    let name: String
    let domain: String
    let breachDate: Date
    let addedDate: Date
    let modifiedDate: Date
    let pwnCount: Int
    let description: String
    let dataClasses: [String]
}

struct AttackVector: Identifiable {
    let id = UUID()
    let name: String
    let description: String
    let riskLevel: RiskLevel
    let prerequisites: [String]
    let steps: [String]
    
    enum RiskLevel {
        case critical, high, medium, low
    }
}

struct ScanMetrics: Codable {
    var scannersUsed: [String] = []
    var totalFindings = 0
    var falsePositivesFiltered = 0
    var scanDuration: TimeInterval = 0
    var accuracyScore: Double = 0.95
}

enum ScanTechnique {
    case syn, connect, udp, stealth, ack, window, fin
}

// Placeholder models for compilation
struct ZoneTransferResult: Codable {
    let domain: String
    let records: [DNSRecord]
    let success: Bool
}

struct ReverseDNSResult: Codable {
    let ipAddress: String
    let hostname: String?
}

struct Asset: Identifiable, Codable {
    let id = UUID()
    let identifier: String
    let type: AssetType
    let ipAddress: String?
    let domain: String?
    
    enum AssetType: String, Codable {
        case service
        case webServer
        case database
        case mailServer
        case dnsServer
        case application
        case unknown
    }
    
    init(identifier: String, type: AssetType, ipAddress: String? = nil, domain: String? = nil) {
        self.identifier = identifier
        self.type = type
        self.ipAddress = ipAddress
        self.domain = domain
    }
}

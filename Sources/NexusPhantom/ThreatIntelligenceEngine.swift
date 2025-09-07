import Foundation
import Combine
import os.log
import SwiftUI

/// Threat Intelligence Engine for correlating findings with threat intelligence
@MainActor
class ThreatIntelligenceEngine: ObservableObject {
    
    // MARK: - Published Properties
    @Published var isUpdating = false
    @Published var threatFeeds: [ThreatFeed] = []
    @Published var iocDatabase: IOCDatabase = IOCDatabase()
    @Published var aptGroups: [APTGroup] = []
    @Published var vulnerabilityDatabase: VulnerabilityDatabase = VulnerabilityDatabase()
    @Published var lastUpdate: Date?
    
    // MARK: - Dependencies
    private let logger = Logger(subsystem: "NexusPhantom", category: "ThreatIntelligenceEngine")
    private var cancellables = Set<AnyCancellable>()
    
    // MARK: - Configuration
    private let updateInterval: TimeInterval = 3600 // 1 hour
    private let threatFeadSources = [
        "MISP", "AlienVault OTX", "VirusTotal", "Shodan", "Censys",
        "Hybrid Analysis", "URLVoid", "AbuseIPDB", "MalwareBazaar"
    ]
    
    init() {
        setupPeriodicUpdates()
        Task {
            await initializeThreatIntelligence()
        }
    }
    
    // MARK: - Main Functions
    
    /// Initialize threat intelligence databases and feeds
    func initializeThreatIntelligence() async {
        logger.info("🧠 Initializing threat intelligence engine")
        
        isUpdating = true
        defer { isUpdating = false }
        
        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                await self.loadIOCDatabase()
            }
            
            group.addTask {
                await self.loadAPTDatabase()
            }
            
            group.addTask {
                await self.loadVulnerabilityDatabase()
            }
            
            group.addTask {
                await self.updateThreatFeeds()
            }
        }
        
        lastUpdate = Date()
        logger.info("✅ Threat intelligence engine initialized")
    }
    
    
    /// Get contextual threat information for a finding
    func getThreatContext(finding: Finding) async -> ThreatContext {
        logger.debug("📊 Getting threat context for finding")
        
        let iocMatches = await findIOCMatches(finding: finding)
        let aptMatches = await findAPTMatches(finding: finding)
        let vulnContext = await getVulnerabilityContext(finding: finding)
        let campaignContext = await getCampaignContext(finding: finding)
        
        return ThreatContext(
            iocMatches: iocMatches,
            aptGroups: aptMatches,
            vulnerabilityContext: vulnContext,
            campaigns: campaignContext,
            riskScore: await assessThreat(finding: finding),
            lastUpdated: Date()
        )
    }
    
    /// Update threat intelligence feeds
    func updateThreatFeeds() async {
        logger.info("🔄 Updating threat intelligence feeds")
        
        isUpdating = true
        defer { isUpdating = false }
        
        await withTaskGroup(of: ThreatFeed?.self) { group in
            for source in threatFeadSources {
                group.addTask {
                    await self.updateThreatFeed(source: source)
                }
            }
            
            for await feed in group {
                if let feed = feed {
                    if let index = threatFeeds.firstIndex(where: { $0.source == feed.source }) {
                        threatFeeds[index] = feed
                    } else {
                        threatFeeds.append(feed)
                    }
                }
            }
        }
        
        lastUpdate = Date()
        logger.info("✅ Threat intelligence feeds updated")
    }
    
    // MARK: - IOC Analysis
    
    private func checkIOCMatch(finding: Finding) async -> Double {
        var score = 0.0
        
        // Extract potential IOCs from finding
        let potentialIOCs = extractIOCs(from: finding)
        
        for ioc in potentialIOCs {
            if await iocDatabase.contains(ioc) {
                let iocInfo = await iocDatabase.getInfo(for: ioc)
                score += iocInfo.severity * 0.3
            }
        }
        
        return min(score, 0.3) // Max 30% contribution
    }
    
    private func findIOCMatches(finding: Finding) async -> [IOCMatch] {
        let potentialIOCs = extractIOCs(from: finding)
        var matches: [IOCMatch] = []
        
        for ioc in potentialIOCs {
            if await iocDatabase.contains(ioc) {
                let iocInfo = await iocDatabase.getInfo(for: ioc)
                let match = IOCMatch(
                    ioc: ioc,
                    type: iocInfo.type,
                    severity: iocInfo.severity,
                    firstSeen: iocInfo.firstSeen,
                    lastSeen: iocInfo.lastSeen,
                    sources: iocInfo.sources,
                    campaigns: iocInfo.campaigns
                )
                matches.append(match)
            }
        }
        
        return matches
    }
    
    private func extractIOCs(from finding: Finding) -> [String] {
        var iocs: [String] = []
        let text = "\(finding.title) \(finding.description) \(finding.affectedAsset)"
        
        // Extract IP addresses
        let ipPattern = #"\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"#
        iocs.append(contentsOf: extractMatches(from: text, pattern: ipPattern))
        
        // Extract domains
        let domainPattern = #"\\b[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.[a-zA-Z]{2,}\\b"#
        iocs.append(contentsOf: extractMatches(from: text, pattern: domainPattern))
        
        // Extract URLs
        let urlPattern = #"https?://[^\\s]+"#
        iocs.append(contentsOf: extractMatches(from: text, pattern: urlPattern))
        
        // Extract file hashes (MD5, SHA1, SHA256)
        let hashPattern = #"\\b[a-fA-F0-9]{32}\\b|\\b[a-fA-F0-9]{40}\\b|\\b[a-fA-F0-9]{64}\\b"#
        iocs.append(contentsOf: extractMatches(from: text, pattern: hashPattern))
        
        return iocs
    }
    
    private func extractMatches(from text: String, pattern: String) -> [String] {
        do {
            let regex = try NSRegularExpression(pattern: pattern, options: [])
            let range = NSRange(text.startIndex..., in: text)
            let matches = regex.matches(in: text, options: [], range: range)
            
            return matches.compactMap { match in
                Range(match.range, in: text).map { String(text[$0]) }
            }
        } catch {
            logger.error("Regex error: \(error)")
            return []
        }
    }
    
    // MARK: - APT Analysis
    
    private func checkAPTTTPs(finding: Finding) async -> Double {
        var score = 0.0
        
        for aptGroup in aptGroups {
            let ttpMatch = calculateTTPMatch(finding: finding, aptGroup: aptGroup)
            if ttpMatch > 0.5 {
                score += ttpMatch * 0.25
            }
        }
        
        return min(score, 0.25) // Max 25% contribution
    }
    
    private func findAPTMatches(finding: Finding) async -> [APTMatch] {
        var matches: [APTMatch] = []
        
        for aptGroup in aptGroups {
            let ttpMatch = calculateTTPMatch(finding: finding, aptGroup: aptGroup)
            if ttpMatch > 0.3 {
                let match = APTMatch(
                    group: aptGroup,
                    confidence: ttpMatch,
                    matchingTTPs: getMatchingTTPs(finding: finding, aptGroup: aptGroup),
                    attribution: aptGroup.attribution
                )
                matches.append(match)
            }
        }
        
        return matches.sorted { $0.confidence > $1.confidence }
    }
    
    private func calculateTTPMatch(finding: Finding, aptGroup: APTGroup) -> Double {
        let findingTTPs = extractTTPs(from: finding)
        let commonTTPs = Set(findingTTPs).intersection(Set(aptGroup.ttps))
        
        guard !aptGroup.ttps.isEmpty else { return 0.0 }
        
        return Double(commonTTPs.count) / Double(aptGroup.ttps.count)
    }
    
    private func extractTTPs(from finding: Finding) -> [String] {
        let text = "\(finding.title) \(finding.description)".lowercased()
        var ttps: [String] = []
        
        // Common TTPs patterns
        let ttpKeywords = [
            "lateral movement", "privilege escalation", "persistence", "defense evasion",
            "credential access", "discovery", "collection", "command and control",
            "exfiltration", "impact", "initial access", "execution"
        ]
        
        for keyword in ttpKeywords {
            if text.contains(keyword) {
                ttps.append(keyword)
            }
        }
        
        return ttps
    }
    
    private func getMatchingTTPs(finding: Finding, aptGroup: APTGroup) -> [String] {
        let findingTTPs = extractTTPs(from: finding)
        return Array(Set(findingTTPs).intersection(Set(aptGroup.ttps)))
    }
    
    // MARK: - Vulnerability Analysis
    
    private func checkVulnExploitation(finding: Finding) async -> Double {
        guard let cveId = finding.cweId else { return 0.0 }
        
        if let vulnInfo = await vulnerabilityDatabase.getVulnerability(cveId: cveId) {
            var score = 0.0
            
            // Check if actively exploited
            if vulnInfo.activelyExploited {
                score += 0.3
            }
            
            // Check if exploit is available
            if vulnInfo.exploitAvailable {
                score += 0.2
            }
            
            // Check CVSS score contribution
            if let cvss = vulnInfo.cvssScore {
                score += (cvss / 10.0) * 0.1
            }
            
            return min(score, 0.4) // Max 40% contribution
        }
        
        return 0.0
    }
    
    private func getVulnerabilityContext(finding: Finding) async -> VulnerabilityContext? {
        guard let cveId = finding.cweId else { return nil }
        
        if let vulnInfo = await vulnerabilityDatabase.getVulnerability(cveId: cveId) {
            return VulnerabilityContext(
                cveId: cveId,
                cvssScore: vulnInfo.cvssScore,
                exploitAvailable: vulnInfo.exploitAvailable,
                activelyExploited: vulnInfo.activelyExploited,
                mitigationAvailable: vulnInfo.mitigationAvailable,
                affectedProducts: vulnInfo.affectedProducts,
                threatActors: vulnInfo.associatedThreatActors
            )
        }
        
        return nil
    }
    
    // MARK: - Campaign Analysis
    
    private func checkThreatAttribution(finding: Finding) async -> Double {
        // Check for campaign attribution based on TTPs and IOCs
        var score = 0.0
        
        let campaigns = await findRelatedCampaigns(finding: finding)
        for campaign in campaigns {
            score += campaign.confidence * 0.15
        }
        
        return min(score, 0.15) // Max 15% contribution
    }
    
    private func getCampaignContext(finding: Finding) async -> [CampaignMatch] {
        return await findRelatedCampaigns(finding: finding)
    }
    
    private func findRelatedCampaigns(finding: Finding) async -> [CampaignMatch] {
        // Placeholder for campaign matching logic
        // Would correlate with known threat campaigns
        return []
    }
    
    // MARK: - Data Loading
    
    private func loadIOCDatabase() async {
        logger.info("📊 Loading IOC database")
        
        // Load IOCs from various sources
        await iocDatabase.loadFromSources([
            "malware_domains", "malicious_ips", "c2_servers",
            "phishing_urls", "malware_hashes"
        ])
    }
    
    private func loadAPTDatabase() async {
        logger.info("🎭 Loading APT database")
        
        // Load known APT groups and their TTPs
        aptGroups = [
            APTGroup(
                name: "APT1",
                aliases: ["Comment Crew", "PLA Unit 61398"],
                country: "China",
                firstSeen: Date(),
                ttps: ["spear phishing", "lateral movement", "data exfiltration"],
                targetSectors: ["Government", "Technology", "Financial"],
                attribution: "High"
            ),
            APTGroup(
                name: "APT28",
                aliases: ["Fancy Bear", "Sofacy", "STRONTIUM"],
                country: "Russia",
                firstSeen: Date(),
                ttps: ["spear phishing", "zero-day exploits", "living off the land"],
                targetSectors: ["Government", "Military", "Aerospace"],
                attribution: "High"
            ),
            APTGroup(
                name: "APT29",
                aliases: ["Cozy Bear", "NOBELIUM"],
                country: "Russia",
                firstSeen: Date(),
                ttps: ["supply chain attacks", "cloud exploitation", "steganography"],
                targetSectors: ["Government", "Technology", "Healthcare"],
                attribution: "High"
            )
        ]
    }
    
    private func loadVulnerabilityDatabase() async {
        logger.info("🛡️ Loading vulnerability database")
        
        await vulnerabilityDatabase.loadFromSources([
            "nvd", "exploit_db", "metasploit", "nuclei_templates"
        ])
    }
    
    private func updateThreatFeed(source: String) async -> ThreatFeed? {
        logger.debug("🔄 Updating threat feed: \(source)")
        
        // Simulate threat feed update
        // In practice, this would query actual threat intelligence APIs
        
        return ThreatFeed(
            source: source,
            lastUpdate: Date(),
            recordCount: Int.random(in: 1000...10000),
            quality: Double.random(in: 0.7...0.95),
            types: ["ioc", "ttp", "campaign", "malware"]
        )
    }
    
    // MARK: - Setup
    
    private func setupPeriodicUpdates() {
        Timer.publish(every: updateInterval, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                Task {
                    await self?.updateThreatFeeds()
                }
            }
            .store(in: &cancellables)
    }
    
    /// Assess threat level for a finding
    func assessThreat(finding: Finding) async -> Double {
        logger.info("🎯 Assessing threat level for: \(finding.title)")
        
        var threatScore = 0.0
        
        // Check severity level
        switch finding.severity {
        case .critical:
            threatScore += 0.9
        case .high:
            threatScore += 0.7
        case .medium:
            threatScore += 0.5
        case .low:
            threatScore += 0.3
        case .info:
            threatScore += 0.1
        }
        
        // CVSS score consideration
        if let cvssScore = finding.cvssScore {
            threatScore += (cvssScore / 10.0) * 0.3
        }
        
        return min(threatScore, 1.0)
    }
}

// MARK: - Supporting Classes

class IOCDatabase {
    private var iocs: [String: IOCInfo] = [:]
    
    func contains(_ ioc: String) async -> Bool {
        return iocs[ioc] != nil
    }
    
    func getInfo(for ioc: String) async -> IOCInfo {
        return iocs[ioc] ?? IOCInfo(
            type: .unknown,
            severity: 0.5,
            firstSeen: Date(),
            lastSeen: Date(),
            sources: [],
            campaigns: []
        )
    }
    
    func loadFromSources(_ sources: [String]) async {
        // Load IOCs from various sources
        for source in sources {
            await loadFromSource(source)
        }
    }
    
    private func loadFromSource(_ source: String) async {
        // Simulate loading IOCs from source
        let sampleIOCs = generateSampleIOCs(for: source)
        for (ioc, info) in sampleIOCs {
            iocs[ioc] = info
        }
    }
    
    private func generateSampleIOCs(for source: String) -> [String: IOCInfo] {
        // Generate sample IOCs for demonstration
        var sampleIOCs: [String: IOCInfo] = [:]
        
        switch source {
        case "malware_domains":
            sampleIOCs["malicious.example.com"] = IOCInfo(
                type: .domain,
                severity: 0.8,
                firstSeen: Date().addingTimeInterval(-86400),
                lastSeen: Date(),
                sources: [source],
                campaigns: ["Campaign X"]
            )
        case "malicious_ips":
            sampleIOCs["192.168.1.100"] = IOCInfo(
                type: .ip,
                severity: 0.9,
                firstSeen: Date().addingTimeInterval(-172800),
                lastSeen: Date(),
                sources: [source],
                campaigns: ["Campaign Y"]
            )
        default:
            break
        }
        
        return sampleIOCs
    }
}

class VulnerabilityDatabase {
    private var vulnerabilities: [String: VulnerabilityInfo] = [:]
    
    func getVulnerability(cveId: String) async -> VulnerabilityInfo? {
        return vulnerabilities[cveId]
    }
    
    func loadFromSources(_ sources: [String]) async {
        for source in sources {
            await loadFromSource(source)
        }
    }
    
    private func loadFromSource(_ source: String) async {
        // Simulate loading vulnerabilities from source
        let sampleVulns = generateSampleVulns(for: source)
        for (cve, info) in sampleVulns {
            vulnerabilities[cve] = info
        }
    }
    
    private func generateSampleVulns(for source: String) -> [String: VulnerabilityInfo] {
        return [
            "CVE-2023-1234": VulnerabilityInfo(
                cvssScore: 9.8,
                exploitAvailable: true,
                activelyExploited: true,
                mitigationAvailable: true,
                affectedProducts: ["Apache", "Nginx"],
                associatedThreatActors: ["APT28", "APT29"]
            )
        ]
    }
}

// MARK: - Data Models

struct ThreatFeed: Identifiable {
    let id = UUID()
    let source: String
    let lastUpdate: Date
    let recordCount: Int
    let quality: Double
    let types: [String]
}

struct IOCInfo {
    let type: IOCType
    let severity: Double
    let firstSeen: Date
    let lastSeen: Date
    let sources: [String]
    let campaigns: [String]
}

enum IOCType {
    case ip, domain, url, hash, email, unknown
}

struct IOCMatch {
    let ioc: String
    let type: IOCType
    let severity: Double
    let firstSeen: Date
    let lastSeen: Date
    let sources: [String]
    let campaigns: [String]
}

struct APTGroup {
    let name: String
    let aliases: [String]
    let country: String
    let firstSeen: Date
    let ttps: [String]
    let targetSectors: [String]
    let attribution: String
}

struct APTMatch {
    let group: APTGroup
    let confidence: Double
    let matchingTTPs: [String]
    let attribution: String
}

struct VulnerabilityInfo {
    let cvssScore: Double?
    let exploitAvailable: Bool
    let activelyExploited: Bool
    let mitigationAvailable: Bool
    let affectedProducts: [String]
    let associatedThreatActors: [String]
}

struct VulnerabilityContext {
    let cveId: String
    let cvssScore: Double?
    let exploitAvailable: Bool
    let activelyExploited: Bool
    let mitigationAvailable: Bool
    let affectedProducts: [String]
    let threatActors: [String]
}

struct CampaignMatch {
    let name: String
    let confidence: Double
    let description: String
    let threatActors: [String]
    let timeframe: DateInterval
}

struct ThreatContext {
    let iocMatches: [IOCMatch]
    let aptGroups: [APTMatch]
    let vulnerabilityContext: VulnerabilityContext?
    let campaigns: [CampaignMatch]
    let riskScore: Double
    let lastUpdated: Date
}

// MARK: - Supporting Types

// Asset type is now defined in ReconnaissanceEngine.swift to avoid duplication

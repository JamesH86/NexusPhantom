import SwiftUI

struct ResearchView: View {
    @EnvironmentObject var aiOrchestrator: AIOrchestrator
    @EnvironmentObject var voiceManager: VoiceManager
    
    @State private var researchQuery = ""
    @State private var selectedCategory: ResearchCategory = .threatIntelligence
    @State private var researchResults: [ResearchResult] = []
    @State private var cveDatabase: [CVEEntry] = []
    @State private var threatIntel: [ThreatIntelligence] = []
    @State private var isResearching = false
    
    enum ResearchCategory: String, CaseIterable {
        case threatIntelligence = "Threat Intelligence"
        case vulnerabilityResearch = "Vulnerability Research"
        case malwareAnalysis = "Malware Analysis"
        case osint = "OSINT"
        case exploitDevelopment = "Exploit Development"
        case securityNews = "Security News"
        
        var icon: String {
            switch self {
            case .threatIntelligence: return "brain.head.profile"
            case .vulnerabilityResearch: return "magnifyingglass.circle"
            case .malwareAnalysis: return "ant.circle"
            case .osint: return "globe"
            case .exploitDevelopment: return "hammer"
            case .securityNews: return "newspaper"
            }
        }
    }
    
    var body: some View {
        VStack(spacing: 0) {
            ResearchHeader(
                researchQuery: $researchQuery,
                selectedCategory: $selectedCategory,
                isResearching: $isResearching
            ) {
                Task {
                    await startResearch()
                }
            }
            
            Divider()
            
            HStack(spacing: 0) {
                VStack {
                    ResearchResultsPanel(results: researchResults)
                }
                .frame(width: 500)
                
                Divider()
                
                VStack {
                    CVEDatabasePanel(cveEntries: cveDatabase)
                    ThreatIntelPanel(threatIntel: threatIntel)
                }
                .frame(maxWidth: .infinity)
            }
        }
        .navigationTitle("NEXUS PHANTOM - Security Research")
        .onAppear {
            loadResearchData()
            voiceManager.speak("Security research module activated")
        }
    }
    
    private func startResearch() async {
        guard !researchQuery.isEmpty else { return }
        
        isResearching = true
        voiceManager.speak("Starting security research on \(researchQuery)")
        
        let context = CyberSecurityContext(
            domain: .research,
            target: researchQuery,
            urgency: .normal,
            isVoiceCommand: false,
            requiredActions: [],
            userPermissions: []
        )
        
        let response = await aiOrchestrator.processQuery(
            "Research \(selectedCategory.rawValue.lowercased()) for: \(researchQuery)",
            context: context
        )
        
        let result = ResearchResult(
            query: researchQuery,
            category: selectedCategory,
            findings: response.content,
            confidence: response.confidence,
            sources: ["AI Analysis", "Threat Intelligence Feeds"]
        )
        
        researchResults.append(result)
        
        isResearching = false
        voiceManager.speak("Research completed. Found relevant security intelligence.")
    }
    
    private func loadResearchData() {
        // Load sample CVE data
        cveDatabase = [
            CVEEntry(
                cveId: "CVE-2024-1234",
                description: "Remote code execution vulnerability",
                severity: .critical,
                cvssScore: 9.8,
                affectedProducts: ["Example Software v1.0"]
            ),
            CVEEntry(
                cveId: "CVE-2024-5678",
                description: "SQL injection vulnerability",
                severity: .high,
                cvssScore: 7.5,
                affectedProducts: ["Web Application Framework"]
            )
        ]
        
        // Load threat intelligence
        threatIntel = [
            ThreatIntelligence(
                threatName: "APT29 (Cozy Bear)",
                threatType: .apt,
                description: "Russian state-sponsored threat group",
                ttps: ["Spear phishing", "PowerShell abuse", "WMI exploitation"],
                iocs: ["evil.domain.com", "192.168.1.100"]
            )
        ]
    }
}

struct ResearchHeader: View {
    @Binding var researchQuery: String
    @Binding var selectedCategory: ResearchView.ResearchCategory
    @Binding var isResearching: Bool
    let researchAction: () -> Void
    
    var body: some View {
        HStack {
            VStack(alignment: .leading) {
                Text("Security Research")
                    .font(.headline)
                    .fontWeight(.bold)
                
                HStack {
                    TextField("Enter research topic or CVE...", text: $researchQuery)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 400)
                    
                    Picker("Category", selection: $selectedCategory) {
                        ForEach(ResearchView.ResearchCategory.allCases, id: \.self) { category in
                            Label(category.rawValue, systemImage: category.icon).tag(category)
                        }
                    }
                    .frame(width: 250)
                }
            }
            
            Spacer()
            
            Button(action: researchAction) {
                HStack {
                    if isResearching {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                            .scaleEffect(0.8)
                    }
                    
                    Text(isResearching ? "Researching..." : "Start Research")
                        .fontWeight(.semibold)
                }
                .foregroundColor(.white)
                .padding(.horizontal, 20)
                .padding(.vertical, 10)
                .background(isResearching ? Color.orange : Color.purple, in: RoundedRectangle(cornerRadius: 8))
            }
            .disabled(isResearching || researchQuery.isEmpty)
        }
        .padding()
        .background(.regularMaterial)
    }
}

struct ResearchResultsPanel: View {
    let results: [ResearchResult]
    
    var body: some View {
        VStack(alignment: .leading) {
            Text("Research Results")
                .font(.headline)
                .fontWeight(.bold)
            
            if results.isEmpty {
                Text("No research results available")
                    .foregroundColor(.secondary)
                    .italic()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(results) { result in
                    ResearchResultRow(result: result)
                }
                .listStyle(.plain)
            }
        }
        .padding()
    }
}

struct ResearchResultRow: View {
    let result: ResearchResult
    @State private var isExpanded = false
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                VStack(alignment: .leading) {
                    Text(result.query)
                        .font(.headline)
                        .fontWeight(.semibold)
                    
                    Text(result.category.rawValue)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                VStack(alignment: .trailing) {
                    Text("Confidence: \(result.confidence * 100, specifier: "%.0f")%")
                        .font(.caption)
                        .foregroundColor(.blue)
                    
                    Text(result.timestamp.formatted(.relative(presentation: .named)))
                        .font(.caption)
.foregroundColor(.secondary)
                }
            }
            
            if isExpanded {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Findings:")
                        .font(.subheadline)
                        .fontWeight(.semibold)
                    
                    Text(result.findings)
                        .font(.body)
                        .foregroundColor(.primary)
                    
                    Text("Sources: \(result.sources.joined(separator: ", "))")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .onTapGesture {
            withAnimation {
                isExpanded.toggle()
            }
        }
    }
}

struct CVEDatabasePanel: View {
    let cveEntries: [CVEEntry]
    
    var body: some View {
        VStack(alignment: .leading) {
            Text("CVE Database")
                .font(.headline)
                .fontWeight(.bold)
            
            List(cveEntries) { cve in
                CVERow(cve: cve)
            }
            .listStyle(.plain)
        }
        .padding()
    }
}

struct CVERow: View {
    let cve: CVEEntry
    
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(cve.cveId)
                    .font(.body)
                    .fontWeight(.medium)
                    .foregroundColor(.blue)
                
                Text(cve.description)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(2)
            }
            
            Spacer()
            
            VStack(alignment: .trailing) {
                Text(cve.severity.rawValue)
                    .font(.caption)
                    .fontWeight(.bold)
                    .foregroundColor(cve.severity.color)
                
                Text("CVSS: \(cve.cvssScore, specifier: "%.1f")")
                    .font(.caption)
                    .foregroundColor(.orange)
            }
        }
        .padding(.vertical, 4)
    }
}

struct ThreatIntelPanel: View {
    let threatIntel: [ThreatIntelligence]
    
    var body: some View {
        VStack(alignment: .leading) {
            Text("Threat Intelligence")
                .font(.headline)
                .fontWeight(.bold)
            
            List(threatIntel) { threat in
                ThreatIntelRow(threat: threat)
            }
            .listStyle(.plain)
        }
        .padding()
    }
}

struct ThreatIntelRow: View {
    let threat: ThreatIntelligence
    @State private var isExpanded = false
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(threat.threatName)
                    .font(.body)
                    .fontWeight(.medium)
                
                Spacer()
                
                Text(threat.threatType.rawValue)
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(.red)
            }
            
            if isExpanded {
                VStack(alignment: .leading, spacing: 4) {
                    Text(threat.description)
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    Text("TTPs: \(threat.ttps.joined(separator: ", "))")
                        .font(.caption)
                        .foregroundColor(.orange)
                    
                    Text("IOCs: \(threat.iocs.joined(separator: ", "))")
                        .font(.caption)
                        .foregroundColor(.blue)
                }
            }
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .onTapGesture {
            withAnimation {
                isExpanded.toggle()
            }
        }
    }
}

// MARK: - Data Models

struct ResearchResult: Identifiable {
    let id = UUID()
    let query: String
    let category: ResearchView.ResearchCategory
    let findings: String
    let confidence: Double
    let sources: [String]
    let timestamp = Date()
}

struct CVEEntry: Identifiable {
    let id = UUID()
    let cveId: String
    let description: String
    let severity: CVESeverity
    let cvssScore: Double
    let affectedProducts: [String]
    let publishedDate = Date()
    
    enum CVESeverity: String, CaseIterable {
        case critical = "Critical"
        case high = "High"
        case medium = "Medium"
        case low = "Low"
        
        var color: Color {
            switch self {
            case .critical: return .red
            case .high: return .orange
            case .medium: return .yellow
            case .low: return .blue
            }
        }
    }
}

struct ThreatIntelligence: Identifiable {
    let id = UUID()
    let threatName: String
    let threatType: ThreatType
    let description: String
    let ttps: [String] // Tactics, Techniques, and Procedures
    let iocs: [String] // Indicators of Compromise
    let lastUpdated = Date()
    
    enum ThreatType: String, CaseIterable {
        case apt = "APT"
        case malware = "Malware"
        case ransomware = "Ransomware"
        case botnet = "Botnet"
        case phishing = "Phishing"
        case insider = "Insider Threat"
    }
}


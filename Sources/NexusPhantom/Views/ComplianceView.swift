import SwiftUI

struct ComplianceView: View {
    @EnvironmentObject var toolRunner: ToolRunner
    @EnvironmentObject var aiOrchestrator: AIOrchestrator
    @EnvironmentObject var voiceManager: VoiceManager
    
    @State private var selectedFramework: ComplianceFramework = .nist
    @State private var auditResults: [AuditResult] = []
    @State private var complianceScore = 0.85
    @State private var recommendations: [ComplianceRecommendation] = []
    @State private var isAuditing = false
    
    enum ComplianceFramework: String, CaseIterable {
        case nist = "NIST Cybersecurity Framework"
        case iso27001 = "ISO 27001"
        case soc2 = "SOC 2"
        case pci = "PCI DSS"
        case hipaa = "HIPAA"
        case gdpr = "GDPR"
        
        var icon: String {
            switch self {
            case .nist: return "shield.checkered"
            case .iso27001: return "checkmark.seal"
            case .soc2: return "building.2"
            case .pci: return "creditcard"
            case .hipaa: return "cross"
            case .gdpr: return "globe.europe.africa"
            }
        }
    }
    
    var body: some View {
        VStack(spacing: 0) {
            ComplianceHeader(
                selectedFramework: $selectedFramework,
                complianceScore: complianceScore,
                isAuditing: $isAuditing
            ) {
                Task {
                    await startComplianceAudit()
                }
            }
            
            Divider()
            
            HStack(spacing: 0) {
                VStack {
                    ComplianceScorePanel(score: complianceScore, framework: selectedFramework)
                    AuditResultsPanel(results: auditResults)
                }
                .frame(width: 400)
                
                Divider()
                
                VStack {
                    RecommendationsPanel(recommendations: recommendations)
                    ComplianceActionsPanel()
                }
                .frame(maxWidth: .infinity)
            }
        }
        .navigationTitle("NEXUS PHANTOM - Compliance & Auditing")
        .onAppear {
            loadComplianceData()
            voiceManager.speak("Compliance auditing module activated")
        }
    }
    
    private func startComplianceAudit() async {
        isAuditing = true
        voiceManager.speak("Starting \(selectedFramework.rawValue) compliance audit")
        
        // Simulate audit
        try? await Task.sleep(nanoseconds: 3_000_000_000)
        
        isAuditing = false
        voiceManager.speak("Compliance audit completed with score \(Int(complianceScore * 100)) percent")
    }
    
    private func loadComplianceData() {
        auditResults = [
            AuditResult(control: "Access Control", status: .compliant, framework: selectedFramework),
            AuditResult(control: "Data Encryption", status: .partiallyCompliant, framework: selectedFramework),
            AuditResult(control: "Incident Response", status: .nonCompliant, framework: selectedFramework)
        ]
        
        recommendations = [
            ComplianceRecommendation(title: "Implement MFA", priority: .high, framework: selectedFramework),
            ComplianceRecommendation(title: "Update Encryption Standards", priority: .medium, framework: selectedFramework)
        ]
    }
}

struct ComplianceHeader: View {
    @Binding var selectedFramework: ComplianceView.ComplianceFramework
    let complianceScore: Double
    @Binding var isAuditing: Bool
    let auditAction: () -> Void
    
    var body: some View {
        HStack {
            VStack(alignment: .leading) {
                Text("Compliance Framework")
                    .font(.headline)
                    .fontWeight(.bold)
                
                Picker("Framework", selection: $selectedFramework) {
                    ForEach(ComplianceView.ComplianceFramework.allCases, id: \.self) { framework in
                        Label(framework.rawValue, systemImage: framework.icon).tag(framework)
                    }
                }
                .frame(width: 300)
            }
            
            Spacer()
            
            VStack(alignment: .trailing) {
                Text("Compliance Score")
                    .font(.headline)
                    .fontWeight(.bold)
                
                Text("\(Int(complianceScore * 100))%")
                    .font(.title)
                    .fontWeight(.bold)
                    .foregroundColor(complianceScore > 0.8 ? .green : complianceScore > 0.6 ? .orange : .red)
            }
            
            Button(action: auditAction) {
                Text(isAuditing ? "Auditing..." : "Start Audit")
                    .fontWeight(.semibold)
                    .foregroundColor(.white)
                    .padding(.horizontal, 20)
                    .padding(.vertical, 10)
                    .background(isAuditing ? Color.orange : Color.blue, in: RoundedRectangle(cornerRadius: 8))
            }
            .disabled(isAuditing)
        }
        .padding()
        .background(.regularMaterial)
    }
}

struct ComplianceScorePanel: View {
    let score: Double
    let framework: ComplianceView.ComplianceFramework
    
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Compliance Score")
                .font(.headline)
                .fontWeight(.bold)
            
            // Circular progress indicator
            ZStack {
                Circle()
                    .stroke(Color.gray.opacity(0.3), lineWidth: 12)
                    .frame(width: 120, height: 120)
                
                Circle()
                    .trim(from: 0, to: score)
                    .stroke(score > 0.8 ? Color.green : score > 0.6 ? Color.orange : Color.red, lineWidth: 12)
                    .frame(width: 120, height: 120)
                    .rotationEffect(.degrees(-90))
                
                VStack {
                    Text("\(Int(score * 100))")
                        .font(.title)
                        .fontWeight(.bold)
                    Text("%")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            
            Text(framework.rawValue)
                .font(.body)
                .foregroundColor(.secondary)
        }
        .padding()
    }
}

struct AuditResultsPanel: View {
    let results: [AuditResult]
    
    var body: some View {
        VStack(alignment: .leading) {
            Text("Audit Results")
                .font(.headline)
                .fontWeight(.bold)
            
            List(results) { result in
                AuditResultRow(result: result)
            }
            .listStyle(.plain)
        }
        .padding()
    }
}

struct AuditResultRow: View {
    let result: AuditResult
    
    var body: some View {
        HStack {
            Text(result.control)
                .font(.body)
                .fontWeight(.medium)
            
            Spacer()
            
            Text(result.status.rawValue)
                .font(.caption)
                .fontWeight(.semibold)
                .foregroundColor(result.status.color)
        }
        .padding(.vertical, 4)
    }
}

struct RecommendationsPanel: View {
    let recommendations: [ComplianceRecommendation]
    
    var body: some View {
        VStack(alignment: .leading) {
            Text("Recommendations")
                .font(.headline)
                .fontWeight(.bold)
            
            List(recommendations) { rec in
                RecommendationRow(recommendation: rec)
            }
            .listStyle(.plain)
        }
        .padding()
    }
}

struct RecommendationRow: View {
    let recommendation: ComplianceRecommendation
    
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(recommendation.title)
                    .font(.body)
                    .fontWeight(.medium)
                
                Text(recommendation.framework.rawValue)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
            
            Text(recommendation.priority.rawValue)
                .font(.caption)
                .fontWeight(.bold)
                .foregroundColor(recommendation.priority.color)
        }
        .padding(.vertical, 4)
    }
}

struct ComplianceActionsPanel: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Quick Actions")
                .font(.headline)
                .fontWeight(.bold)
            
            Button("Generate Report") {
                // Generate compliance report
            }
            .buttonStyle(.borderedProminent)
            
            Button("Export Evidence") {
                // Export audit evidence
            }
            .buttonStyle(.bordered)
            
            Button("Schedule Re-audit") {
                // Schedule next audit
            }
            .buttonStyle(.bordered)
        }
        .padding()
    }
}

// MARK: - Data Models

struct AuditResult: Identifiable {
    let id = UUID()
    let control: String
    let status: ComplianceStatus
    let framework: ComplianceView.ComplianceFramework
    let timestamp = Date()
    
    enum ComplianceStatus: String, CaseIterable {
        case compliant = "Compliant"
        case partiallyCompliant = "Partially Compliant"
        case nonCompliant = "Non-Compliant"
        case notApplicable = "Not Applicable"
        
        var color: Color {
            switch self {
            case .compliant: return .green
            case .partiallyCompliant: return .yellow
            case .nonCompliant: return .red
            case .notApplicable: return .gray
            }
        }
    }
}

struct ComplianceRecommendation: Identifiable {
    let id = UUID()
    let title: String
    let priority: Priority
    let framework: ComplianceView.ComplianceFramework
    let description: String
    
    init(title: String, priority: Priority, framework: ComplianceView.ComplianceFramework, description: String = "") {
        self.title = title
        self.priority = priority
        self.framework = framework
        self.description = description
    }
    
    enum Priority: String, CaseIterable {
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


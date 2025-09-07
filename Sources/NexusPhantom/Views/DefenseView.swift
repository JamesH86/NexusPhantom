import SwiftUI
import Combine

struct DefenseView: View {
    // @EnvironmentObject var threatEngine: ThreatDetectionEngine
    @EnvironmentObject var aiOrchestrator: AIOrchestrator
    @EnvironmentObject var voiceManager: VoiceManager
    
    @State private var selectedIncident: SecurityIncident?
    @State private var incidents: [SecurityIncident] = []
    @State private var mitigations: [MitigationAction] = []
    @State private var forensicsData: [ForensicsEvidence] = []
    @State private var isInvestigating = false
    
    var body: some View {
        VStack(spacing: 0) {
            // Defense status header
            DefenseStatusHeader()
            
            Divider()
            
            HStack(spacing: 0) {
                // Left panel - Active incidents
                VStack {
                    IncidentsPanel(incidents: incidents, selectedIncident: $selectedIncident)
                    MitigationsPanel(mitigations: mitigations)
                }
                .frame(width: 400)
                
                Divider()
                
                // Center panel - Incident details and response
                VStack {
                    if let incident = selectedIncident {
                        IncidentDetailsPanel(incident: incident)
                        ResponseActionsPanel(incident: incident)
                    } else {
                        Text("Select an incident to view details")
                            .foregroundColor(.secondary)
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                }
                .frame(maxWidth: .infinity)
                
                Divider()
                
                // Right panel - Forensics and AI assistance
                VStack {
                    ForensicsPanel(evidence: forensicsData)
                    AIDefenseAssistancePanel()
                }
                .frame(width: 350)
            }
        }
        .navigationTitle("NEXUS PHANTOM - Defense & Incident Response")
        .onAppear {
            loadSecurityIncidents()
            voiceManager.speak("Defense module activated. Monitoring for security incidents.")
        }
    }
    
    private func loadSecurityIncidents() {
        incidents = [
            SecurityIncident(
                title: "Suspicious Network Activity",
                type: .networkAnomaly,
                severity: .high,
                description: "Unusual outbound connections detected",
                affectedAssets: ["192.168.1.50", "web-server-01"]
            ),
            SecurityIncident(
                title: "Malware Detection",
                type: .malware,
                severity: .critical,
                description: "Potential trojan detected in downloads folder",
                affectedAssets: ["user-workstation-05"]
            )
        ]
    }
}

struct DefenseStatusHeader: View {
    // @EnvironmentObject var threatDetectionEngine: ThreatDetectionEngine
    
    var body: some View {
        HStack {
            VStack(alignment: .leading) {
                Text("Defense Status")
                    .font(.headline)
                    .fontWeight(.bold)
                
                HStack {
                    Label("Threat Level: Secure", 
                          systemImage: "shield.fill")
                        .foregroundColor(.green)
                    
                    Spacer()
                    
                    Label("Monitoring: Active", 
                          systemImage: "eye.fill")
                        .foregroundColor(.green)
                }
            }
            
            Spacer()
            
            Button("Emergency Response") {
                // Trigger emergency response
            }
            .buttonStyle(.borderedProminent)
            .foregroundColor(.white)
            .background(.red)
        }
        .padding()
        .background(.regularMaterial)
    }
}

struct IncidentsPanel: View {
    let incidents: [SecurityIncident]
    @Binding var selectedIncident: SecurityIncident?
    
    var body: some View {
        VStack(alignment: .leading) {
            Text("Security Incidents")
                .font(.headline)
                .fontWeight(.bold)
            
            List(incidents, selection: $selectedIncident) { incident in
                IncidentRow(incident: incident)
            }
            .listStyle(.plain)
        }
        .padding()
    }
}

struct IncidentRow: View {
    let incident: SecurityIncident
    
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(incident.title)
                    .font(.body)
                    .fontWeight(.medium)
                
                Text(incident.type.rawValue)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
            
            VStack(alignment: .trailing) {
                Text(incident.severity.rawValue)
                    .font(.caption)
                    .fontWeight(.bold)
                    .foregroundColor(incident.severity.color)
                
                Text(incident.timestamp.formatted(.relative(presentation: .named)))
                    .font(.caption)
.foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

struct MitigationsPanel: View {
    let mitigations: [MitigationAction]
    
    var body: some View {
        VStack(alignment: .leading) {
            Text("Applied Mitigations")
                .font(.headline)
                .fontWeight(.bold)
            
            if mitigations.isEmpty {
                Text("No mitigations applied")
                    .foregroundColor(.secondary)
                    .italic()
            } else {
                List(mitigations) { mitigation in
                    MitigationRow(mitigation: mitigation)
                }
                .listStyle(.plain)
            }
        }
        .padding()
    }
}

struct MitigationRow: View {
    let mitigation: MitigationAction
    
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(mitigation.action)
                    .font(.body)
                    .fontWeight(.medium)
                
                Text(mitigation.target)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
            
            Text(mitigation.status.rawValue)
                .font(.caption)
                .fontWeight(.semibold)
                .foregroundColor(mitigation.status.color)
        }
        .padding(.vertical, 4)
    }
}

struct IncidentDetailsPanel: View {
    let incident: SecurityIncident
    
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Incident Details")
                .font(.headline)
                .fontWeight(.bold)
            
            VStack(alignment: .leading, spacing: 8) {
                DetailRow(label: "Title", value: incident.title)
                DetailRow(label: "Type", value: incident.type.rawValue)
                DetailRow(label: "Severity", value: incident.severity.rawValue)
                DetailRow(label: "Description", value: incident.description)
                DetailRow(label: "Affected Assets", value: incident.affectedAssets.joined(separator: ", "))
                DetailRow(label: "Timestamp", value: incident.timestamp.formatted())
            }
        }
        .padding()
    }
}

// DetailRow is now defined in CriticalInfrastructureView.swift

struct ResponseActionsPanel: View {
    let incident: SecurityIncident
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Response Actions")
                .font(.headline)
                .fontWeight(.bold)
            
            Button("Contain Threat") {
                // Contain the threat
            }
            .buttonStyle(.borderedProminent)
            
            Button("Collect Evidence") {
                // Collect forensic evidence
            }
            .buttonStyle(.bordered)
            
            Button("Block IP Address") {
                // Block malicious IP
            }
            .buttonStyle(.bordered)
            
            Button("Quarantine Asset") {
                // Quarantine affected asset
            }
            .buttonStyle(.bordered)
        }
        .padding()
    }
}

struct ForensicsPanel: View {
    let evidence: [ForensicsEvidence]
    
    var body: some View {
        VStack(alignment: .leading) {
            Text("Forensics Evidence")
                .font(.headline)
                .fontWeight(.bold)
            
            if evidence.isEmpty {
                Text("No evidence collected")
                    .foregroundColor(.secondary)
                    .italic()
            } else {
                List(evidence) { item in
                    EvidenceRow(evidence: item)
                }
                .listStyle(.plain)
            }
        }
        .padding()
    }
}

struct EvidenceRow: View {
    let evidence: ForensicsEvidence
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(evidence.type.rawValue)
                .font(.body)
                .fontWeight(.medium)
            
            Text(evidence.description)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding(.vertical, 4)
    }
}

struct AIDefenseAssistancePanel: View {
    @EnvironmentObject var aiOrchestrator: AIOrchestrator
    @State private var aiQuery = ""
    @State private var aiResponse = ""
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("AI Defense Assistant")
                .font(.headline)
                .fontWeight(.bold)
            
            TextField("Ask AI about threat response...", text: $aiQuery)
                .textFieldStyle(.roundedBorder)
            
            Button("Get Defense Guidance") {
                Task {
                    await getAIDefenseHelp()
                }
            }
            .buttonStyle(.borderedProminent)
            
            if !aiResponse.isEmpty {
                ScrollView {
                    Text(aiResponse)
                        .font(.caption)
                        .foregroundColor(.primary)
                        .padding()
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
                }
                .frame(maxHeight: 200)
            }
        }
        .padding()
    }
    
    private func getAIDefenseHelp() async {
        let context = CyberSecurityContext(
            domain: .defense,
            target: nil,
            urgency: .high,
            isVoiceCommand: false,
            requiredActions: [],
            userPermissions: []
        )
        
        let response = await aiOrchestrator.processQuery(aiQuery, context: context)
        aiResponse = response.content
    }
}

// MARK: - Data Models

struct SecurityIncident: Identifiable, Hashable {
    let id = UUID()
    let title: String
    let type: IncidentType
    let severity: IncidentSeverity
    let description: String
    let affectedAssets: [String]
    let timestamp = Date()
    
    enum IncidentType: String, CaseIterable {
        case malware = "Malware"
        case networkAnomaly = "Network Anomaly"
        case dataExfiltration = "Data Exfiltration"
        case unauthorizedAccess = "Unauthorized Access"
        case ddos = "DDoS Attack"
        case phishing = "Phishing"
    }
    
    enum IncidentSeverity: String, CaseIterable {
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

struct MitigationAction: Identifiable {
    let id = UUID()
    let action: String
    let target: String
    let status: MitigationStatus
    let timestamp = Date()
    
    enum MitigationStatus: String, CaseIterable {
        case pending = "Pending"
        case inProgress = "In Progress"
        case completed = "Completed"
        case failed = "Failed"
        
        var color: Color {
            switch self {
            case .pending: return .blue
            case .inProgress: return .orange
            case .completed: return .green
            case .failed: return .red
            }
        }
    }
}

struct ForensicsEvidence: Identifiable {
    let id = UUID()
    let type: EvidenceType
    let description: String
    let filePath: String?
    let hash: String?
    let timestamp = Date()
    
    enum EvidenceType: String, CaseIterable {
        case networkCapture = "Network Capture"
        case memoryDump = "Memory Dump"
        case diskImage = "Disk Image"
        case logFile = "Log File"
        case malwareSample = "Malware Sample"
    }
}


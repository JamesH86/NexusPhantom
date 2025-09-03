import SwiftUI

struct ReportsView: View {
    @EnvironmentObject var aiOrchestrator: AIOrchestrator
    @EnvironmentObject var toolRunner: ToolRunner
    @EnvironmentObject var voiceManager: VoiceManager
    
    @State private var reports: [SecurityReport] = []
    @State private var selectedReportType: ReportType = .penetrationTest
    @State private var isGenerating = false
    @State private var selectedReport: SecurityReport?
    
    enum ReportType: String, CaseIterable {
        case penetrationTest = "Penetration Test"
        case vulnerabilityAssessment = "Vulnerability Assessment"
        case incidentResponse = "Incident Response"
        case complianceAudit = "Compliance Audit"
        case threatAnalysis = "Threat Analysis"
        case executiveSummary = "Executive Summary"
        
        var icon: String {
            switch self {
            case .penetrationTest: return "shield.lefthalf.filled"
            case .vulnerabilityAssessment: return "magnifyingglass.circle"
            case .incidentResponse: return "exclamationmark.triangle"
            case .complianceAudit: return "checkmark.seal"
            case .threatAnalysis: return "brain.head.profile"
            case .executiveSummary: return "doc.text"
            }
        }
    }
    
    var body: some View {
        VStack(spacing: 0) {
            ReportsHeader(
                selectedReportType: $selectedReportType,
                isGenerating: $isGenerating
            ) {
                Task {
                    await generateReport()
                }
            }
            
            Divider()
            
            HStack(spacing: 0) {
                // Left panel - Report list
                VStack {
                    ReportListPanel(reports: reports, selectedReport: $selectedReport)
                }
                .frame(width: 400)
                
                Divider()
                
                // Right panel - Report preview/editor
                VStack {
                    if let report = selectedReport {
                        ReportPreviewPanel(report: report)
                    } else {
                        Text("Select a report to view details")
                            .foregroundColor(.secondary)
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                }
                .frame(maxWidth: .infinity)
            }
        }
        .navigationTitle("NEXUS PHANTOM - Security Reports")
        .onAppear {
            loadExistingReports()
            voiceManager.speak("Security reporting module activated")
        }
    }
    
    private func generateReport() async {
        isGenerating = true
        voiceManager.speak("Generating \(selectedReportType.rawValue.lowercased())")
        
        let context = CyberSecurityContext(
            domain: .research,
            target: "report_generation",
            urgency: .normal,
            isVoiceCommand: false,
            requiredActions: [],
            userPermissions: []
        )
        
        let query = "Generate a professional \(selectedReportType.rawValue.lowercased()) with executive summary, technical findings, risk assessment, and recommendations"
        let aiResponse = await aiOrchestrator.processQuery(query, context: context)
        
        let report = SecurityReport(
            title: "\(selectedReportType.rawValue) - \(Date().formatted(.dateTime))",
            type: selectedReportType,
            content: aiResponse.content,
            status: .draft,
            format: .markdown
        )
        
        reports.append(report)
        selectedReport = report
        
        isGenerating = false
        voiceManager.speak("Report generation completed")
    }
    
    private func loadExistingReports() {
        // Load sample reports
        reports = [
            SecurityReport(
                title: "Network Penetration Test - Example Corp",
                type: .penetrationTest,
                content: samplePentestReport,
                status: .completed,
                format: .markdown
            ),
            SecurityReport(
                title: "Vulnerability Assessment - Q4 2024",
                type: .vulnerabilityAssessment,
                content: sampleVulnReport,
                status: .draft,
                format: .markdown
            )
        ]
    }
}

struct ReportsHeader: View {
    @Binding var selectedReportType: ReportsView.ReportType
    @Binding var isGenerating: Bool
    let generateAction: () -> Void
    
    var body: some View {
        HStack {
            VStack(alignment: .leading) {
                Text("Report Generation")
                    .font(.headline)
                    .fontWeight(.bold)
                
                Picker("Report Type", selection: $selectedReportType) {
                    ForEach(ReportsView.ReportType.allCases, id: \.self) { type in
                        Label(type.rawValue, systemImage: type.icon).tag(type)
                    }
                }
                .frame(width: 300)
            }
            
            Spacer()
            
            Button(action: generateAction) {
                HStack {
                    if isGenerating {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                            .scaleEffect(0.8)
                    }
                    
                    Text(isGenerating ? "Generating..." : "Generate Report")
                        .fontWeight(.semibold)
                }
                .foregroundColor(.white)
                .padding(.horizontal, 20)
                .padding(.vertical, 10)
                .background(isGenerating ? Color.orange : Color.green, in: RoundedRectangle(cornerRadius: 8))
            }
            .disabled(isGenerating)
        }
        .padding()
        .background(.regularMaterial)
    }
}

struct ReportListPanel: View {
    let reports: [SecurityReport]
    @Binding var selectedReport: SecurityReport?
    
    var body: some View {
        VStack(alignment: .leading) {
            Text("Security Reports")
                .font(.headline)
                .fontWeight(.bold)
            
            List(reports, selection: $selectedReport) { report in
                ReportListRow(report: report)
            }
            .listStyle(.plain)
        }
        .padding()
    }
}

struct ReportListRow: View {
    let report: SecurityReport
    
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(report.title)
                    .font(.body)
                    .fontWeight(.medium)
                    .lineLimit(2)
                
                Text(report.type.rawValue)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
            
            VStack(alignment: .trailing) {
                Text(report.status.rawValue)
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(report.status.color)
                
                Text(report.createdDate.formatted(.relative(presentation: .named)))
                    .font(.caption)
.foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 6)
    }
}

struct ReportPreviewPanel: View {
    let report: SecurityReport
    @State private var isEditing = false
    @State private var editedContent = ""
    
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Report header
            HStack {
                VStack(alignment: .leading) {
                    Text(report.title)
                        .font(.title2)
                        .fontWeight(.bold)
                    
                    Text(report.type.rawValue)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                HStack {
                    Button(isEditing ? "Save" : "Edit") {
                        if isEditing {
                            // Save changes
                        } else {
                            editedContent = report.content
                        }
                        isEditing.toggle()
                    }
                    .buttonStyle(.bordered)
                    
                    Button("Export") {
                        exportReport()
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
            
            Divider()
            
            // Report content
            ScrollView {
                if isEditing {
                    TextEditor(text: $editedContent)
                        .font(.body)
                        .frame(maxWidth: .infinity, minHeight: 400)
                } else {
                    Text(report.content)
                        .font(.body)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
                }
            }
        }
        .padding()
    }
    
    private func exportReport() {
        // Export report to PDF or other formats
    }
}

// MARK: - Data Models

struct SecurityReport: Identifiable, Hashable {
    let id = UUID()
    let title: String
    let type: ReportsView.ReportType
    let content: String
    let status: ReportStatus
    let format: ReportFormat
    let createdDate = Date()
    var lastModified = Date()
    
    enum ReportStatus: String, CaseIterable {
        case draft = "Draft"
        case review = "Under Review"
        case completed = "Completed"
        case published = "Published"
        
        var color: Color {
            switch self {
            case .draft: return .blue
            case .review: return .orange
            case .completed: return .green
            case .published: return .purple
            }
        }
    }
    
    enum ReportFormat: String, CaseIterable {
        case markdown = "Markdown"
        case pdf = "PDF"
        case html = "HTML"
        case docx = "Word Document"
    }
}

// MARK: - Sample Report Content

private let samplePentestReport = """
# Penetration Test Report

## Executive Summary
This report presents the findings of a comprehensive penetration test conducted on the target infrastructure. The assessment identified several security vulnerabilities that require immediate attention.

## Scope and Methodology
- **Target**: example.com infrastructure
- **Duration**: 5 days
- **Methodology**: OWASP Testing Guide, PTES
- **Tools Used**: Nmap, Burp Suite, Metasploit, Nuclei

## Findings
### Critical Vulnerabilities
1. SQL Injection in login form
2. Remote Code Execution in file upload

### High Risk Vulnerabilities
1. Cross-Site Scripting (XSS)
2. Insecure Direct Object References

## Recommendations
1. Implement input validation
2. Apply security patches
3. Enable WAF protection
4. Conduct security code review

## Conclusion
Immediate remediation of critical vulnerabilities is recommended.
"""

private let sampleVulnReport = """
# Vulnerability Assessment Report

## Overview
Comprehensive vulnerability assessment conducted using automated scanning tools and manual verification.

## Summary Statistics
- **Total Vulnerabilities**: 23
- **Critical**: 2
- **High**: 5
- **Medium**: 10
- **Low**: 6

## Detailed Findings
[Detailed vulnerability listings would appear here]

## Risk Assessment
Overall risk level: HIGH

## Remediation Plan
Prioritized list of remediation actions with timelines.
"""


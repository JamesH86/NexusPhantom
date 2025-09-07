import SwiftUI
import Charts

struct DashboardView: View {
    // @EnvironmentObject var threatEngine: ThreatDetectionEngine
    @EnvironmentObject var aiOrchestrator: AIOrchestrator
    @EnvironmentObject var toolRunner: ToolRunner
    @EnvironmentObject var appState: AppState
    
    @State private var refreshTimer: Timer?
    
    var body: some View {
        ScrollView {
            LazyVGrid(columns: dashboardLayout, spacing: 20) {
                // Threat Level Overview
                // ThreatLevelCard()
                
                // AI Models Status
                AIModelsCard()
                
                // Active Operations
                ActiveOperationsCard()
                
                // Live Network Monitor
                // NetworkMonitorCard()
                
                // Recent Threats
                // RecentThreatsCard()
                
// Tool Status
                DashboardToolStatusCard()
                
                // Performance Metrics
                // PerformanceMetricsCard()
                
                // Quick Actions
                QuickActionsCard()
            }
            .padding()
        }
        .navigationTitle("NEXUS PHANTOM Dashboard")
        .onAppear {
            startDashboardRefresh()
        }
        .onDisappear {
            stopDashboardRefresh()
        }
    }
    
    private var dashboardLayout: [GridItem] {
        [
            GridItem(.flexible(), spacing: 20),
            GridItem(.flexible(), spacing: 20)
        ]
    }
    
    private func startDashboardRefresh() {
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { _ in
            Task {
                // Refresh dashboard data
            }
        }
    }
    
    private func stopDashboardRefresh() {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }
}

// MARK: - Dashboard Cards
struct ThreatLevelCard: View {
    @EnvironmentObject var threatEngine: ThreatDetectionEngine
    
    var body: some View {
        DashboardCard(title: "Threat Level") {
            VStack(spacing: 16) {
                // Large threat level indicator
                ZStack {
                    Circle()
                        .fill(threatEngine.currentThreatLevel.color.opacity(0.2))
                        .frame(width: 100, height: 100)
                    
                    Circle()
                        .stroke(threatEngine.currentThreatLevel.color, lineWidth: 8)
                        .frame(width: 100, height: 100)
                    
                    VStack {
                        Image(systemName: threatLevelIcon)
                            .font(.system(size: 30, weight: .bold))
                            .foregroundColor(threatEngine.currentThreatLevel.color)
                        
                        Text(threatEngine.currentThreatLevel.rawValue)
                            .font(.caption)
                            .fontWeight(.bold)
                    }
                }
                
                // Threat statistics
                HStack {
                    StatItem(label: "Active", value: "\(threatEngine.activeThreats.count)")
                    StatItem(label: "Critical", value: "\(threatEngine.monitoringStats.criticalThreats)")
                    StatItem(label: "Mitigated", value: "\(threatEngine.monitoringStats.mitigationsApplied)")
                }
            }
        }
    }
    
    private var threatLevelIcon: String {
        switch threatEngine.currentThreatLevel {
        case .critical: return "exclamationmark.triangle.fill"
        case .high: return "exclamationmark.circle.fill"
        case .medium: return "info.circle.fill"
        case .low: return "checkmark.circle.fill"
        case .secure: return "shield.checkered"
        }
    }
}

struct AIModelsCard: View {
    @EnvironmentObject var aiOrchestrator: AIOrchestrator
    
    var body: some View {
        DashboardCard(title: "AI Models") {
            VStack(alignment: .leading, spacing: 12) {
                ForEach(aiOrchestrator.activeModels, id: \.self) { model in
                    HStack {
                        Circle()
                            .fill(.green)
                            .frame(width: 8, height: 8)
                        
                        Text(model)
                            .font(.body)
                            .fontWeight(.medium)
                        
                        Spacer()
                        
                        if let metrics = aiOrchestrator.modelPerformance[model] {
                            Text("\(metrics.avgResponseTime, specifier: "%.1f")s")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                }
                
                if aiOrchestrator.activeModels.isEmpty {
                    Text("No AI models active")
                        .foregroundColor(.secondary)
                        .italic()
                }
            }
        }
    }
}

struct ActiveOperationsCard: View {
    @EnvironmentObject var toolRunner: ToolRunner
    
    var body: some View {
        DashboardCard(title: "Active Operations") {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(toolRunner.runningTools) { tool in
                    HStack {
                        Image(systemName: "gear")
                            .foregroundColor(.orange)
// .symbolEffect(.rotate, isActive: tool.status == .running)
                        
                        VStack(alignment: .leading) {
                            Text(tool.name)
                                .font(.headline)
                                .fontWeight(.semibold)
                            Text(tool.target)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        
                        Spacer()
                        
                        Text(tool.status == .running ? "Running" : "Completed")
                            .font(.caption)
                            .foregroundColor(tool.status == .running ? .orange : .green)
                    }
                }
                
                if toolRunner.runningTools.isEmpty {
                    Text("No active operations")
                        .foregroundColor(.secondary)
                        .italic()
                }
            }
        }
    }
}

struct NetworkMonitorCard: View {
    @EnvironmentObject var threatEngine: ThreatDetectionEngine
    
    var body: some View {
        DashboardCard(title: "Network Monitor") {
            VStack(alignment: .leading, spacing: 12) {
                // Connection count
                HStack {
                    Text("Connections:")
                        .fontWeight(.medium)
                    Spacer()
                    Text("\(threatEngine.networkConnections.count)")
                        .fontWeight(.bold)
                        .foregroundColor(.blue)
                }
                
                // Suspicious connections
                HStack {
                    Text("Suspicious:")
                        .fontWeight(.medium)
                    Spacer()
                    Text("\(threatEngine.networkConnections.filter { $0.riskScore > 0.5 }.count)")
                        .fontWeight(.bold)
                        .foregroundColor(.orange)
                }
                
                // Network activity chart (placeholder)
                RoundedRectangle(cornerRadius: 8)
                    .fill(.gray.opacity(0.2))
                    .frame(height: 60)
                    .overlay {
                        Text("Live Network Activity Chart")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
            }
        }
    }
}

struct RecentThreatsCard: View {
    @EnvironmentObject var threatEngine: ThreatDetectionEngine
    
    var body: some View {
        DashboardCard(title: "Recent Threats") {
            VStack(alignment: .leading, spacing: 8) {
ForEach(Array(threatEngine.activeThreats.prefix(5))) { threat in
                    HStack {
                        Circle()
                            .fill(threat.severity.color)
                            .frame(width: 8, height: 8)
                        
                        VStack(alignment: .leading) {
                            Text(threat.type.rawValue)
                                .font(.headline)
                                .fontWeight(.semibold)
                            Text(threat.description)
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .lineLimit(2)
                        }
                        
                        Spacer()
                        
                        Text(threat.timestamp.formatted(.relative(presentation: .named)))
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
                
                if threatEngine.activeThreats.isEmpty {
                    Text("No recent threats detected")
                        .foregroundColor(.green)
                        .italic()
                }
            }
        }
    }
}

struct DashboardToolStatusCard: View {
    @EnvironmentObject var toolRunner: ToolRunner
    
    var body: some View {
        DashboardCard(title: "Tool Status") {
            VStack(alignment: .leading, spacing: 8) {
                let installedCount = toolRunner.availableTools.filter { $0.isInstalled }.count
                let totalCount = toolRunner.availableTools.count
                
                HStack {
                    Text("Tools Ready:")
                        .fontWeight(.medium)
                    Spacer()
                    Text("\(installedCount)/\(totalCount)")
                        .fontWeight(.bold)
                        .foregroundColor(installedCount == totalCount ? .green : .orange)
                }
                
                // Tool categories
                ForEach(ToolRunner.ToolCategory.allCases.prefix(5), id: \.self) { category in
                    let categoryTools = toolRunner.availableTools.filter { $0.category == category }
                    let installedInCategory = categoryTools.filter { $0.isInstalled }.count
                    
                    HStack {
                        Text(category.rawValue)
                            .font(.caption)
                        Spacer()
                        Text("\(installedInCategory)/\(categoryTools.count)")
                            .font(.caption)
                            .foregroundColor(installedInCategory == categoryTools.count ? .green : .red)
                    }
                }
            }
        }
    }
}

struct PerformanceMetricsCard: View {
    @EnvironmentObject var threatEngine: ThreatDetectionEngine
    @EnvironmentObject var aiOrchestrator: AIOrchestrator
    
    var body: some View {
        DashboardCard(title: "Performance Metrics") {
            VStack(alignment: .leading, spacing: 12) {
MetricRow(label: "Detection Accuracy", value: String(format: "%.1f%%", threatEngine.monitoringStats.detectionAccuracy * 100))
                MetricRow(label: "Events Analyzed", value: "\(threatEngine.monitoringStats.networkEventsAnalyzed + threatEngine.monitoringStats.fileSystemEventsAnalyzed)")
MetricRow(label: "AI Response Time", value: String(format: "%.1fs", calculateAvgResponseTime()))
                MetricRow(label: "Uptime", value: "24h 15m")
            }
        }
    }
    
    private func calculateAvgResponseTime() -> Double {
        let times = aiOrchestrator.modelPerformance.values.map { $0.avgResponseTime }
        return times.isEmpty ? 0.0 : times.reduce(0, +) / Double(times.count)
    }
}

struct QuickActionsCard: View {
    @EnvironmentObject var toolRunner: ToolRunner
    // @EnvironmentObject var threatEngine: ThreatDetectionEngine
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        DashboardCard(title: "Quick Actions") {
            VStack(spacing: 12) {
                ActionButton(title: "Full Network Scan", icon: "network", color: .blue) {
                    Task {
                        await toolRunner.runFullSecurityScan()
                    }
                }
                
                ActionButton(title: "Tool Status", icon: "magnifyingglass.circle", color: .orange) {
                    // Placeholder for threat analysis
                }
                
                ActionButton(title: "Launch Burp", icon: "globe", color: .purple) {
                    Task {
                        await toolRunner.launchBurpSuite()
                    }
                }
                
                ActionButton(title: "Bug Bounty Mode", icon: "dollarsign.circle", color: .green) {
                    appState.currentView = .bugBounty
                }
            }
        }
    }
}

// MARK: - Dashboard Components
struct DashboardCard<Content: View>: View {
    let title: String
    let content: Content
    
    init(title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.headline)
                .fontWeight(.bold)
                .foregroundColor(.primary)
            
            content
        }
        .padding(20)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
        .shadow(color: .black.opacity(0.1), radius: 8, x: 0, y: 4)
    }
}

struct StatItem: View {
    let label: String
    let value: String
    
    var body: some View {
        VStack {
            Text(value)
                .font(.title2)
                .fontWeight(.bold)
                .foregroundColor(.primary)
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }
}

struct MetricRow: View {
    let label: String
    let value: String
    
    var body: some View {
        HStack {
            Text(label)
                .font(.body)
                .foregroundColor(.primary)
            Spacer()
            Text(value)
                .font(.body)
                .fontWeight(.semibold)
                .foregroundColor(.secondary)
        }
    }
}

struct ActionButton: View {
    let title: String
    let icon: String
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack {
                Image(systemName: icon)
                    .frame(width: 20)
                Text(title)
                    .fontWeight(.medium)
                Spacer()
            }
            .foregroundColor(.white)
            .padding()
            .background(color, in: RoundedRectangle(cornerRadius: 8))
        }
        .buttonStyle(.borderless)
    }
}

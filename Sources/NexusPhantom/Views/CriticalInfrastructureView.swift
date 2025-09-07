import SwiftUI
import Charts

struct CriticalInfrastructureView: View {
    @StateObject private var infraModule = CriticalInfrastructureModule()
    @State private var selectedSystem: SCADASystem?
    @State private var showingSystemDetails = false
    @State private var selectedThreat: InfrastructureThreat?
    @State private var showingThreatDetails = false
    
    var body: some View {
        GeometryReader { geometry in
            ScrollView {
                VStack(spacing: 20) {
                    // 🚨 CRITICAL ALERT BANNER
                    if !infraModule.realTimeAlerts.isEmpty {
                        CriticalAlertBanner(alerts: infraModule.realTimeAlerts)
                    }
                    
                    // 🎯 MAIN COMMAND CENTER GRID
                    LazyVGrid(columns: [
                        GridItem(.flexible(), spacing: 20),
                        GridItem(.flexible(), spacing: 20)
                    ], spacing: 20) {
                        
                        // 🏭 POWER GRID STATUS COMMAND CENTER
                        PowerGridCommandCenter(infraModule: infraModule)
                        
                        // 🌍 REAL-TIME THREAT LANDSCAPE
                        ThreatLandscapeView(infraModule: infraModule)
                        
                        // 🛡️ NATION-STATE THREAT MONITOR
                        NationStateThreatCenter(infraModule: infraModule)
                        
                        // 📊 COMPLIANCE DASHBOARD
                        ComplianceCommandCenter(infraModule: infraModule)
                        
                        // ⚡ QUANTUM-SAFE CRYPTO STATUS
                        QuantumSafeStatus(quantumEngine: infraModule.getQuantumEngine())
                        
                        // 🤖 AUTONOMOUS RESPONSE CENTER
                        AutonomousResponseCenter(responseSystem: infraModule.getIncidentOrchestrator())
                    }
                    
                    // 🏭 SCADA SYSTEMS MONITORING GRID
                    SCADASystemsGrid(systems: infraModule.scadaSystems) { system in
                        selectedSystem = system
                        showingSystemDetails = true
                    }
                    
                    // 🚨 ACTIVE THREATS TABLE
                    ActiveThreatsSection(threats: infraModule.activeThreats) { threat in
                        selectedThreat = threat
                        showingThreatDetails = true
                    }
                }
                .padding()
            }
        }
        .background(
            LinearGradient(
                gradient: Gradient(colors: [
                    Color.black.opacity(0.95),
                    Color.red.opacity(0.1),
                    Color.black.opacity(0.95)
                ]),
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        )
        .preferredColorScheme(.dark)
        .navigationTitle("🚨 CRITICAL INFRASTRUCTURE DEFENSE")
        // .navigationBarTitleDisplayMode(.large) // Not available on macOS
        .sheet(isPresented: $showingSystemDetails) {
            if let system = selectedSystem {
                SCADASystemDetailsSheet(system: system)
            }
        }
        .sheet(isPresented: $showingThreatDetails) {
            if let threat = selectedThreat {
                ThreatDetailsSheet(threat: threat)
            }
        }
        .task {
            await infraModule.startCriticalMonitoring()
        }
    }
}

// MARK: - Critical Alert Banner
struct CriticalAlertBanner: View {
    let alerts: [CriticalAlert]
    @State private var currentAlertIndex = 0
    
    private let timer = Timer.publish(every: 3, on: .main, in: .common).autoconnect()
    
    var body: some View {
        if !alerts.isEmpty {
            VStack(spacing: 0) {
                // Flashing border for critical alerts
                Rectangle()
                    .fill(alerts[currentAlertIndex].severity.color)
                    .frame(height: 4)
                
                HStack {
                    Image(systemName: alerts[currentAlertIndex].severity == .critical ? "exclamationmark.triangle.fill" : "exclamationmark.circle.fill")
                        .foregroundColor(alerts[currentAlertIndex].severity.color)
                        .font(.title2)
                        .scaleEffect(alerts[currentAlertIndex].severity == .critical ? 1.2 : 1.0)
                    
                    VStack(alignment: .leading, spacing: 4) {
                        Text(alerts[currentAlertIndex].title)
                            .font(.headline)
                            .fontWeight(.bold)
                            .foregroundColor(.white)
                        
                        Text(alerts[currentAlertIndex].message)
                            .font(.subheadline)
                            .foregroundColor(.white.opacity(0.9))
                    }
                    
                    Spacer()
                    
                    Text(alerts[currentAlertIndex].timestamp.formatted(.relative(presentation: .named)))
                        .font(.caption)
                        .foregroundColor(.white.opacity(0.7))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color.white.opacity(0.2), in: RoundedRectangle(cornerRadius: 4))
                }
                .padding()
                .background(
                    LinearGradient(
                        gradient: Gradient(colors: [
                            alerts[currentAlertIndex].severity.color.opacity(0.3),
                            Color.black.opacity(0.8)
                        ]),
                        startPoint: .leading,
                        endPoint: .trailing
                    )
                )
            }
            .cornerRadius(12)
            .shadow(color: alerts[currentAlertIndex].severity.color.opacity(0.5), radius: 8, x: 0, y: 4)
            .onReceive(timer) { _ in
                withAnimation(.easeInOut(duration: 0.5)) {
                    currentAlertIndex = (currentAlertIndex + 1) % alerts.count
                }
            }
        }
    }
}

// MARK: - Power Grid Command Center
struct PowerGridCommandCenter: View {
    @ObservedObject var infraModule: CriticalInfrastructureModule
    
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "bolt.fill")
                    .foregroundColor(.yellow)
                    .font(.title2)
                
                Text("POWER GRID STATUS")
                    .font(.headline)
                    .fontWeight(.bold)
                    .foregroundColor(.white)
                
                Spacer()
                
                Circle()
                    .fill(infraModule.powerGridStatus.color)
                    .frame(width: 12, height: 12)
                    .overlay(
                        Circle()
                            .stroke(Color.white.opacity(0.3), lineWidth: 2)
                    )
            }
            
            // Grid Status Indicator
            HStack {
                VStack(alignment: .leading) {
                    Text(infraModule.powerGridStatus.rawValue)
                        .font(.title3)
                        .fontWeight(.semibold)
                        .foregroundColor(infraModule.powerGridStatus.color)
                    
                    Text("Current Status")
                        .font(.caption)
                        .foregroundColor(.white.opacity(0.7))
                }
                
                Spacer()
                
                VStack(alignment: .trailing) {
                    Text("\(infraModule.scadaSystems.filter { $0.type == .powerGrid }.count)")
                        .font(.title2)
                        .fontWeight(.bold)
                        .foregroundColor(.white)
                    
                    Text("Grid Systems")
                        .font(.caption)
                        .foregroundColor(.white.opacity(0.7))
                }
            }
            
            // Quick Actions
            HStack(spacing: 12) {
                CriticalActionButton(
                    title: "EMERGENCY SHUTDOWN",
                    icon: "power",
                    color: .red
                ) {
                    // Emergency shutdown logic
                }
                
                CriticalActionButton(
                    title: "ISOLATION PROTOCOL",
                    icon: "shield.lefthalf.filled",
                    color: .orange
                ) {
                    // Isolation protocol
                }
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(infraModule.powerGridStatus.color.opacity(0.3), lineWidth: 1)
                )
        )
    }
}

// MARK: - Threat Landscape View
struct ThreatLandscapeView: View {
    @ObservedObject var infraModule: CriticalInfrastructureModule
    
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "eye.trianglebadge.exclamationmark")
                    .foregroundColor(.red)
                    .font(.title2)
                
                Text("THREAT LANDSCAPE")
                    .font(.headline)
                    .fontWeight(.bold)
                    .foregroundColor(.white)
                
                Spacer()
                
                Text("LIVE")
                    .font(.caption)
                    .fontWeight(.bold)
                    .foregroundColor(.red)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(Color.red.opacity(0.3), in: RoundedRectangle(cornerRadius: 4))
            }
            
            // Threat Level Indicator
            HStack {
                VStack(alignment: .leading) {
                    Text(infraModule.threatLevel.rawValue)
                        .font(.title3)
                        .fontWeight(.semibold)
                        .foregroundColor(infraModule.threatLevel.color)
                    
                    Text("Current Threat Level")
                        .font(.caption)
                        .foregroundColor(.white.opacity(0.7))
                }
                
                Spacer()
                
                // Threat Count
                VStack {
                    Text("\(infraModule.activeThreats.count)")
                        .font(.title)
                        .fontWeight(.bold)
                        .foregroundColor(.white)
                    
                    Text("Active Threats")
                        .font(.caption)
                        .foregroundColor(.white.opacity(0.7))
                }
            }
            
            // Protocol Threat Distribution
            VStack(alignment: .leading, spacing: 8) {
                Text("Protocol Threats")
                    .font(.subheadline)
                    .fontWeight(.semibold)
                    .foregroundColor(.white.opacity(0.9))
                
                LazyVGrid(columns: [
                    GridItem(.flexible()),
                    GridItem(.flexible())
                ], spacing: 8) {
                    ProtocolThreatIndicator(protocolName: "Modbus", count: 2, severity: .high)
                    ProtocolThreatIndicator(protocolName: "DNP3", count: 1, severity: .critical)
                    ProtocolThreatIndicator(protocolName: "OPC UA", count: 0, severity: .low)
                    ProtocolThreatIndicator(protocolName: "IEC 104", count: 0, severity: .low)
                }
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(infraModule.threatLevel.color.opacity(0.3), lineWidth: 1)
                )
        )
    }
}

// MARK: - Protocol Threat Indicator
struct ProtocolThreatIndicator: View {
    let protocolName: String
    let count: Int
    let severity: ThreatSeverity
    
    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(severity.color)
                .frame(width: 8, height: 8)
            
            Text(protocolName)
                .font(.caption)
                .foregroundColor(.white.opacity(0.8))
            
            Spacer()
            
            Text("\(count)")
                .font(.caption)
                .fontWeight(.semibold)
                .foregroundColor(.white)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(Color.white.opacity(0.1), in: RoundedRectangle(cornerRadius: 6))
    }
}

// MARK: - Nation-State Threat Center
struct NationStateThreatCenter: View {
    @ObservedObject var infraModule: CriticalInfrastructureModule
    
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "globe.badge.chevron.backward")
                    .foregroundColor(.purple)
                    .font(.title2)
                
                Text("NATION-STATE ACTORS")
                    .font(.headline)
                    .fontWeight(.bold)
                    .foregroundColor(.white)
            }
            
            if let latestThreat = infraModule.nationStateActivity.first {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text(latestThreat.actor)
                            .font(.subheadline)
                            .fontWeight(.semibold)
                            .foregroundColor(.red)
                        
                        Spacer()
                        
                        Text("\(Int(latestThreat.confidence * 100))%")
                            .font(.subheadline)
                            .fontWeight(.bold)
                            .foregroundColor(.white)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.red.opacity(0.3), in: RoundedRectangle(cornerRadius: 4))
                    }
                    
                    Text(latestThreat.campaign)
                        .font(.caption)
                        .foregroundColor(.white.opacity(0.8))
                    
                    Text("MITRE Techniques: \(latestThreat.techniques.count)")
                        .font(.caption2)
                        .foregroundColor(.white.opacity(0.6))
                }
                .padding()
                .background(Color.red.opacity(0.2), in: RoundedRectangle(cornerRadius: 8))
            } else {
                Text("No nation-state activity detected")
                    .font(.subheadline)
                    .foregroundColor(.white.opacity(0.7))
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.green.opacity(0.2), in: RoundedRectangle(cornerRadius: 8))
            }
            
            HStack {
                Text("Attribution Confidence")
                    .font(.caption)
                    .foregroundColor(.white.opacity(0.7))
                
                Spacer()
                
                Text("\(Int(infraModule.attributionConfidence * 100))%")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(.white)
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(Color.purple.opacity(0.3), lineWidth: 1)
                )
        )
    }
}

// MARK: - Compliance Command Center
struct ComplianceCommandCenter: View {
    @ObservedObject var infraModule: CriticalInfrastructureModule
    
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "checkmark.seal.fill")
                    .foregroundColor(.blue)
                    .font(.title2)
                
                Text("COMPLIANCE STATUS")
                    .font(.headline)
                    .fontWeight(.bold)
                    .foregroundColor(.white)
                
                Spacer()
                
                Text("\(Int(infraModule.complianceScore * 100))%")
                    .font(.title3)
                    .fontWeight(.bold)
                    .foregroundColor(infraModule.complianceScore > 0.8 ? .green : infraModule.complianceScore > 0.6 ? .orange : .red)
            }
            
            VStack(spacing: 8) {
                ComplianceFrameworkIndicator(
                    name: "NERC CIP",
                    score: infraModule.nercCIPCompliance.score,
                    color: .orange
                )
                
                ComplianceFrameworkIndicator(
                    name: "NIST CSF",
                    score: infraModule.nistCSFCompliance.score,
                    color: .blue
                )
                
                ComplianceFrameworkIndicator(
                    name: "IEC 62443",
                    score: infraModule.iec62443Compliance.score,
                    color: .green
                )
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(Color.blue.opacity(0.3), lineWidth: 1)
                )
        )
    }
}

// MARK: - Compliance Framework Indicator
struct ComplianceFrameworkIndicator: View {
    let name: String
    let score: Double
    let color: Color
    
    var body: some View {
        HStack {
            Text(name)
                .font(.caption)
                .fontWeight(.medium)
                .foregroundColor(.white.opacity(0.9))
            
            Spacer()
            
            ProgressView(value: score)
                .progressViewStyle(.linear)
                .frame(width: 60)
                .tint(color)
            
            Text("\(Int(score * 100))%")
                .font(.caption)
                .fontWeight(.semibold)
                .foregroundColor(.white)
                .frame(width: 35, alignment: .trailing)
        }
    }
}

// MARK: - Quantum-Safe Status
struct QuantumSafeStatus: View {
    @ObservedObject var quantumEngine: QuantumSafeCryptoEngine
    
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "atom")
                    .foregroundColor(.cyan)
                    .font(.title2)
                
                Text("QUANTUM READINESS")
                    .font(.headline)
                    .fontWeight(.bold)
                    .foregroundColor(.white)
            }
            
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("Quantum-Safe Score")
                        .font(.subheadline)
                        .foregroundColor(.white.opacity(0.9))
                    
                    Spacer()
                    
                    Text("\(Int(quantumEngine.quantumReadiness * 100))%")
                        .font(.subheadline)
                        .fontWeight(.bold)
                        .foregroundColor(quantumEngine.quantumReadiness > 0.7 ? .green : .orange)
                }
                
                ProgressView(value: quantumEngine.quantumReadiness)
                    .progressViewStyle(.linear)
                    .tint(.cyan)
                
                Text("Post-quantum cryptography implementation status")
                    .font(.caption2)
                    .foregroundColor(.white.opacity(0.6))
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(Color.cyan.opacity(0.3), lineWidth: 1)
                )
        )
    }
}

// MARK: - Autonomous Response Center
struct AutonomousResponseCenter: View {
    @ObservedObject var responseSystem: AutonomousIncidentResponse
    
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "cpu.fill")
                    .foregroundColor(.green)
                    .font(.title2)
                
                Text("AUTO RESPONSE")
                    .font(.headline)
                    .fontWeight(.bold)
                    .foregroundColor(.white)
            }
            
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("Mode")
                        .font(.subheadline)
                        .foregroundColor(.white.opacity(0.9))
                    
                    Spacer()
                    
                    Text(responseSystem.autonomyMode.rawValue)
                        .font(.subheadline)
                        .fontWeight(.semibold)
                        .foregroundColor(responseSystem.autonomyMode == .autonomous ? .green : responseSystem.autonomyMode == .supervised ? .orange : .blue)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2)
                        .background(Color.white.opacity(0.2), in: RoundedRectangle(cornerRadius: 4))
                }
                
                HStack {
                    Text("Active Playbooks")
                        .font(.caption)
                        .foregroundColor(.white.opacity(0.7))
                    
                    Spacer()
                    
                    Text("\(responseSystem.activePlaybooks.count)")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(.white)
                }
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(Color.green.opacity(0.3), lineWidth: 1)
                )
        )
    }
}

// MARK: - SCADA Systems Grid
struct SCADASystemsGrid: View {
    let systems: [SCADASystem]
    let onSystemTap: (SCADASystem) -> Void
    
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("🏭 SCADA SYSTEMS MONITORING")
                .font(.title2)
                .fontWeight(.bold)
                .foregroundColor(.white)
            
            LazyVGrid(columns: [
                GridItem(.flexible(), spacing: 16),
                GridItem(.flexible(), spacing: 16),
                GridItem(.flexible(), spacing: 16)
            ], spacing: 16) {
                ForEach(systems) { system in
                    SCADASystemCard(system: system) {
                        onSystemTap(system)
                    }
                }
            }
        }
    }
}

// MARK: - SCADA System Card
struct SCADASystemCard: View {
    let system: SCADASystem
    let onTap: () -> Void
    
    var body: some View {
        Button(action: onTap) {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Circle()
                        .fill(system.status.color)
                        .frame(width: 12, height: 12)
                    
                    Text(system.type.rawValue)
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(.white.opacity(0.8))
                    
                    Spacer()
                    
                    Text(system.criticalityLevel.rawValue)
                        .font(.caption2)
                        .fontWeight(.bold)
                        .foregroundColor(system.criticalityLevel.color)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(system.criticalityLevel.color.opacity(0.2), in: RoundedRectangle(cornerRadius: 3))
                }
                
                Text(system.name)
                    .font(.subheadline)
                    .fontWeight(.semibold)
                    .foregroundColor(.white)
                    .multilineTextAlignment(.leading)
                
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Security Score")
                            .font(.caption2)
                            .foregroundColor(.white.opacity(0.6))
                        
                        Text("\(Int(system.securityScore * 100))%")
                            .font(.caption)
                            .fontWeight(.semibold)
                            .foregroundColor(system.securityScore > 0.8 ? .green : system.securityScore > 0.6 ? .orange : .red)
                    }
                    
                    Spacer()
                    
                    Text(system.status.rawValue)
                        .font(.caption)
                        .fontWeight(.medium)
                        .foregroundColor(system.status.color)
                }
            }
            .padding()
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(.ultraThinMaterial)
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(system.status.color.opacity(0.3), lineWidth: 1)
                    )
            )
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Active Threats Section
struct ActiveThreatsSection: View {
    let threats: [InfrastructureThreat]
    let onThreatTap: (InfrastructureThreat) -> Void
    
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("🚨 ACTIVE INFRASTRUCTURE THREATS")
                    .font(.title2)
                    .fontWeight(.bold)
                    .foregroundColor(.white)
                
                Spacer()
                
                Text("\(threats.count) Active")
                    .font(.subheadline)
                    .fontWeight(.semibold)
                    .foregroundColor(.red)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.red.opacity(0.2), in: RoundedRectangle(cornerRadius: 6))
            }
            
            if threats.isEmpty {
                Text("No active threats detected")
                    .font(.subheadline)
                    .foregroundColor(.white.opacity(0.7))
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.green.opacity(0.2), in: RoundedRectangle(cornerRadius: 8))
            } else {
                VStack(spacing: 8) {
                    ForEach(threats) { threat in
                        ThreatRow(threat: threat) {
                            onThreatTap(threat)
                        }
                    }
                }
            }
        }
    }
}

// MARK: - Threat Row
struct ThreatRow: View {
    let threat: InfrastructureThreat
    let onTap: () -> Void
    
    var body: some View {
        Button(action: onTap) {
            HStack(spacing: 12) {
                Circle()
                    .fill(threat.severity.color)
                    .frame(width: 16, height: 16)
                    .overlay(
                        Circle()
                            .stroke(Color.white.opacity(0.3), lineWidth: 1)
                    )
                
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(threat.description)
                            .font(.subheadline)
                            .fontWeight(.medium)
                            .foregroundColor(.white)
                            .multilineTextAlignment(.leading)
                        
                        Spacer()
                        
                        if let protocolName = threat.networkProtocol {
                            Text(protocolName)
                                .font(.caption2)
                                .fontWeight(.semibold)
                                .foregroundColor(.white)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color.white.opacity(0.2), in: RoundedRectangle(cornerRadius: 3))
                        }
                    }
                    
                    HStack {
                        Text(threat.severity.rawValue)
                            .font(.caption)
                            .fontWeight(.semibold)
                            .foregroundColor(threat.severity.color)
                        
                        Spacer()
                        
                        Text(threat.timestamp.formatted(.relative(presentation: .named)))
                            .font(.caption)
                            .foregroundColor(.white.opacity(0.6))
                    }
                }
            }
            .padding()
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(.ultraThinMaterial)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(threat.severity.color.opacity(0.3), lineWidth: 1)
                    )
            )
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Critical Action Button
struct CriticalActionButton: View {
    let title: String
    let icon: String
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Image(systemName: icon)
                    .font(.caption)
                
                Text(title)
                    .font(.caption2)
                    .fontWeight(.semibold)
            }
            .foregroundColor(.white)
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(color.opacity(0.8), in: RoundedRectangle(cornerRadius: 6))
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .stroke(color, lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Detail Sheets
struct SCADASystemDetailsSheet: View {
    let system: SCADASystem
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // System Overview
                    VStack(alignment: .leading, spacing: 12) {
                        Text("System Overview")
                            .font(.headline)
                            .fontWeight(.bold)
                        
                        VStack(spacing: 8) {
                            DetailRow(label: "Name", value: system.name)
                            DetailRow(label: "Type", value: system.type.rawValue)
                            DetailRow(label: "Status", value: system.status.rawValue)
                            DetailRow(label: "Criticality", value: system.criticalityLevel.rawValue)
                            DetailRow(label: "Security Score", value: "\(Int(system.securityScore * 100))%")
                            DetailRow(label: "Last Update", value: system.lastUpdate.formatted())
                        }
                    }
                    .padding()
                    .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
                }
                .padding()
            }
            .navigationTitle(system.name)
            // .navigationBarTitleDisplayMode(.large) // Not available on macOS
            .toolbar {
                ToolbarItem(placement: .automatic) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
    }
}

struct ThreatDetailsSheet: View {
    let threat: InfrastructureThreat
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // Threat Details
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Threat Details")
                            .font(.headline)
                            .fontWeight(.bold)
                        
                        VStack(spacing: 8) {
                            DetailRow(label: "Description", value: threat.description)
                            DetailRow(label: "Severity", value: threat.severity.rawValue)
                            if let protocolName = threat.networkProtocol {
                                DetailRow(label: "Protocol", value: protocolName)
                            }
                            DetailRow(label: "Timestamp", value: threat.timestamp.formatted())
                            DetailRow(label: "Mitigation", value: threat.mitigationSuggestion)
                        }
                    }
                    .padding()
                    .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
                }
                .padding()
            }
            .navigationTitle("Threat Analysis")
            // .navigationBarTitleDisplayMode(.large) // Not available on macOS
            .toolbar {
                ToolbarItem(placement: .automatic) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
    }
}


struct DetailRow: View {
    let label: String
    let value: String
    
    var body: some View {
        HStack {
            Text(label)
                .font(.subheadline)
                .foregroundColor(.secondary)
            
            Spacer()
            
            Text(value)
                .font(.subheadline)
                .fontWeight(.medium)
                .multilineTextAlignment(.trailing)
        }
    }
}

struct CriticalInfrastructureView_Previews: PreviewProvider {
    static var previews: some View {
        CriticalInfrastructureView()
    }
}

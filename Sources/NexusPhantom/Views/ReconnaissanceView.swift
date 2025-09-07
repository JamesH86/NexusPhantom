import SwiftUI
import Combine

struct ReconnaissanceView: View {
    @EnvironmentObject var toolRunner: ToolRunner
    @EnvironmentObject var aiOrchestrator: AIOrchestrator
    @EnvironmentObject var voiceManager: VoiceManager
    
    @State private var targetInput = ""
    @State private var selectedScanType: ScanType = .comprehensive
    @State private var isScanning = false
    @State private var discoveredHosts: [DiscoveredHost] = []
    @State private var openPorts: [PortScan] = []
    @State private var subdomains: [String] = []
    @State private var technologies: [TechStack] = []
    @State private var osFingerprints: [OSFingerprint] = []
    
    enum ScanType: String, CaseIterable {
        case quick = "Quick Scan"
        case comprehensive = "Comprehensive"
        case stealth = "Stealth Mode"
        case aggressive = "Aggressive"
        case custom = "Custom"
    }
    
    var body: some View {
        VStack(spacing: 0) {
            // Header with target input
            ReconHeader(
                targetInput: $targetInput,
                selectedScanType: $selectedScanType,
                isScanning: $isScanning
            ) {
                Task {
                    await startReconnaissance()
                }
            }
            
            Divider()
            
            // Main recon interface
            HStack(spacing: 0) {
                // Left panel - Network discovery
                VStack {
                    NetworkDiscoveryPanel(discoveredHosts: discoveredHosts)
                    PortScanPanel(openPorts: openPorts)
                }
                .frame(width: 400)
                
                Divider()
                
                // Center panel - Subdomain enumeration
                VStack {
                    SubdomainPanel(subdomains: subdomains)
                    TechnologyPanel(technologies: technologies)
                }
                .frame(maxWidth: .infinity)
                
                Divider()
                
                // Right panel - OS fingerprinting and analysis
                VStack {
                    OSFingerprintPanel(fingerprints: osFingerprints)
                    ReconActionsPanel()
                }
                .frame(width: 350)
            }
        }
        .navigationTitle("NEXUS PHANTOM - Reconnaissance")
        .onAppear {
            voiceManager.speak("Reconnaissance module activated. Ready for network discovery operations.")
        }
    }
    
    private func startReconnaissance() async {
        guard !targetInput.isEmpty else { return }
        
        isScanning = true
        voiceManager.speak("Initiating reconnaissance operations on \(targetInput)")
        
        // Clear previous results
        discoveredHosts.removeAll()
        openPorts.removeAll()
        subdomains.removeAll()
        technologies.removeAll()
        osFingerprints.removeAll()
        
        // Execute reconnaissance workflow based on scan type
        switch selectedScanType {
        case .quick:
            await performQuickRecon()
        case .comprehensive:
            await performComprehensiveRecon()
        case .stealth:
            await performStealthRecon()
        case .aggressive:
            await performAggressiveRecon()
        case .custom:
            await performCustomRecon()
        }
        
        isScanning = false
        voiceManager.speak("Reconnaissance completed. Discovered \(discoveredHosts.count) hosts and \(subdomains.count) subdomains.")
    }
    
    private func performQuickRecon() async {
        // Quick network discovery
        await performPingSweep()
        await performBasicPortScan()
        await performSubdomainEnum()
    }
    
    private func performComprehensiveRecon() async {
        // Full reconnaissance workflow
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.performPingSweep() }
            group.addTask { await self.performFullPortScan() }
            group.addTask { await self.performSubdomainEnum() }
            group.addTask { await self.performServiceDetection() }
            group.addTask { await self.performOSFingerprinting() }
            group.addTask { await self.performTechnologyDetection() }
        }
    }
    
    private func performStealthRecon() async {
        // Stealth reconnaissance with timing delays
        await performStealthPingSweep()
        await performStealthPortScan()
        await performPassiveSubdomainEnum()
    }
    
    private func performAggressiveRecon() async {
        // Aggressive scanning with all techniques
        await performComprehensiveRecon()
        await performVulnerabilityScanning()
        await performWebCrawling()
    }
    
    private func performCustomRecon() async {
        // Custom reconnaissance based on AI recommendations
        let context = CyberSecurityContext(
            domain: .osint,
            target: targetInput,
            urgency: .normal,
            isVoiceCommand: false,
            requiredActions: [],
            userPermissions: [.networkScanning]
        )
        
        let query = "Generate custom reconnaissance strategy for \(targetInput)"
        let aiResponse = await aiOrchestrator.processQuery(query, context: context)
        
        // Execute AI-recommended reconnaissance steps
        await executeAIReconPlan(aiResponse)
    }
    
    // MARK: - Reconnaissance Methods
    
    private func performPingSweep() async {
        let command = "/usr/local/bin/nmap -sn \(targetInput)"
        let result = await toolRunner.executeToolCommand(command, toolName: "nmap")
        
        if result.isSuccess {
            let hosts = parseNmapHosts(result.output)
            discoveredHosts.append(contentsOf: hosts)
        }
    }
    
    private func performBasicPortScan() async {
        let command = "/usr/local/bin/nmap -F \(targetInput)"
        let result = await toolRunner.executeToolCommand(command, toolName: "nmap")
        
        if result.isSuccess {
            let ports = parseNmapPorts(result.output)
            openPorts.append(contentsOf: ports)
        }
    }
    
    private func performFullPortScan() async {
        let command = "/usr/local/bin/nmap -p- -sS \(targetInput)"
        let result = await toolRunner.executeToolCommand(command, toolName: "nmap")
        
        if result.isSuccess {
            let ports = parseNmapPorts(result.output)
            openPorts.append(contentsOf: ports)
        }
    }
    
    private func performSubdomainEnum() async {
        // Use multiple subdomain enumeration tools
        let tools = [
            ("subfinder", "/usr/local/bin/subfinder -d \(targetInput) -json"),
            ("amass", "/usr/local/bin/amass enum -d \(targetInput)"),
            ("assetfinder", "/usr/local/bin/assetfinder \(targetInput)")
        ]
        
        for (toolName, command) in tools {
            let result = await toolRunner.executeToolCommand(command, toolName: toolName)
            if result.isSuccess {
                let foundSubdomains = parseSubdomains(result.output, tool: toolName)
                subdomains.append(contentsOf: foundSubdomains)
            }
        }
        
        // Remove duplicates
        subdomains = Array(Set(subdomains))
    }
    
    private func performServiceDetection() async {
        let command = "/usr/local/bin/nmap -sV \(targetInput)"
        let result = await toolRunner.executeToolCommand(command, toolName: "nmap")
        
        if result.isSuccess {
            let services = parseNmapServices(result.output)
            // Update discovered hosts with service information
        }
    }
    
    private func performOSFingerprinting() async {
        let command = "/usr/local/bin/nmap -O \(targetInput)"
        let result = await toolRunner.executeToolCommand(command, toolName: "nmap")
        
        if result.isSuccess {
            let fingerprints = parseOSFingerprints(result.output)
            osFingerprints.append(contentsOf: fingerprints)
        }
    }
    
    private func performTechnologyDetection() async {
        let whatwebCommand = "/usr/local/bin/whatweb \(targetInput) --log-json=/tmp/whatweb_output.json"
        let result = await toolRunner.executeToolCommand(whatwebCommand, toolName: "whatweb")
        
        if result.isSuccess {
            let techs = parseTechnologies(result.output)
            technologies.append(contentsOf: techs)
        }
    }
    
    private func performStealthPingSweep() async {
        let command = "/usr/local/bin/nmap -sn -T1 \(targetInput)"
        await toolRunner.executeToolCommand(command, toolName: "nmap")
    }
    
    private func performStealthPortScan() async {
        let command = "/usr/local/bin/nmap -sS -T1 -f \(targetInput)"
        await toolRunner.executeToolCommand(command, toolName: "nmap")
    }
    
    private func performPassiveSubdomainEnum() async {
        // Use passive techniques only
        let command = "/usr/local/bin/subfinder -d \(targetInput) -passive"
        await toolRunner.executeToolCommand(command, toolName: "subfinder")
    }
    
    private func performVulnerabilityScanning() async {
        let command = "/usr/local/bin/nmap --script vuln \(targetInput)"
        await toolRunner.executeToolCommand(command, toolName: "nmap")
    }
    
    private func performWebCrawling() async {
        let command = "/usr/local/bin/gobuster dir -u http://\(targetInput) -w /usr/share/wordlists/common.txt"
        await toolRunner.executeToolCommand(command, toolName: "gobuster")
    }
    
    private func executeAIReconPlan(_ response: AIResponse) async {
        // Execute AI-generated reconnaissance plan
        for action in response.actions {
            if case .scan(let tool) = action.type {
                await toolRunner.runTool(tool)
            }
        }
    }
    
    // MARK: - Parsing Methods
    
    private func parseNmapHosts(_ output: String) -> [DiscoveredHost] {
        var hosts: [DiscoveredHost] = []
        let lines = output.components(separatedBy: .newlines)
        
        for line in lines {
            if line.contains("Nmap scan report for") {
                let components = line.components(separatedBy: " ")
                if let hostInfo = components.last {
                    let host = DiscoveredHost(
                        ip: hostInfo,
                        hostname: nil,
                        status: "up",
                        lastSeen: Date()
                    )
                    hosts.append(host)
                }
            }
        }
        
        return hosts
    }
    
    private func parseNmapPorts(_ output: String) -> [PortScan] {
        var ports: [PortScan] = []
        let lines = output.components(separatedBy: .newlines)
        
        for line in lines {
            if line.contains("/tcp") || line.contains("/udp") {
                let components = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
                if components.count >= 3 {
                    let portInfo = components[0]
                    let state = components[1]
                    let service = components[2]
                    
                    if let port = Int(portInfo.components(separatedBy: "/").first ?? "") {
                        let portScan = PortScan(
                            port: port,
                            `protocol`: portInfo.contains("tcp") ? "TCP" : "UDP",
                            state: state,
                            service: service,
                            version: nil
                        )
                        ports.append(portScan)
                    }
                }
            }
        }
        
        return ports
    }
    
    private func parseSubdomains(_ output: String, tool: String) -> [String] {
        if tool == "subfinder" {
            // Parse JSON output from subfinder
            if let data = output.data(using: .utf8),
               let json = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] {
                return json.compactMap { $0["host"] as? String }
            }
        }
        
        // Fallback to line-by-line parsing
        return output.components(separatedBy: .newlines)
            .filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
    }
    
    private func parseNmapServices(_ output: String) -> [NetworkService] {
        // Parse nmap service detection output
        return []
    }
    
    private func parseOSFingerprints(_ output: String) -> [OSFingerprint] {
        var fingerprints: [OSFingerprint] = []
        let lines = output.components(separatedBy: .newlines)
        
        for line in lines {
            if line.contains("OS details:") {
                let osInfo = line.replacingOccurrences(of: "OS details: ", with: "")
                let fingerprint = OSFingerprint(
                    target: targetInput,
                    osDetails: osInfo,
                    confidence: 0.8,
                    method: "nmap"
                )
                fingerprints.append(fingerprint)
            }
        }
        
        return fingerprints
    }
    
    private func parseTechnologies(_ output: String) -> [TechStack] {
        // Parse technology detection output
        return []
    }
}

// MARK: - Reconnaissance Components

struct ReconHeader: View {
    @Binding var targetInput: String
    @Binding var selectedScanType: ReconnaissanceView.ScanType
    @Binding var isScanning: Bool
    let startAction: () -> Void
    
    var body: some View {
        HStack {
            VStack(alignment: .leading) {
                Text("Reconnaissance Target")
                    .font(.headline)
                    .fontWeight(.bold)
                
                HStack {
                    TextField("Enter target (IP, domain, or CIDR)", text: $targetInput)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 300)
                    
                    Picker("Scan Type", selection: $selectedScanType) {
                        ForEach(ReconnaissanceView.ScanType.allCases, id: \.self) { type in
                            Text(type.rawValue).tag(type)
                        }
                    }
                    .frame(width: 150)
                }
            }
            
            Spacer()
            
            Button(action: startAction) {
                HStack {
                    if isScanning {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                            .scaleEffect(0.8)
                    }
                    
                    Text(isScanning ? "Scanning..." : "Start Reconnaissance")
                        .fontWeight(.semibold)
                }
                .foregroundColor(.white)
                .padding(.horizontal, 20)
                .padding(.vertical, 10)
                .background(isScanning ? Color.orange : Color.blue, in: RoundedRectangle(cornerRadius: 8))
            }
            .disabled(isScanning || targetInput.isEmpty)
        }
        .padding()
        .background(.regularMaterial)
    }
}

struct NetworkDiscoveryPanel: View {
    let discoveredHosts: [DiscoveredHost]
    
    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Discovered Hosts")
                    .font(.headline)
                    .fontWeight(.bold)
                
                Spacer()
                
                Text("\(discoveredHosts.count)")
                    .font(.title2)
                    .fontWeight(.bold)
                    .foregroundColor(.green)
            }
            
            List(discoveredHosts) { host in
                HostRow(host: host)
            }
            .listStyle(.plain)
        }
        .padding()
    }
}

struct HostRow: View {
    let host: DiscoveredHost
    
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(host.ip)
                    .font(.body)
                    .fontWeight(.medium)
                    .foregroundColor(.primary)
                
                if let hostname = host.hostname {
                    Text(hostname)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            
            Spacer()
            
            VStack(alignment: .trailing) {
                Text(host.status)
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(host.status == "up" ? .green : .red)
                
                Text(host.lastSeen.formatted(.relative(presentation: .named)))
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

struct PortScanPanel: View {
    let openPorts: [PortScan]
    
    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Open Ports")
                    .font(.headline)
                    .fontWeight(.bold)
                
                Spacer()
                
                Text("\(openPorts.count)")
                    .font(.title2)
                    .fontWeight(.bold)
                    .foregroundColor(.orange)
            }
            
            List(openPorts) { port in
                PortRow(port: port)
            }
            .listStyle(.plain)
        }
        .padding()
    }
}

struct PortRow: View {
    let port: PortScan
    
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("\(port.port)/\(port.`protocol`)")
                    .font(.body)
                    .fontWeight(.medium)
                    .foregroundColor(.primary)
                
                Text(port.service)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
            
            VStack(alignment: .trailing) {
                Text(port.state)
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(.green)
                
                if let version = port.version {
                    Text(version)
                        .font(.caption)
                        .foregroundColor(.blue)
                }
            }
        }
        .padding(.vertical, 2)
    }
}

struct SubdomainPanel: View {
    let subdomains: [String]
    
    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Subdomains")
                    .font(.headline)
                    .fontWeight(.bold)
                
                Spacer()
                
                Text("\(subdomains.count)")
                    .font(.title2)
                    .fontWeight(.bold)
                    .foregroundColor(.purple)
            }
            
            List(subdomains, id: \.self) { subdomain in
                Text(subdomain)
                    .font(.body)
                    .padding(.vertical, 2)
            }
            .listStyle(.plain)
        }
        .padding()
    }
}

struct TechnologyPanel: View {
    let technologies: [TechStack]
    
    var body: some View {
        VStack(alignment: .leading) {
            Text("Technology Stack")
                .font(.headline)
                .fontWeight(.bold)
            
            // Technology detection results
            if technologies.isEmpty {
                Text("No technologies detected")
                    .foregroundColor(.secondary)
                    .italic()
            } else {
                ForEach(technologies) { tech in
                    TechRow(technology: tech)
                }
            }
        }
        .padding()
    }
}

struct TechRow: View {
    let technology: TechStack
    
    var body: some View {
        HStack {
            Text(technology.name)
                .font(.body)
                .fontWeight(.medium)
            
            Spacer()
            
            if let version = technology.version {
                Text(version)
                    .font(.caption)
                    .foregroundColor(.blue)
            }
        }
        .padding(.vertical, 2)
    }
}

struct OSFingerprintPanel: View {
    let fingerprints: [OSFingerprint]
    
    var body: some View {
        VStack(alignment: .leading) {
            Text("OS Fingerprinting")
                .font(.headline)
                .fontWeight(.bold)
            
            ForEach(fingerprints) { fingerprint in
                OSFingerprintRow(fingerprint: fingerprint)
            }
            
            if fingerprints.isEmpty {
                Text("No OS fingerprints available")
                    .foregroundColor(.secondary)
                    .italic()
            }
        }
        .padding()
    }
}

struct OSFingerprintRow: View {
    let fingerprint: OSFingerprint
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(fingerprint.osDetails)
                .font(.body)
                .fontWeight(.medium)
            
            Text("Confidence: \(fingerprint.confidence * 100, specifier: "%.0f")%")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding(.vertical, 4)
    }
}

struct ReconActionsPanel: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Quick Actions")
                .font(.headline)
                .fontWeight(.bold)
            
            Button("Export Results") {
                // Export reconnaissance results
            }
            .buttonStyle(.borderedProminent)
            
            Button("Generate Report") {
                // Generate reconnaissance report
            }
            .buttonStyle(.bordered)
            
            Button("Continue to Exploitation") {
                // Move to exploitation phase
            }
            .buttonStyle(.bordered)
        }
        .padding()
    }
}

// MARK: - Data Models

struct DiscoveredHost: Identifiable {
    let id = UUID()
    let ip: String
    let hostname: String?
    let status: String
    let lastSeen: Date
    var openPorts: [Int] = []
    var services: [String] = []
    var osGuess: String?
}

struct PortScan: Identifiable {
    let id = UUID()
    let port: Int
    let `protocol`: String
    let state: String
    let service: String
    let version: String?
    let target: String = ""
}

struct TechStack: Identifiable {
    let id = UUID()
    let name: String
    let version: String?
    let confidence: Double
    let target: String
}

struct OSFingerprint: Identifiable {
    let id = UUID()
    let target: String
    let osDetails: String
    let confidence: Double
    let method: String
    let timestamp = Date()
}

struct NetworkService: Identifiable {
    let id = UUID()
    let port: Int
    let service: String
    let version: String?
    let state: String
    let `protocol`: String
}


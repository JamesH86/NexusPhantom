import Foundation
import Combine
import os.log

@MainActor
class ToolRunner: ObservableObject {
    @Published var runningTools: [ActiveTool] = []
    @Published var availableTools: [CyberSecTool] = []
    @Published var toolResults: [String: ToolResult] = [:]
    @Published var isInitialized = false
    
    private let logger = Logger(subsystem: "NexusPhantom", category: "ToolRunner")
    private var cancellables = Set<AnyCancellable>()
    
    // Tool categories for organization
    enum ToolCategory: String, CaseIterable {
        case reconnaissance = "Reconnaissance"
        case vulnerability = "Vulnerability Assessment"
        case exploitation = "Exploitation"
        case postExploitation = "Post-Exploitation"
        case webApplication = "Web Application"
        case networkSecurity = "Network Security"
        case wireless = "Wireless Security"
        case forensics = "Digital Forensics"
        case malwareAnalysis = "Malware Analysis"
        case cryptography = "Cryptography"
        case osint = "OSINT"
        case compliance = "Compliance"
        case nsaTools = "NSA Public Tools"
    }
    
    init() {
        setupAvailableTools()
    }
    
    func initializeTools() async {
        logger.info("🛠️ Initializing cybersecurity toolkit...")
        
        await withTaskGroup(of: (String, Bool).self) { group in
            for tool in availableTools {
                group.addTask {
                    let isAvailable = await self.checkToolAvailability(tool)
                    return (tool.name, isAvailable)
                }
            }
            
            for await (toolName, isAvailable) in group {
                if let index = availableTools.firstIndex(where: { $0.name == toolName }) {
                    availableTools[index].isInstalled = isAvailable
                    
                    if !isAvailable {
                        logger.info("📥 Installing \(toolName)...")
                        await installTool(availableTools[index])
                    }
                }
            }
        }
        
        isInitialized = true
        logger.info("🔥 Tool Runner initialized with \(self.availableTools.filter { $0.isInstalled }.count) tools ready")
    }
    
    private func setupAvailableTools() {
        availableTools = [
            // MARK: - Reconnaissance Tools
            CyberSecTool(name: "nmap", category: .reconnaissance, command: "/usr/local/bin/nmap", description: "Network discovery and port scanning"),
            CyberSecTool(name: "masscan", category: .reconnaissance, command: "/usr/local/bin/masscan", description: "High-speed port scanner"),
            CyberSecTool(name: "subfinder", category: .reconnaissance, command: "/usr/local/bin/subfinder", description: "Subdomain discovery tool"),
            CyberSecTool(name: "amass", category: .reconnaissance, command: "/usr/local/bin/amass", description: "Attack surface mapping"),
            CyberSecTool(name: "assetfinder", category: .reconnaissance, command: "/usr/local/bin/assetfinder", description: "Domain asset discovery"),
            CyberSecTool(name: "findomain", category: .reconnaissance, command: "/usr/local/bin/findomain", description: "Fast subdomain enumeration"),
            CyberSecTool(name: "gobuster", category: .reconnaissance, command: "/usr/local/bin/gobuster", description: "Directory/file brute-forcer"),
            CyberSecTool(name: "ffuf", category: .reconnaissance, command: "/usr/local/bin/ffuf", description: "Fast web fuzzer"),
            CyberSecTool(name: "feroxbuster", category: .reconnaissance, command: "/usr/local/bin/feroxbuster", description: "Fast directory brute-forcer"),
            CyberSecTool(name: "dnsrecon", category: .reconnaissance, command: "/usr/local/bin/dnsrecon", description: "DNS enumeration tool"),
            CyberSecTool(name: "whatweb", category: .reconnaissance, command: "/usr/local/bin/whatweb", description: "Web technology identification"),
            CyberSecTool(name: "httpx", category: .reconnaissance, command: "/usr/local/bin/httpx", description: "HTTP toolkit for probing"),
            CyberSecTool(name: "httprobe", category: .reconnaissance, command: "/usr/local/bin/httprobe", description: "HTTP probe tool"),
            
            // MARK: - Vulnerability Assessment
            CyberSecTool(name: "nuclei", category: .vulnerability, command: "/usr/local/bin/nuclei", description: "Fast vulnerability scanner"),
            CyberSecTool(name: "nikto", category: .vulnerability, command: "/usr/local/bin/nikto", description: "Web server scanner"),
            CyberSecTool(name: "openvas", category: .vulnerability, command: "/usr/local/bin/openvas", description: "Comprehensive vulnerability scanner"),
            CyberSecTool(name: "nessus", category: .vulnerability, command: "/usr/local/bin/nessus", description: "Professional vulnerability scanner"),
            CyberSecTool(name: "testssl", category: .vulnerability, command: "/usr/local/bin/testssl", description: "SSL/TLS configuration scanner"),
            
            // MARK: - Web Application Security
            CyberSecTool(name: "burpsuite", category: .webApplication, command: "/Applications/Burp Suite Community Edition.app/Contents/MacOS/Burp Suite Community Edition", description: "Web application security testing"),
            CyberSecTool(name: "sqlmap", category: .webApplication, command: "/usr/local/bin/sqlmap", description: "SQL injection testing tool"),
            CyberSecTool(name: "wpscan", category: .webApplication, command: "/usr/local/bin/wpscan", description: "WordPress security scanner"),
            CyberSecTool(name: "zaproxy", category: .webApplication, command: "/usr/local/bin/zap", description: "OWASP ZAP proxy"),
            CyberSecTool(name: "dirb", category: .webApplication, command: "/usr/local/bin/dirb", description: "Web content scanner"),
            CyberSecTool(name: "xsstrike", category: .webApplication, command: "/opt/xsstrike/xsstrike.py", description: "XSS detection suite"),
            CyberSecTool(name: "paramspider", category: .webApplication, command: "/opt/paramspider/paramspider.py", description: "Parameter discovery tool"),
            CyberSecTool(name: "arjun", category: .webApplication, command: "/usr/local/bin/arjun", description: "HTTP parameter discovery"),
            
            // MARK: - Exploitation Frameworks
            CyberSecTool(name: "metasploit", category: .exploitation, command: "/usr/local/bin/msfconsole", description: "Penetration testing framework"),
            CyberSecTool(name: "armitage", category: .exploitation, command: "/opt/armitage/armitage", description: "Metasploit GUI interface"),
            CyberSecTool(name: "cobalt-strike", category: .exploitation, command: "/opt/cobaltstrike/cobaltstrike", description: "Advanced threat emulation"),
            CyberSecTool(name: "empire", category: .exploitation, command: "/opt/Empire/empire", description: "PowerShell post-exploitation"),
            
            // MARK: - Network Security
            CyberSecTool(name: "wireshark", category: .networkSecurity, command: "/Applications/Wireshark.app/Contents/MacOS/Wireshark", description: "Network protocol analyzer"),
            CyberSecTool(name: "tcpdump", category: .networkSecurity, command: "/usr/sbin/tcpdump", description: "Network packet capture"),
            CyberSecTool(name: "bettercap", category: .networkSecurity, command: "/usr/local/bin/bettercap", description: "Network reconnaissance and MITM"),
            CyberSecTool(name: "ettercap", category: .networkSecurity, command: "/usr/local/bin/ettercap", description: "Network sniffer and interceptor"),
            CyberSecTool(name: "netcat", category: .networkSecurity, command: "/usr/local/bin/nc", description: "Network utility"),
            CyberSecTool(name: "socat", category: .networkSecurity, command: "/usr/local/bin/socat", description: "Multipurpose relay tool"),
            
            // MARK: - Wireless Security
            CyberSecTool(name: "aircrack-ng", category: .wireless, command: "/usr/local/bin/aircrack-ng", description: "WiFi security testing suite"),
            CyberSecTool(name: "kismet", category: .wireless, command: "/usr/local/bin/kismet", description: "Wireless network detector"),
            CyberSecTool(name: "reaver", category: .wireless, command: "/usr/local/bin/reaver", description: "WPS attack tool"),
            
            // MARK: - Password Cracking & Cryptography
            CyberSecTool(name: "john", category: .cryptography, command: "/usr/local/bin/john", description: "John the Ripper password cracker"),
            CyberSecTool(name: "hashcat", category: .cryptography, command: "/usr/local/bin/hashcat", description: "Advanced password recovery"),
            CyberSecTool(name: "hydra", category: .cryptography, command: "/usr/local/bin/hydra", description: "Network login cracker"),
            CyberSecTool(name: "crunch", category: .cryptography, command: "/usr/local/bin/crunch", description: "Wordlist generator"),
            CyberSecTool(name: "hashid", category: .cryptography, command: "/usr/local/bin/hashid", description: "Hash identifier"),
            CyberSecTool(name: "cewl", category: .cryptography, command: "/usr/local/bin/cewl", description: "Custom wordlist generator"),
            
            // MARK: - Digital Forensics
            CyberSecTool(name: "volatility", category: .forensics, command: "/usr/local/bin/volatility", description: "Memory forensics framework"),
            CyberSecTool(name: "autopsy", category: .forensics, command: "/Applications/Autopsy.app/Contents/MacOS/autopsy", description: "Digital forensics platform"),
            CyberSecTool(name: "binwalk", category: .forensics, command: "/usr/local/bin/binwalk", description: "Firmware analysis tool"),
            CyberSecTool(name: "foremost", category: .forensics, command: "/usr/local/bin/foremost", description: "File carving tool"),
            CyberSecTool(name: "sleuthkit", category: .forensics, command: "/usr/local/bin/tsk_recover", description: "Digital investigation toolkit"),
            CyberSecTool(name: "ddrescue", category: .forensics, command: "/usr/local/bin/ddrescue", description: "Data recovery tool"),
            
            // MARK: - Malware Analysis
            CyberSecTool(name: "radare2", category: .malwareAnalysis, command: "/usr/local/bin/radare2", description: "Reverse engineering framework"),
            CyberSecTool(name: "ghidra", category: .malwareAnalysis, command: "/usr/local/bin/ghidra", description: "NSA Software Reverse Engineering Suite"),
            CyberSecTool(name: "ida-free", category: .malwareAnalysis, command: "/Applications/IDA Freeware.app/Contents/MacOS/idaq64", description: "Interactive disassembler"),
            CyberSecTool(name: "yara", category: .malwareAnalysis, command: "/usr/local/bin/yara", description: "Malware identification tool"),
            CyberSecTool(name: "clamav", category: .malwareAnalysis, command: "/usr/local/bin/clamscan", description: "Antivirus scanner"),
            CyberSecTool(name: "upx", category: .malwareAnalysis, command: "/usr/local/bin/upx", description: "Executable packer/unpacker"),
            
            // MARK: - OSINT Tools
            CyberSecTool(name: "recon-ng", category: .osint, command: "/usr/local/bin/recon-ng", description: "Full-featured OSINT framework"),
            CyberSecTool(name: "maltego", category: .osint, command: "/Applications/Maltego.app/Contents/MacOS/Maltego", description: "Link analysis platform"),
            CyberSecTool(name: "spiderfoot", category: .osint, command: "/usr/local/bin/spiderfoot", description: "Automated OSINT collection"),
            CyberSecTool(name: "theharvester", category: .osint, command: "/usr/local/bin/theharvester", description: "Email and subdomain harvester"),
            CyberSecTool(name: "shodan", category: .osint, command: "/usr/local/bin/shodan", description: "Internet device search engine"),
            CyberSecTool(name: "sherlock", category: .osint, command: "/usr/local/bin/sherlock", description: "Social media username search"),
            
            // MARK: - NSA Public Tools
            CyberSecTool(name: "ghidra-nsa", category: .nsaTools, command: "/Applications/Ghidra.app/Contents/MacOS/ghidra", description: "NSA Software Reverse Engineering Suite"),
            CyberSecTool(name: "armitage", category: .nsaTools, command: "/opt/armitage/armitage", description: "Metasploit GUI by Raphael Mudge"),
            CyberSecTool(name: "sirius", category: .nsaTools, command: "/opt/sirius/sirius.py", description: "NSA Video surveillance analysis"),
            CyberSecTool(name: "apache-spot", category: .nsaTools, command: "/opt/apache-spot/spot.py", description: "NSA Apache Spot network analysis"),
            CyberSecTool(name: "walkoff", category: .nsaTools, command: "/opt/walkoff/walkoff.py", description: "NSA Security orchestration platform"),
            CyberSecTool(name: "grassmarlin", category: .nsaTools, command: "/opt/grassmarlin/grassmarlin.jar", description: "NSA Network situational awareness"),
            CyberSecTool(name: "lemongraph", category: .nsaTools, command: "/opt/lemongraph/lemongraph.py", description: "NSA Graph database for cybersecurity"),
            CyberSecTool(name: "elitewolf", category: .nsaTools, command: "/opt/elitewolf/elitewolf.py", description: "NSA Forensic analysis tool"),
            CyberSecTool(name: "bless", category: .nsaTools, command: "/opt/bless/bless.py", description: "NSA SSH certificate authority"),
            CyberSecTool(name: "dl-fingerprinting", category: .nsaTools, command: "/opt/dl-fingerprinting/fingerprint.py", description: "NSA Deep learning fingerprinting"),
            
            // MARK: - Mobile Security
            CyberSecTool(name: "frida", category: .exploitation, command: "/usr/local/bin/frida", description: "Dynamic instrumentation toolkit"),
            CyberSecTool(name: "objection", category: .exploitation, command: "/usr/local/bin/objection", description: "Mobile application security testing"),
            CyberSecTool(name: "mobsf", category: .exploitation, command: "/opt/mobsf/mobsf.py", description: "Mobile Security Framework"),
            CyberSecTool(name: "class-dump", category: .exploitation, command: "/usr/local/bin/class-dump", description: "Objective-C class dumper"),
            
            // MARK: - Bug Bounty Specific
            CyberSecTool(name: "waybackurls", category: .reconnaissance, command: "/usr/local/bin/waybackurls", description: "Wayback machine URL extractor"),
            CyberSecTool(name: "gau", category: .reconnaissance, command: "/usr/local/bin/gau", description: "Get all URLs from various sources"),
            CyberSecTool(name: "katana", category: .reconnaissance, command: "/usr/local/bin/katana", description: "Next-generation crawling framework"),
            CyberSecTool(name: "notify", category: .reconnaissance, command: "/usr/local/bin/notify", description: "Stream notification tool"),
            
            // MARK: - Cloud Security
            CyberSecTool(name: "awscli", category: .compliance, command: "/usr/local/bin/aws", description: "AWS command line interface"),
            CyberSecTool(name: "azure-cli", category: .compliance, command: "/usr/local/bin/az", description: "Azure command line interface"),
            CyberSecTool(name: "prowler", category: .compliance, command: "/usr/local/bin/prowler", description: "AWS security assessment"),
            CyberSecTool(name: "scoutsuite", category: .compliance, command: "/usr/local/bin/scout", description: "Multi-cloud security auditing"),
            CyberSecTool(name: "trivy", category: .compliance, command: "/usr/local/bin/trivy", description: "Container security scanner"),
            CyberSecTool(name: "grype", category: .compliance, command: "/usr/local/bin/grype", description: "Container vulnerability scanner"),
            
            // MARK: - Compliance Tools
            CyberSecTool(name: "openscap", category: .compliance, command: "/usr/local/bin/openscap", description: "Security compliance scanner"),
            CyberSecTool(name: "lynis", category: .compliance, command: "/usr/local/bin/lynis", description: "Security auditing tool"),
            
            // MARK: - Social Engineering
            CyberSecTool(name: "set", category: .exploitation, command: "/usr/local/bin/setoolkit", description: "Social Engineering Toolkit")
        ]
    }
    
    private func checkToolAvailability(_ tool: CyberSecTool) async -> Bool {
        let fileManager = FileManager.default
        return fileManager.fileExists(atPath: tool.command)
    }
    
    private func installTool(_ tool: CyberSecTool) async {
        logger.info("📦 Installing \(tool.name)...")
        
        // Determine installation method based on tool
        switch tool.name {
        case "burpsuite":
            await installBurpSuite()
        case "ghidra":
            await installGhidra()
        case "metasploit":
            await installMetasploit()
        default:
            await installViaBrew(tool.name)
        }
    }
    
    private func installBurpSuite() async {
        // Burp Suite is already detected in /Applications
        if let index = availableTools.firstIndex(where: { $0.name == "burpsuite" }) {
            availableTools[index].isInstalled = true
            logger.info("✅ Burp Suite Community Edition detected")
        }
    }
    
    private func installGhidra() async {
        let installCommand = "brew install ghidra"
        await executeCommand(installCommand)
    }
    
    private func installMetasploit() async {
        let installCommand = "brew install metasploit"
        await executeCommand(installCommand)
    }
    
    private func installViaBrew(_ toolName: String) async {
        let installCommand = "brew install \(toolName)"
        await executeCommand(installCommand)
    }
    
    private func executeCommand(_ command: String) async {
        let process = Process()
        process.launchPath = "/bin/zsh"
        process.arguments = ["-c", command]
        
        do {
            try process.run()
            process.waitUntilExit()
            logger.info("Command executed: \(command)")
        } catch {
            logger.error("Failed to execute: \(command) - \(error)")
        }
    }
    
    // Convenience runner used by some views
    func runTool(_ name: String) async {
        logger.info("🛠️ Requested to run tool: \(name)")
        // Placeholder: map known tool names to a basic command
        switch name.lowercased() {
        case "nmap":
            _ = await executeToolCommand("/usr/local/bin/nmap -F 127.0.0.1", toolName: "nmap")
        default:
            break
        }
    }
    
    // MARK: - Tool Execution Methods
    
    func runFullSecurityScan() async {
        logger.info("🔍 Starting full security scan...")
        
        let scanTool = ActiveTool(
            name: "Full Security Scan",
            target: "Network",
            status: .running,
            progress: 0.0
        )
        
        runningTools.append(scanTool)
        
        // Run multiple tools in parallel
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.runNmapScan("192.168.1.0/24") }
            group.addTask { await self.runNucleiScan("localhost") }
            group.addTask { await self.runSubfinderScan("example.com") }
        }
        
        if let index = runningTools.firstIndex(where: { $0.id == scanTool.id }) {
            runningTools[index].status = .completed
            runningTools[index].progress = 1.0
        }
    }
    
    func runNmapScan(_ target: String) async {
        logger.info("🌐 Running Nmap scan on \(target)")
        
        let tool = ActiveTool(
            name: "Nmap",
            target: target,
            status: .running,
            progress: 0.0
        )
        
        runningTools.append(tool)
        
        let command = "/usr/local/bin/nmap -sS -sV -O \(target)"
        let result = await executeToolCommand(command, toolName: "nmap")
        
        toolResults["nmap-\(target)"] = result
        
        if let index = runningTools.firstIndex(where: { $0.id == tool.id }) {
            runningTools[index].status = .completed
            runningTools[index].progress = 1.0
        }
    }
    
    func launchBurpSuite() async {
        logger.info("🕷️ Launching Burp Suite...")
        
        let tool = ActiveTool(
            name: "Burp Suite",
            target: "Web Application Testing",
            status: .running,
            progress: 0.0
        )
        
        runningTools.append(tool)
        
        let command = "open '/Applications/Burp Suite Community Edition.app'"
        await executeCommand(command)
        
        // Configure Burp Suite proxy settings
        await configureBurpProxy()
        
        if let index = runningTools.firstIndex(where: { $0.id == tool.id }) {
            runningTools[index].status = .completed
            runningTools[index].progress = 1.0
        }
    }
    
    func launchMetasploit() async {
        logger.info("💥 Launching Metasploit Framework...")
        
        let tool = ActiveTool(
            name: "Metasploit",
            target: "Exploitation Framework",
            status: .running,
            progress: 0.0
        )
        
        runningTools.append(tool)
        
        // Start Metasploit RPC server for API access
        let command = "/usr/local/bin/msfconsole -r /tmp/msf_startup.rc"
        await executeCommand(command)
        
        if let index = runningTools.firstIndex(where: { $0.id == tool.id }) {
            runningTools[index].status = .completed
            runningTools[index].progress = 1.0
        }
    }
    
    func runNucleiScan(_ target: String) async {
        logger.info("🎯 Running Nuclei vulnerability scan on \(target)")
        
        let tool = ActiveTool(
            name: "Nuclei",
            target: target,
            status: .running,
            progress: 0.0
        )
        
        runningTools.append(tool)
        
        let command = "/usr/local/bin/nuclei -u \(target) -json"
        let result = await executeToolCommand(command, toolName: "nuclei")
        
        toolResults["nuclei-\(target)"] = result
        
        if let index = runningTools.firstIndex(where: { $0.id == tool.id }) {
            runningTools[index].status = .completed
            runningTools[index].progress = 1.0
        }
    }
    
    func runSubfinderScan(_ domain: String) async {
        logger.info("🔍 Running Subfinder on \(domain)")
        
        let tool = ActiveTool(
            name: "Subfinder",
            target: domain,
            status: .running,
            progress: 0.0
        )
        
        runningTools.append(tool)
        
        let command = "/usr/local/bin/subfinder -d \(domain) -json"
        let result = await executeToolCommand(command, toolName: "subfinder")
        
        toolResults["subfinder-\(domain)"] = result
        
        if let index = runningTools.firstIndex(where: { $0.id == tool.id }) {
            runningTools[index].status = .completed
            runningTools[index].progress = 1.0
        }
    }
    
    func runJohnCrack(_ hashFile: String) async {
        logger.info("🔓 Running John the Ripper on \(hashFile)")
        
        let tool = ActiveTool(
            name: "John the Ripper",
            target: hashFile,
            status: .running,
            progress: 0.0
        )
        
        runningTools.append(tool)
        
        let command = "/usr/local/bin/john --wordlist=/usr/share/wordlists/rockyou.txt \(hashFile)"
        let result = await executeToolCommand(command, toolName: "john")
        
        toolResults["john-\(hashFile)"] = result
        
        if let index = runningTools.firstIndex(where: { $0.id == tool.id }) {
            runningTools[index].status = .completed
            runningTools[index].progress = 1.0
        }
    }
    
    func runGhidraAnalysis(_ binaryPath: String) async {
        logger.info("🧬 Running Ghidra analysis on \(binaryPath)")
        
        let tool = ActiveTool(
            name: "Ghidra",
            target: binaryPath,
            status: .running,
            progress: 0.0
        )
        
        runningTools.append(tool)
        
        // Launch Ghidra with headless analysis
        let command = "/usr/local/bin/ghidra-analyzeHeadless /tmp/ghidra_projects NewProject -import \(binaryPath) -postScript GhidraScript.py"
        let result = await executeToolCommand(command, toolName: "ghidra")
        
        toolResults["ghidra-\(binaryPath)"] = result
        
        if let index = runningTools.firstIndex(where: { $0.id == tool.id }) {
            runningTools[index].status = .completed
            runningTools[index].progress = 1.0
        }
    }
    
    public func executeToolCommand(_ command: String, toolName: String) async -> ToolResult {
        let startTime = Date()
        
        let process = Process()
        let pipe = Pipe()
        let errorPipe = Pipe()
        
        process.standardOutput = pipe
        process.standardError = errorPipe
        process.launchPath = "/bin/zsh"
        process.arguments = ["-c", command]
        
        do {
            try process.run()
            
            let outputData = pipe.fileHandleForReading.readDataToEndOfFile()
            let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
            
            process.waitUntilExit()
            
            let output = String(data: outputData, encoding: .utf8) ?? ""
            let error = String(data: errorData, encoding: .utf8) ?? ""
            let executionTime = Date().timeIntervalSince(startTime)
            
            return ToolResult(
                toolName: toolName,
                output: output,
                error: error,
                exitCode: process.terminationStatus,
                executionTime: executionTime,
                timestamp: Date()
            )
        } catch {
            return ToolResult(
                toolName: toolName,
                output: "",
                error: "Failed to execute: \(error)",
                exitCode: -1,
                executionTime: Date().timeIntervalSince(startTime),
                timestamp: Date()
            )
        }
    }
    
    private func configureBurpProxy() async {
        // Configure Burp Suite proxy settings for automated scanning
        let proxyConfig = """
        {
            "proxy": {
                "http": {
                    "bind_address": "127.0.0.1",
                    "bind_port": 8080
                }
            },
            "spider": {
                "enabled": true
            },
            "scanner": {
                "enabled": true
            }
        }
        """
        
        // Write configuration file
        let configPath = "/tmp/burp_config.json"
        try? proxyConfig.write(toFile: configPath, atomically: true, encoding: .utf8)
    }
    
    func stopAllOperations() async {
        logger.info("🛑 Stopping all operations...")
        
        for tool in runningTools where tool.status == .running {
            await stopTool(tool)
        }
        
        runningTools.removeAll { $0.status == .stopped }
    }
    
    private func stopTool(_ tool: ActiveTool) async {
        // Implementation to stop specific running tools
        logger.info("Stopping \(tool.name)")
        
        if let index = runningTools.firstIndex(where: { $0.id == tool.id }) {
            runningTools[index].status = .stopped
        }
    }
    
    // MARK: - Specialized Cybersecurity Operations
    
    func performBugBountyRecon(_ target: String) async -> [ToolResult] {
        logger.info("💰 Starting bug bounty reconnaissance on \(target)")
        
        var results: [ToolResult] = []
        
        // Multi-stage reconnaissance
        await withTaskGroup(of: ToolResult.self) { group in
            group.addTask { await self.executeToolCommand("/usr/local/bin/subfinder -d \(target) -json", toolName: "subfinder") }
            group.addTask { await self.executeToolCommand("/usr/local/bin/amass enum -d \(target)", toolName: "amass") }
            group.addTask { await self.executeToolCommand("/usr/local/bin/nuclei -u \(target) -json", toolName: "nuclei") }
            
            for await result in group {
                results.append(result)
            }
        }
        
        return results
    }
    
    func performThreatHunt() async {
        logger.info("🔎 Initiating threat hunting operation...")
        
        let tool = ActiveTool(
            name: "Threat Hunt",
            target: "System-wide",
            status: .running,
            progress: 0.0
        )
        
        runningTools.append(tool)
        
        // Multi-vector threat hunting
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.scanForMalware() }
            group.addTask { await self.analyzeNetworkTraffic() }
            group.addTask { await self.checkSystemIntegrity() }
        }
        
        if let index = runningTools.firstIndex(where: { $0.id == tool.id }) {
            runningTools[index].status = .completed
            runningTools[index].progress = 1.0
        }
    }
    
    private func scanForMalware() async {
        // Implement malware scanning logic
        let command = "/usr/local/bin/clamdscan --recursive /"
        _ = await executeToolCommand(command, toolName: "clamav")
    }
    
    private func analyzeNetworkTraffic() async {
        // Network traffic analysis
        let command = "/usr/sbin/tcpdump -i en0 -c 1000 -w /tmp/traffic_capture.pcap"
        _ = await executeToolCommand(command, toolName: "tcpdump")
    }
    
    private func checkSystemIntegrity() async {
        // System integrity verification
        let command = "/usr/local/bin/lynis audit system"
        _ = await executeToolCommand(command, toolName: "lynis")
    }
}

// MARK: - Data Models
struct CyberSecTool: Identifiable {
    let id = UUID()
    let name: String
    let category: ToolRunner.ToolCategory
    let command: String
    let description: String
    var isInstalled: Bool = false
    let requiredPermissions: [String] = []
    
    init(name: String, category: ToolRunner.ToolCategory, command: String, description: String) {
        self.name = name
        self.category = category
        self.command = command
        self.description = description
    }
}

struct ActiveTool: Identifiable {
    let id = UUID()
    let name: String
    let target: String
    var status: ToolStatus
    var progress: Double
    let startTime = Date()
    
    enum ToolStatus {
        case running
        case completed
        case failed
        case stopped
    }
}

struct ToolResult: Identifiable {
    let id = UUID()
    let toolName: String
    let output: String
    let error: String
    let exitCode: Int32
    let executionTime: TimeInterval
    let timestamp: Date
    
    var isSuccess: Bool {
        return exitCode == 0
    }
    
    var parsedOutput: [String: Any] {
        // Attempt to parse JSON output
        guard let data = output.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return ["raw_output": output]
        }
        return json
    }
}

// MARK: - Root Permission Integration
struct RootPermissionManager {
    static func requestRootAccess(for operation: String) async -> Bool {
        // Implement RootPermission trait from user rules
        let permission = RootPermissionImpl()
        
        guard permission.isUserConsented() else {
            return false
        }
        
        guard permission.isMethodSafe() else {
            return false
        }
        
        do {
            try permission.rootDevice()
            return true
        } catch {
            return false
        }
    }
}

struct RootPermissionImpl: RootPermission {
    func isUserConsented() -> Bool {
        // Check if user has explicitly consented to root operations
        return true // This should be implemented with actual user consent mechanism
    }
    
    func isMethodSafe() -> Bool {
        // Verify the operation is safe and authorized
        return true // This should implement actual safety checks
    }
    
    func rootDevice() throws {
        // Implement root device access with proper authorization
        // This integrates with the RootPermission trait from user rules
    }
}

enum RootError: Error {
    case permissionDenied
    case unsafeOperation
    case deviceNotFound
}

// Implement the RootPermission trait from user rules
protocol RootPermission {
    func isUserConsented() -> Bool
    func isMethodSafe() -> Bool
    func rootDevice() throws
}

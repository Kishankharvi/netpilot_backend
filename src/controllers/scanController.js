const express = require("express")
const { v4: uuidv4 } = require("uuid")
const router = express.Router()
const Nmap = require('node-nmap');


Nmap.nmapLocation = "nmap"; 

const knownVulnerabilities = [
  // Map ports/services to known vulnerabilities 
  { port: 22, service: "ssh", name: "Open SSH Port", severity: "medium", description: "SSH service detected. Check for weak configuration." },
  { port: 21, service: "ftp", name: "Anonymous FTP Access", severity: "high", description: "FTP service detected. Check for anonymous access." },
  { port: 23, service: "telnet", name: "Default Credentials", severity: "critical", description: "Telnet service detected. Check for default credentials." },
  { port: 80, service: "http", name: "Outdated Apache Version", severity: "high", description: "HTTP service detected. Check for outdated Apache version." },
  { port: 443, service: "https", name: "Weak SSL Configuration", severity: "medium", description: "HTTPS service detected. Check for weak SSL/TLS configuration." },
 
];


//Real network scan using Nmap
const realNetworkScan = async (scanId, target, scanType) => {
  const scan = global.scans.find((s) => s.id === scanId);
  if (!scan) return;

  try {
    scan.status = "running";
    scan.currentStep = "Running Nmap scan...";
    scan.progress = 10;

    // Nmap options
    const options = {
      ports: scanType === "comprehensive" ? "1-65535" : "1-1000",
      flags: ["-sV"], // Service/version detection
    };

    const nmapScan = new Nmap.NmapScan(target, options.ports, options.flags);

    nmapScan.on('complete', function(data) {
      scan.currentStep = "Analyzing scan results...";
      scan.progress = 80;

      // Map Nmap results to vulnerabilities
      const vulnerabilities = [];
      data.forEach(host => {
        host.openPorts.forEach(portInfo => {
          const match = knownVulnerabilities.find(v =>
            v.port === portInfo.port && portInfo.service && portInfo.service.includes(v.service)
          );
          if (match) {
            vulnerabilities.push({
              ...match,
              id: uuidv4(),
              target: target,
              discoveredAt: new Date().toISOString(),
              scanType: scanType,
              port: portInfo.port,
              service: portInfo.service,
              cve: match.cve || "",
            });
          }
        });
      });

      scan.vulnerabilities = vulnerabilities;
      scan.status = "completed";
      scan.completedAt = new Date().toISOString();
      scan.currentStep = "Scan completed successfully";
      scan.duration = Math.floor((new Date() - new Date(scan.createdAt)) / 1000);

      console.log(` Real scan ${scanId} completed with ${vulnerabilities.length} vulnerabilities found`);
    });

    nmapScan.on('error', function(error) {
      scan.status = "failed";
      scan.error = error.message;
      scan.currentStep = "Scan failed";
      console.error(` Real scan ${scanId} failed:`, error);
    });

    nmapScan.startScan();
  } catch (error) {
    scan.status = "failed";
    scan.error = error.message;
    scan.currentStep = "Scan failed";
    console.error(`❌ Real scan ${scanId} failed:`, error);
  }
};


//Mock vulnerability database
// const mockVulnerabilities = [
//   {
//     name: "Open SSH Port",
//     description: "SSH service is running on default port 22 with potential weak configuration",
//     severity: "medium",
//     port: 22,
//     service: "ssh",
//     cve: "CVE-2023-0001",
//   },
//   {
//     name: "Outdated Apache Version",
//     description: "Web server running outdated Apache version with known security vulnerabilities",
//     severity: "high",
//     port: 80,
//     service: "http",
//     cve: "CVE-2023-0002",
//   },
//   {
//     name: "Weak SSL Configuration",
//     description: "SSL/TLS configuration allows weak cipher suites and outdated protocols",
//     severity: "medium",
//     port: 443,
//     service: "https",
//     cve: "CVE-2023-0003",
//   },
//   {
//     name: "Anonymous FTP Access",
//     description: "FTP server allows anonymous login with read/write access",
//     severity: "high",
//     port: 21,
//     service: "ftp",
//     cve: "CVE-2023-0004",
//   },
//   {
//     name: "Default Credentials",
//     description: "Service using default username/password combination",
//     severity: "critical",
//     port: 23,
//     service: "telnet",
//     cve: "CVE-2023-0005",
//   },
//   {
//     name: "SQL Injection Vulnerability",
//     description: "Web application vulnerable to SQL injection attacks",
//     severity: "critical",
//     port: 80,
//     service: "http",
//     cve: "CVE-2023-0006",
//   },
//   {
//     name: "Cross-Site Scripting (XSS)",
//     description: "Web application vulnerable to reflected XSS attacks",
//     severity: "medium",
//     port: 80,
//     service: "http",
//     cve: "CVE-2023-0007",
//   },
//   {
//     name: "Unencrypted Database Connection",
//     description: "Database connection not using encryption",
//     severity: "high",
//     port: 3306,
//     service: "mysql",
//     cve: "CVE-2023-0008",
//   },
// ]

// Simulate network scanning process
// const simulateNetworkScan = async (scanId, target, scanType) => {
//   const scan = global.scans.find((s) => s.id === scanId)
//   if (!scan) return

//   try {
//     // Update scan status
//     scan.status = "running"
//     scan.currentStep = "Initializing network discovery..."
//     scan.progress = 5

//     // Simulate scanning phases with realistic delays
//     const phases = [
//       { step: "Performing host discovery...", progress: 15, delay: 1500 },
//       { step: "Port scanning in progress...", progress: 35, delay: 3000 },
//       { step: "Service version detection...", progress: 55, delay: 2500 },
//       { step: "Vulnerability assessment...", progress: 75, delay: 4000 },
//       { step: "Analyzing results with AI...", progress: 90, delay: 2000 },
//       { step: "Generating comprehensive report...", progress: 95, delay: 1500 },
//       { step: "Finalizing scan results...", progress: 100, delay: 1000 },
//     ]

//     for (const phase of phases) {
//       await new Promise((resolve) => setTimeout(resolve, phase.delay))
//       scan.currentStep = phase.step
//       scan.progress = phase.progress
//       console.log(`📊 Scan ${scanId}: ${phase.step} (${phase.progress}%)`)
//     }

//     // Generate vulnerabilities based on scan type
//     const vulnCount = {
//       basic: { min: 2, max: 3 },
//       comprehensive: { min: 4, max: 6 },
//       stealth: { min: 1, max: 2 },
//     }

//     const range = vulnCount[scanType] || vulnCount.basic
//     const numVulns = Math.floor(Math.random() * (range.max - range.min + 1)) + range.min

//     const selectedVulns = mockVulnerabilities
//       .sort(() => 0.5 - Math.random())
//       .slice(0, numVulns)
//       .map((vuln) => ({
//         ...vuln,
//         id: uuidv4(),
//         target: target,
//         discoveredAt: new Date().toISOString(),
//         scanType: scanType,
//       }))

//     scan.vulnerabilities = selectedVulns
//     scan.status = "completed"
//     scan.completedAt = new Date().toISOString()
//     scan.currentStep = "Scan completed successfully"
//     scan.duration = Math.floor((new Date() - new Date(scan.createdAt)) / 1000)

//     console.log(`✅ Scan ${scanId} completed with ${selectedVulns.length} vulnerabilities found`)
//   } catch (error) {
//     console.error(`❌ Scan ${scanId} failed:`, error)
//     scan.status = "failed"
//     scan.error = error.message
//     scan.currentStep = "Scan failed"
//   }
// }

// Get all scans
router.get("/", (req, res) => {
  const scansWithStats = global.scans.map((scan) => ({
    ...scan,
    vulnerabilityStats: scan.vulnerabilities
      ? {
          total: scan.vulnerabilities.length,
          critical: scan.vulnerabilities.filter((v) => v.severity === "critical").length,
          high: scan.vulnerabilities.filter((v) => v.severity === "high").length,
          medium: scan.vulnerabilities.filter((v) => v.severity === "medium").length,
          low: scan.vulnerabilities.filter((v) => v.severity === "low").length,
        }
      : null,
  }))

  res.json(scansWithStats)
})

// Get specific scan
router.get("/:id", (req, res) => {
  const scan = global.scans.find((s) => s.id === req.params.id)
  if (!scan) {
    return res.status(404).json({ error: "Scan not found" })
  }
  res.json(scan)
})

// Start new scan
// router.post("/start", async (req, res) => {
//   const { target, scanType, description } = req.body

//   if (!target) {
//     return res.status(400).json({ error: "Target is required" })
//   }

//   const targetRegex = /^(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3})$/;

//   if (!targetRegex.test(target)) {
//     console.log("❌ Failing validation:", target)
//     return res.status(400).json({
//       error: "Invalid target format. Please provide a valid IP address or domain name.",
//     })
//   }
//   const scanId = uuidv4()
//   const newScan = {
//     id: scanId,
//     target,
//     scanType: scanType || "basic",
//     description: description || "",
//     status: "initializing",
//     progress: 0,
//     currentStep: "Preparing scan configuration...",
//     createdAt: new Date().toISOString(),
//     vulnerabilities: [],
//     metadata: {
//       userAgent: req.get("User-Agent"),
//       clientIP: req.ip,
//       scanConfiguration: {
//         type: scanType || "basic",
//         timeout: 300,
//         maxPorts: scanType === "comprehensive" ? 65535 : 1000,
//       },
//     },
//   }

//   global.scans.push(newScan)
//   console.log(`🚀 Starting new ${scanType || "basic"} scan for target: ${target}`)

//   // Start scanning process asynchronously
//  //simulateNetworkScan(scanId, target, scanType || "basic")
//  realNetworkScan(scanId, target, scanType || "basic")

//   res.status(201).json(newScan)
// })
// router.post("/start", async (req, res) => {
//   const { target, scanType, description } = req.body
  
//   if (!target) {
//     return res.status(400).json({ error: "Target is required" })
//   }

//   // Comprehensive IP and domain validation regex (matching frontend)
//   const ipOrDomainRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})+$/

//   // Clean the target input
//   const cleanTarget = target.trim()
  
//   if (!ipOrDomainRegex.test(cleanTarget)) {
//     console.log("❌ Failing validation:", cleanTarget)
//     return res.status(400).json({
//       error: "Invalid target format. Please provide a valid IP address or domain name.",
//     })
//   }

//   // Additional validation helpers
//   const isValidIP = (ip) => {
//     const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
//     return ipRegex.test(ip)
//   }

//   const isValidDomain = (domain) => {
//     const domainRegex = /^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})+$/
//     return domainRegex.test(domain)
//   }

//   // Validate specific format
//   if (!isValidIP(cleanTarget) && !isValidDomain(cleanTarget)) {
//     console.log("❌ Target failed specific validation:", cleanTarget)
//     return res.status(400).json({
//       error: "Please enter a valid IP address (e.g., 192.168.1.1) or domain name (e.g., example.com)",
//     })
//   }

//   // Optional: Add security checks for private/reserved IPs
//   const isPrivateIP = (ip) => {
//     if (!isValidIP(ip)) return false
//     const parts = ip.split('.').map(Number)
//     return (
//       (parts[0] === 10) ||
//       (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
//       (parts[0] === 192 && parts[1] === 168) ||
//       (parts[0] === 127) || // localhost
//       (parts[0] === 169 && parts[1] === 254) // link-local
//     )
//   }

//   // Log validation success
//   console.log("✅ Target validation passed:", cleanTarget)
//   console.log("Target type:", isValidIP(cleanTarget) ? "IP Address" : "Domain Name")
  
//   if (isValidIP(cleanTarget) && isPrivateIP(cleanTarget)) {
//     console.log("ℹ️  Private IP address detected:", cleanTarget)
//   }

//   const scanId = uuidv4()
//   const newScan = {
//     id: scanId,
//     target: cleanTarget, // Use cleaned target
//     scanType: scanType || "basic",
//     description: description || "",
//     status: "initializing",
//     progress: 0,
//     currentStep: "Preparing scan configuration...",
//     createdAt: new Date().toISOString(),
//     vulnerabilities: [],
//     metadata: {
//       userAgent: req.get("User-Agent"),
//       clientIP: req.ip,
//       targetType: isValidIP(cleanTarget) ? "ip" : "domain",
//       isPrivateTarget: isValidIP(cleanTarget) ? isPrivateIP(cleanTarget) : false,
//       scanConfiguration: {
//         type: scanType || "basic",
//         timeout: 300,
//         maxPorts: scanType === "comprehensive" ? 65535 : 1000,
//       },
//     },
//   }

//   // Continue with your scan logic here...
//   console.log("🚀 Starting scan:", newScan)
  
//   // Return success response
//   res.status(200).json({
//     success: true,
//     scanId: scanId,
//     message: "Scan started successfully",
//     scan: newScan
//   })
// })
router.post("/start", async (req, res) => {
  const { target, scanType, description } = req.body
  
  if (!target) {
    return res.status(400).json({ error: "Target is required" })
  }

  // Clean the target input and extract domain/IP from URL if needed
  let cleanTarget = target.trim()
  
  // If it looks like a URL, extract just the domain/IP part
  if (cleanTarget.includes('://')) {
    try {
      const url = new URL(cleanTarget)
      cleanTarget = url.hostname
    } catch (e) {
      console.log("❌ Invalid URL format:", cleanTarget)
      return res.status(400).json({
        error: "Invalid URL format. Please provide a valid IP address, domain name, or URL.",
      })
    }
  } else if (cleanTarget.includes('/')) {
    // If it contains a path but no protocol, extract just the domain part
    cleanTarget = cleanTarget.split('/')[0]
  }
  
  // Comprehensive IP and domain validation regex
  const ipOrDomainRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})+$/
  
  if (!ipOrDomainRegex.test(cleanTarget)) {
    console.log("❌ Failing validation:", cleanTarget)
    return res.status(400).json({
      error: "Invalid target format. Please provide a valid IP address, domain name, or URL.",
    })
  }

  // Additional validation helpers
  const isValidIP = (ip) => {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
    return ipRegex.test(ip)
  }

  const isValidDomain = (domain) => {
    const domainRegex = /^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})+$/
    return domainRegex.test(domain)
  }

  // Validate specific format
  if (!isValidIP(cleanTarget) && !isValidDomain(cleanTarget)) {
    console.log("❌ Target failed specific validation:", cleanTarget)
    return res.status(400).json({
      error: "Please enter a valid IP address (e.g., 192.168.1.1) or domain name (e.g., example.com)",
    })
  }

  // Optional: Add security checks for private/reserved IPs
  const isPrivateIP = (ip) => {
    if (!isValidIP(ip)) return false
    const parts = ip.split('.').map(Number)
    return (
      (parts[0] === 10) ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      (parts[0] === 127) || // localhost
      (parts[0] === 169 && parts[1] === 254) // link-local
    )
  }

  // Log validation success
  console.log("✅ Target validation passed:", cleanTarget)
  console.log("Target type:", isValidIP(cleanTarget) ? "IP Address" : "Domain Name")
  
  if (isValidIP(cleanTarget) && isPrivateIP(cleanTarget)) {
    console.log("ℹ️  Private IP address detected:", cleanTarget)
  }

  const scanId = uuidv4()
  const newScan = {
    id: scanId,
    target: cleanTarget, // Use cleaned target
    scanType: scanType || "basic",
    description: description || "",
    status: "initializing",
    progress: 0,
    currentStep: "Preparing scan configuration...",
    createdAt: new Date().toISOString(),
    vulnerabilities: [],
    metadata: {
      userAgent: req.get("User-Agent"),
      clientIP: req.ip,
      targetType: isValidIP(cleanTarget) ? "ip" : "domain",
      isPrivateTarget: isValidIP(cleanTarget) ? isPrivateIP(cleanTarget) : false,
      scanConfiguration: {
        type: scanType || "basic",
        timeout: 300,
        maxPorts: scanType === "comprehensive" ? 65535 : 1000,
      },
    },
  }

  // Continue with your scan logic here...
  console.log("🚀 Starting scan:", newScan)
  
  // Return success response
  res.status(200).json({
    success: true,
    scanId: scanId,
    message: "Scan started successfully",
    scan: newScan
  })
})

// Stop/Cancel scan
router.post("/:id/stop", (req, res) => {
  const scan = global.scans.find((s) => s.id === req.params.id)
  if (!scan) {
    return res.status(404).json({ error: "Scan not found" })
  }

  if (scan.status === "running") {
    scan.status = "cancelled"
    scan.currentStep = "Scan cancelled by user"
    scan.cancelledAt = new Date().toISOString()
    console.log(`🛑 Scan ${req.params.id} cancelled by user`)
  }

  res.json(scan)
})

// Delete scan
router.delete("/:id", (req, res) => {
  const scanIndex = global.scans.findIndex((s) => s.id === req.params.id)
  if (scanIndex === -1) {
    return res.status(404).json({ error: "Scan not found" })
  }

  const deletedScan = global.scans.splice(scanIndex, 1)[0]
  console.log(`🗑️ Deleted scan: ${req.params.id}`)
  res.json({ message: "Scan deleted successfully", scan: deletedScan })
})

module.exports = router

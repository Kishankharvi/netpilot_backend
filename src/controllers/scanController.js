const express = require("express")
const { v4: uuidv4 } = require("uuid")
const router = express.Router()
const Nmap = require("node-nmap")

Nmap.nmapLocation = "nmap"

const knownVulnerabilities = [
  { port: 22, service: "ssh", name: "Open SSH Port", severity: "medium", description: "SSH service detected. Check for weak configuration." },
  { port: 21, service: "ftp", name: "Anonymous FTP Access", severity: "high", description: "FTP service detected. Check for anonymous access." },
  { port: 23, service: "telnet", name: "Default Credentials", severity: "critical", description: "Telnet service detected. Check for default credentials." },
  { port: 80, service: "http", name: "Outdated Apache Version", severity: "high", description: "HTTP service detected. Check for outdated Apache version." },
  { port: 443, service: "https", name: "Weak SSL Configuration", severity: "medium", description: "HTTPS service detected. Check for weak SSL/TLS configuration." }
]

const realNetworkScan = async (scanId, target, scanType) => {
  const scan = global.scans.find((s) => s.id === scanId)
  if (!scan) return

  try {
    scan.status = "running"
    scan.currentStep = "Running Nmap scan..."
    scan.progress = 10

    const options = {
      ports: scanType === "comprehensive" ? "1-65535" : "1-1000",
      flags: ["-sV"]
    }

   const nmapScan = new Nmap.NmapScan(target, [
  "-sV",
  "-p", options.ports
])


    nmapScan.on("complete", function (data) {
      scan.currentStep = "Analyzing scan results..."
      scan.progress = 80

      const vulnerabilities = []
      data.forEach((host) => {
        host.openPorts.forEach((portInfo) => {
          const match = knownVulnerabilities.find(
            (v) => v.port === portInfo.port && portInfo.service && portInfo.service.includes(v.service)
          )
          if (match) {
            vulnerabilities.push({
              ...match,
              id: uuidv4(),
              target: target,
              discoveredAt: new Date().toISOString(),
              scanType: scanType,
              port: portInfo.port,
              service: portInfo.service,
              cve: match.cve || ""
            })
          }
        })
      })

      scan.vulnerabilities = vulnerabilities
      scan.status = "completed"
      scan.completedAt = new Date().toISOString()
      scan.currentStep = "Scan completed successfully"
      scan.duration = Math.floor((new Date() - new Date(scan.createdAt)) / 1000)

      console.log(`✅ Real scan ${scanId} completed with ${vulnerabilities.length} vulnerabilities found`)
    })

    nmapScan.on("error", function (error) {
      scan.status = "failed"
      scan.error = error.message
      scan.currentStep = "Scan failed"
      console.error(`❌ Real scan ${scanId} failed:`, error)
    })

    nmapScan.startScan()
  } catch (error) {
    scan.status = "failed"
    scan.error = error.message
    scan.currentStep = "Scan failed"
    console.error(`❌ Real scan ${scanId} failed:`, error)
  }
}

router.get("/", (req, res) => {
  const scansWithStats = global.scans.map((scan) => ({
    ...scan,
    vulnerabilityStats: scan.vulnerabilities
      ? {
          total: scan.vulnerabilities.length,
          critical: scan.vulnerabilities.filter((v) => v.severity === "critical").length,
          high: scan.vulnerabilities.filter((v) => v.severity === "high").length,
          medium: scan.vulnerabilities.filter((v) => v.severity === "medium").length,
          low: scan.vulnerabilities.filter((v) => v.severity === "low").length
        }
      : null
  }))

  res.json(scansWithStats)
})

router.get("/:id", (req, res) => {
  const scan = global.scans.find((s) => s.id === req.params.id)
  if (!scan) return res.status(404).json({ error: "Scan not found" })
  res.json(scan)
})

router.post("/start", async (req, res) => {
  const { target, scanType, description } = req.body

  if (!target) return res.status(400).json({ error: "Target is required" })

  let cleanTarget = target.trim()
  if (cleanTarget.includes("://")) {
    try {
      const url = new URL(cleanTarget)
      cleanTarget = url.hostname
    } catch (e) {
      return res.status(400).json({ error: "Invalid URL format." })
    }
  } else if (cleanTarget.includes("/")) {
    cleanTarget = cleanTarget.split("/")[0]
  }

  const ipOrDomainRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})+$/
  if (!ipOrDomainRegex.test(cleanTarget)) {
    return res.status(400).json({
      error: "Invalid target format. Provide a valid IP address, domain name, or URL."
    })
  }

  const isValidIP = (ip) => /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip)
  const isPrivateIP = (ip) => {
    const parts = ip.split(".").map(Number)
    return (
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      parts[0] === 127 ||
      (parts[0] === 169 && parts[1] === 254)
    )
  }

  const scanId = uuidv4()
  const newScan = {
    id: scanId,
    target: cleanTarget,
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
        maxPorts: scanType === "comprehensive" ? 65535 : 1000
      }
    }
  }

  global.scans.push(newScan)
  realNetworkScan(scanId, cleanTarget, scanType || "basic")
  res.status(201).json({ success: true, scanId, scan: newScan })
})

router.post("/:id/stop", (req, res) => {
  const scan = global.scans.find((s) => s.id === req.params.id)
  if (!scan) return res.status(404).json({ error: "Scan not found" })

  if (scan.status === "running") {
    scan.status = "cancelled"
    scan.currentStep = "Scan cancelled by user"
    scan.cancelledAt = new Date().toISOString()
    console.log(`🛑 Scan ${req.params.id} cancelled by user`)
  }

  res.json(scan)
})

router.delete("/:id", (req, res) => {
  const index = global.scans.findIndex((s) => s.id === req.params.id)
  if (index === -1) return res.status(404).json({ error: "Scan not found" })
  const deleted = global.scans.splice(index, 1)[0]
  res.json({ message: "Scan deleted successfully", scan: deleted })
})

module.exports = router
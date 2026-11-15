<p align="right">
  <b>English</b> | <a href="FRAMEWORK.fr.md">Français</a>
</p>

# SocketForge — Framework Specification & AI Documentation

This document is the technical manifest intended for AI agents and software engineers. It outlines all capabilities, architectural components, and public contracts exposed by **SocketForge**.

---

## 🎯 Scope & Responsibility

SocketForge is a cross-platform .NET system engineering library dedicated to **observing, enumerating, and analyzing active TCP and UDP sockets and network flows at the OS level (Windows & Linux)**, without external drivers or Npcap/WinPcap dependencies.

---

## 🚀 Key Capabilities

* **Zero Npcap Dependency**:
  * Windows: Native inspection via Win32 IP Helper API (`iphlpapi.dll`: `GetExtendedTcpTable`, `GetExtendedUdpTable`), for both IPv4 (`AF_INET`) and IPv6 (`AF_INET6`) sockets; link-local IPv6 addresses keep their scope id (`fe80::1%12`). A table that grows between the size call and the read call is read again with the new size; any other API error raises `Win32Exception` instead of an empty scan.
  * Linux: Direct kernel inspection via `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` and inode correlation across `/proc/<pid>/fd`.
  * IPv4 peers of dual-stack sockets (`::ffff:a.b.c.d`) are reported as IPv4 addresses on both platforms, so a host keeps a single address.
* **Flow Direction Resolution (`SocketFlowDirectionResolver`)**:
  * Accurate and deterministic classification of `Listening`, `Inbound`, and `Outbound` states across both Windows and Linux.
  * Local listener indexing (`LISTEN` / `0A` / State 2) to formally identify inbound connections destined for hosted services (SSH, HTTP, databases, etc.).
  * Heuristic fallback rules based on dynamic/ephemeral port allocations (Linux `>= 32768`, IANA `>= 49152`) and privileged ranges (`< 1024`).
* **Process Correlation**:
  * Direct correlation of every active socket to its owning process and underlying target executable resolved via **`ProcessForge`**.
  * Each scan resolves every distinct PID once, whatever the number of sockets the process owns (since 2.1.0, Windows and Linux).
  * `SocketScannerFactory.Create()` (since 2.1.0) builds the scanner with a ProcessForge `CachingProcessInspector` around a `CrossPlatformProcessInspector`, kept for the scanner's lifetime: a process already seen is not read again on the next scans unless its start time changed. Keep one scanner for as long as you scan.
  * `SocketScannerFactory.Create(IProcessInspector)` uses the given inspector as is, without adding a cache.
* **Strong Typing & Canonical Deduplication Keys**:
  * Immutable data models (`ActiveSocketConnection`, `SocketEndpoint`, `SocketTransportProtocol`, `SocketFlowDirection`).
  * Canonical deduplication keys preserving logical application flows independently of client ephemeral port variations.
  * The owner part of the key is the target executable, else the executable path, else the process name (since 2.0.0), so processes whose path cannot be read are no longer merged into one flow. Breaking change: the keys of flows whose path was empty differ from the ones written by 1.x.
* **Ownerless TIME_WAIT sockets are not reported** (since 2.0.0): a TCP socket (IPv4 or IPv6) in TIME_WAIT owned by pid 0 on Windows, or with inode 0 on Linux, no longer belongs to any process and would otherwise appear as a second flow of the same destination.

---

## 📋 Maintenance Protocol for AI Agents

All enhancements to SocketForge must comply with:
1. **Backward Compatibility:** Preserve all existing public contracts. Use overloads or optional parameters.
2. **Code Cleanliness:** Zero warnings (`<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`), zero pragmas/suppressions.
3. **Testing Standards:** Test naming convention `TargetMethod_ScenarioOrCondition_ExpectedResult`.
4. **Documentation:** Update both `FRAMEWORK.md` and `FRAMEWORK.fr.md` immediately upon introducing or modifying capabilities.
5. **Validation:** Full pass of `./verify.ps1`.

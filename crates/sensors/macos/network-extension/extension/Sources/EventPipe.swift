// The extension side of the extension↔agent seam (issue #33): a reconnecting
// Unix-socket client writing the NDJSON wire records `src/wire.rs` defines.
// WIRE_VERSION here must match that file — bump both together.
//
// Built and packaged per packaging/macos (not by cargo); type-checked in CI
// by `swiftc -typecheck` so drift against the SDK is caught on every change.

import Darwin
import Foundation

/// Mirror of `wire::WIRE_VERSION`.
let wireVersion: UInt32 = 1

/// One wire record, shaped exactly like `wire::NeRecord`'s serde output
/// (`kind` tag, snake_case fields).
struct WireRecord: Encodable {
    let kind: String
    let v: UInt32
    let ts_ns: UInt64
    let pid: UInt32
    let process_path: String?
    // flow
    var direction: String? = nil
    var remote_addr: String? = nil
    var remote_port: UInt16? = nil
    var local_port: UInt16? = nil
    var `protocol`: UInt8? = nil
    // flow_stats
    var bytes_sent: UInt64? = nil
    var bytes_received: UInt64? = nil
    // dns
    var query: String? = nil
    var qtype: UInt32? = nil
    var result: String? = nil
    var rcode: UInt32? = nil
}

/// Extracts the pid from an `audit_token_t` serialized as `Data`
/// (`NEFilterFlow.sourceAppAuditToken`): eight u32s, pid at index 5.
func pidFromAuditToken(_ token: Data) -> UInt32 {
    guard token.count >= 8 * MemoryLayout<UInt32>.size else { return 0 }
    return token.withUnsafeBytes { raw in
        raw.load(fromByteOffset: 5 * MemoryLayout<UInt32>.size, as: UInt32.self)
    }
}

/// Resolves the executable path for a pid (best effort).
func processPath(forPid pid: UInt32) -> String? {
    var buffer = [CChar](repeating: 0, count: 4096)
    let n = proc_pidpath(Int32(pid), &buffer, UInt32(buffer.count))
    guard n > 0 else { return nil }
    return String(cString: buffer)
}

/// Wall-clock now in ns since the UNIX epoch.
func nowNs() -> UInt64 {
    var ts = timespec()
    clock_gettime(CLOCK_REALTIME, &ts)
    return UInt64(ts.tv_sec) * 1_000_000_000 + UInt64(ts.tv_nsec)
}

/// Reconnecting NDJSON writer over the agent's Unix socket in the shared
/// app-group container (a network-extension sandbox allows its own app
/// group, not arbitrary paths — see packaging/macos).
final class EventPipe {
    private let socketPath: String
    private var fd: Int32 = -1
    private let queue = DispatchQueue(label: "synthaea.ne.eventpipe")
    private let encoder = JSONEncoder()

    init(socketPath: String) {
        self.socketPath = socketPath
    }

    func send(_ record: WireRecord) {
        queue.async {
            guard let data = try? self.encoder.encode(record) else { return }
            var line = data
            line.append(0x0A)
            if self.fd < 0 { self.connect() }
            guard self.fd >= 0 else { return }
            let ok = line.withUnsafeBytes { raw -> Bool in
                write(self.fd, raw.baseAddress, raw.count) == raw.count
            }
            if !ok {
                // Agent restarted (or backpressure) — drop this record, and
                // reconnect on the next one. The agent's stream counts skew;
                // the extension must never buffer unboundedly.
                close(self.fd)
                self.fd = -1
            }
        }
    }

    private func connect() {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let ok = withUnsafeMutableBytes(of: &addr.sun_path) { raw -> Bool in
            let bytes = Array(socketPath.utf8)
            guard bytes.count < raw.count else { return false }
            raw.copyBytes(from: bytes)
            return true
        }
        guard ok else {
            close(fd)
            return
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.connect(fd, sa, len)
            }
        }
        if result == 0 {
            self.fd = fd
        } else {
            close(fd)
        }
    }
}

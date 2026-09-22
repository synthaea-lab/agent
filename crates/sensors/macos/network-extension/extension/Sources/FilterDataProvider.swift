// NEFilterDataProvider: every socket flow, inbound + outbound, with process
// attribution from the flow's audit token (issue #33). Verdicts are
// allow-everything — this is telemetry, not inline blocking; blocking is
// response-milestone (M6) work on the same provider.

import Foundation
import NetworkExtension

class FilterDataProvider: NEFilterDataProvider {
    // The app-group container is the one filesystem location both the
    // extension sandbox and the agent share; packaging/macos wires the group
    // id into both signing profiles.
    static let socketPath =
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.dev.synthaea.agent")?
            .appendingPathComponent("ne.sock").path ?? "/var/run/synthaea-ne.sock"

    let pipe = EventPipe(socketPath: FilterDataProvider.socketPath)

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // One rule: see all flows, both directions. defaultAction .allow is
        // the fail-open telemetry posture (never break the host's network
        // because the sensor is unhealthy).
        let all = NENetworkRule(
            remoteNetwork: nil,
            remotePrefix: 0,
            localNetwork: nil,
            localPrefix: 0,
            protocol: .any,
            direction: .any
        )
        let settings = NEFilterSettings(
            rules: [NEFilterRule(networkRule: all, action: .filterData)],
            defaultAction: .allow
        )
        apply(settings) { error in
            completionHandler(error)
        }
    }

    override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        if let socketFlow = flow as? NEFilterSocketFlow,
            let remote = socketFlow.remoteEndpoint as? NWHostEndpoint
        {
            let pid = flow.sourceAppAuditToken.map(pidFromAuditToken) ?? 0
            let record = WireRecord(
                kind: "flow",
                v: wireVersion,
                ts_ns: nowNs(),
                pid: pid,
                process_path: processPath(forPid: pid),
                direction: socketFlow.direction == .inbound ? "inbound" : "outbound",
                remote_addr: remote.hostname,
                remote_port: UInt16(remote.port) ?? 0,
                local_port: (socketFlow.localEndpoint as? NWHostEndpoint)
                    .flatMap { UInt16($0.port) } ?? 0,
                protocol: UInt8(clamping: socketFlow.socketProtocol)
            )
            pipe.send(record)
        }
        return .allow()
    }

    // Flow accounting at flow close — the NetworkFlowEvent-shaped volume
    // fact. Requires `reportByteCounts` in the filter configuration
    // (packaging/macos).
    override func handle(_ report: NEFilterReport) {
        guard report.event == .flowClosed,
            let socketFlow = report.flow as? NEFilterSocketFlow,
            let remote = socketFlow.remoteEndpoint as? NWHostEndpoint
        else { return }
        let pid = report.flow?.sourceAppAuditToken.map(pidFromAuditToken) ?? 0
        let record = WireRecord(
            kind: "flow_stats",
            v: wireVersion,
            ts_ns: nowNs(),
            pid: pid,
            process_path: processPath(forPid: pid),
            remote_addr: remote.hostname,
            remote_port: UInt16(remote.port) ?? 0,
            local_port: (socketFlow.localEndpoint as? NWHostEndpoint)
                .flatMap { UInt16($0.port) } ?? 0,
            protocol: UInt8(clamping: socketFlow.socketProtocol),
            bytes_sent: UInt64(clamping: report.bytesOutboundCount),
            bytes_received: UInt64(clamping: report.bytesInboundCount)
        )
        pipe.send(record)
    }
}

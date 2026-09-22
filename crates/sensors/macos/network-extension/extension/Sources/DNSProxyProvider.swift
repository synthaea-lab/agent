// NEDNSProxyProvider: DNS query/response pairs with process attribution
// (issue #33). A DNS proxy must actually proxy — each app flow's datagrams
// are forwarded to the upstream resolver and the responses returned, with
// the (query, answers, rcode) pair reported over the event pipe.
//
// The DNS parsing here is deliberately minimal (question name/type, response
// rcode, A/AAAA answers) — enough for the domain↔process join key; anything
// unparseable is forwarded untouched and reported without the parsed fields.

import Foundation
import Network
import NetworkExtension

class DNSProxyProvider: NEDNSProxyProvider {
    let pipe = EventPipe(socketPath: FilterDataProvider.socketPath)
    // Upstream resolver; packaging/macos provisions the real value through
    // the provider configuration (a proxy must name its upstream — using
    // the system setting would loop through ourselves).
    let upstream = Network.NWEndpoint.hostPort(host: "1.1.1.1", port: 53)

    override func startProxy(
        options: [String: Any]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        completionHandler(nil)
    }

    override func stopProxy(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let udpFlow = flow as? NEAppProxyUDPFlow else {
            // TCP DNS (large answers, DoT fallback) — not proxied by this
            // scaffold; returning false lets the system handle it natively.
            return false
        }
        let pid = flow.metaData.sourceAppAuditToken.map(pidFromAuditToken) ?? 0
        let path = processPath(forPid: pid)
        udpFlow.open(withLocalEndpoint: nil) { error in
            guard error == nil else { return }
            self.pump(udpFlow, pid: pid, path: path)
        }
        return true
    }

    private func pump(_ udpFlow: NEAppProxyUDPFlow, pid: UInt32, path: String?) {
        // The endpoint stays type-inferred throughout: this SDK exposes two
        // `NWEndpoint` types (NetworkExtension's deprecated class and
        // Network's enum) and naming the former is ambiguous — the closure
        // parameter and the `sentBy:` array below carry the type instead.
        udpFlow.readDatagrams { datagrams, endpoints, error in
            guard error == nil, let datagrams, let endpoints, !datagrams.isEmpty else {
                udpFlow.closeReadWithError(error)
                udpFlow.closeWriteWithError(error)
                return
            }
            for (query, endpoint) in zip(datagrams, endpoints) {
                let question = DnsMessage.parseQuestion(query)
                let connection = NWConnection(to: self.upstream, using: .udp)
                connection.stateUpdateHandler = { state in
                    guard case .ready = state else { return }
                    connection.send(
                        content: query,
                        completion: .contentProcessed { _ in
                            connection.receiveMessage { response, _, _, _ in
                                defer { connection.cancel() }
                                guard let response else { return }
                                udpFlow.writeDatagrams([response], sentBy: [endpoint]) { _ in }
                                let answer = DnsMessage.parseResponse(response)
                                self.pipe.send(
                                    WireRecord(
                                        kind: "dns",
                                        v: wireVersion,
                                        ts_ns: nowNs(),
                                        pid: pid,
                                        process_path: path,
                                        query: question?.name ?? "",
                                        qtype: question?.qtype ?? 0,
                                        result: answer.addresses.isEmpty
                                            ? nil : answer.addresses.joined(separator: ";"),
                                        rcode: answer.rcode
                                    ))
                            }
                        })
                }
                connection.start(queue: .global())
            }
            // Keep reading until the flow closes.
            self.pump(udpFlow, pid: pid, path: path)
        }
    }
}

/// Minimal DNS wire-format reader — question name/type and A/AAAA answers.
enum DnsMessage {
    struct Question {
        let name: String
        let qtype: UInt32
    }

    struct Response {
        let rcode: UInt32
        let addresses: [String]
    }

    static func parseQuestion(_ data: Data) -> Question? {
        guard data.count > 12 else { return nil }
        var offset = 12
        guard let name = readName(data, at: &offset) else { return nil }
        guard offset + 2 <= data.count else { return nil }
        let qtype = UInt32(data[offset]) << 8 | UInt32(data[offset + 1])
        return Question(name: name, qtype: qtype)
    }

    static func parseResponse(_ data: Data) -> Response {
        guard data.count > 12 else { return Response(rcode: 0, addresses: []) }
        let rcode = UInt32(data[3] & 0x0F)
        let qdcount = Int(data[4]) << 8 | Int(data[5])
        let ancount = Int(data[6]) << 8 | Int(data[7])
        var offset = 12
        for _ in 0..<qdcount {
            guard readName(data, at: &offset) != nil, offset + 4 <= data.count else {
                return Response(rcode: rcode, addresses: [])
            }
            offset += 4
        }
        var addresses: [String] = []
        for _ in 0..<ancount {
            guard readName(data, at: &offset) != nil, offset + 10 <= data.count else { break }
            let rtype = Int(data[offset]) << 8 | Int(data[offset + 1])
            let rdlen = Int(data[offset + 8]) << 8 | Int(data[offset + 9])
            offset += 10
            guard offset + rdlen <= data.count else { break }
            let rdata = data.subdata(in: offset..<offset + rdlen)
            offset += rdlen
            if rtype == 1, rdlen == 4 {
                addresses.append(rdata.map(String.init).joined(separator: "."))
            } else if rtype == 28, rdlen == 16 {
                let groups = stride(from: 0, to: 16, by: 2).map {
                    String(format: "%x", Int(rdata[$0]) << 8 | Int(rdata[$0 + 1]))
                }
                addresses.append(groups.joined(separator: ":"))
            }
        }
        return Response(rcode: rcode, addresses: addresses)
    }

    /// Reads a (possibly compression-pointer-terminated) name; advances
    /// `offset` past it in the original record.
    private static func readName(_ data: Data, at offset: inout Int) -> String? {
        var labels: [String] = []
        var cursor = offset
        var jumped = false
        var guardCounter = 0
        while cursor < data.count {
            guardCounter += 1
            if guardCounter > 64 { return nil }
            let len = Int(data[cursor])
            if len == 0 {
                if !jumped { offset = cursor + 1 }
                return labels.joined(separator: ".")
            }
            if len & 0xC0 == 0xC0 {
                guard cursor + 1 < data.count else { return nil }
                if !jumped { offset = cursor + 2 }
                cursor = (len & 0x3F) << 8 | Int(data[cursor + 1])
                jumped = true
                continue
            }
            guard cursor + 1 + len <= data.count else { return nil }
            let label = data.subdata(in: cursor + 1..<cursor + 1 + len)
            labels.append(String(decoding: label, as: UTF8.self))
            cursor += 1 + len
        }
        return nil
    }
}

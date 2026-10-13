// DNSSDCache.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MDNSCore

// MARK: - DNSSDCache

/// What we have heard on the wire, keyed by full lowercase DNS names. Pure value type, no I/O.
///
/// Names compare case-insensitively over ASCII only (RFC 4343); names as
/// received are kept for display. Records expire `ttl` seconds after the
/// `now` they were ingested with; expired records are dropped at the next
/// `ingest`, so a reader that wants an up-to-date view ingests `[]` first.
/// A TTL-0 record is a goodbye (RFC 6762 §10.1) and removes what it names.
/// SRV and TXT hold one value per instance, so a newer one replaces the
/// older; A/AAAA honour the cache-flush bit (RFC 6762 §10.2). Shared PTRs do
/// not: a cache-flush bit on a service-type PTR is a responder error and
/// would otherwise evict every other responder's instances.
struct DNSSDCache: Sendable {

    private struct Entry<Value: Sendable>: Sendable {
        var value: Value
        var expiry: ContinuousClock.Instant
    }

    private struct Service: Sendable {
        var target: String
        var port: UInt16
    }

    /// PTR owner → lowercase target → target as received.
    private var pointers: [String: [String: Entry<String>]] = [:]
    /// Instance name → SRV.
    private var services: [String: Entry<Service>] = [:]
    /// Instance name → TXT character-strings, in the order received.
    private var texts: [String: Entry<[String]>] = [:]
    private struct AddressEntry: Sendable {
        var record: DNSRecord
        var expiry: ContinuousClock.Instant
        /// When this record was last heard; drives cache-flush eviction.
        var heard: ContinuousClock.Instant
    }

    /// Host name → A and AAAA records, most recently heard first.
    private var addressRecords: [String: [AddressEntry]] = [:]

    // MARK: Ingest

    mutating func ingest(_ records: [DNSRecord], now: ContinuousClock.Instant) {
        prune(now: now)
        for record in records {
            let owner = record.name.dnsLowercased
            let expiry = now + .seconds(Int64(record.ttl))
            let isGoodbye = record.ttl == 0
            switch record.rdata {
            case .ptr(let domain):
                if isGoodbye {
                    pointers[owner]?[domain.dnsLowercased] = nil
                    if pointers[owner]?.isEmpty == true { pointers[owner] = nil }
                } else {
                    pointers[owner, default: [:]][domain.dnsLowercased] = Entry(value: domain, expiry: expiry)
                }
            case .srv(_, _, let port, let target):
                services[owner] = isGoodbye ? nil : Entry(value: Service(target: target, port: port), expiry: expiry)
            case .txt(let strings):
                texts[owner] = isGoodbye ? nil : Entry(value: strings, expiry: expiry)
            case .a(let bytes), .aaaa(let bytes):
                var entries = addressRecords[owner] ?? []
                entries.removeAll { Self.sameAddress($0.record, record.type, bytes) }
                if !isGoodbye {
                    if record.cacheFlush {
                        // RFC 6762 §10.2: a cache-flush record replaces the
                        // records of this name and type heard more than 1 s
                        // earlier — so an address change takes effect now,
                        // not when the old record's TTL lapses. Records from
                        // the same burst (within 1 s) are kept together.
                        entries.removeAll { $0.record.type == record.type && now - $0.heard > .seconds(1) }
                    }
                    entries.insert(AddressEntry(record: record, expiry: expiry, heard: now), at: 0)
                }
                addressRecords[owner] = entries.isEmpty ? nil : entries
            case .unknown:
                continue
            }
        }
    }

    // MARK: Queries

    /// Instance names (first label) currently advertised for a service type; TTL-0 goodbyes remove them.
    func instances(of serviceType: String) -> [String] {
        let owner = "\(serviceType).local".dnsLowercased
        return (pointers[owner] ?? [:]).values
            .compactMap { Self.instanceName(fullName: $0.value, serviceType: serviceType) }
            .sorted()
    }

    /// SRV target and port for an instance, if known and unexpired.
    func srv(instance: String, serviceType: String) -> (target: String, port: UInt16)? {
        guard let service = services[Self.key(instance: instance, serviceType: serviceType)]?.value else { return nil }
        return (service.target, service.port)
    }

    /// TXT for an instance as key/value (a bare key maps to ""; the RFC 6763 single empty string → [:]).
    func txt(instance: String, serviceType: String) -> [String: String]? {
        texts[Self.key(instance: instance, serviceType: serviceType)].map { TXTRecord.decode($0.value) }
    }

    /// Addresses for a host, A before AAAA, formatted as resolvableHosts does today.
    /// Within each family, the most recently heard address comes first.
    func addresses(host: String) -> [String] {
        let records = (addressRecords[host.dnsLowercased] ?? []).map(\.record)
        return LinuxServiceDiscovery.resolvableHosts(from: records).map(\.host)
    }

    // MARK: Names

    /// The lowercase full name of an instance: `<instance>.<type>.local`.
    static func key(instance: String, serviceType: String) -> String {
        "\(instance).\(serviceType).local".dnsLowercased
    }

    /// The instance part of `<instance>.<type>.local`, as received. Splits
    /// only at the service-type suffix, so dots and spaces in the instance
    /// survive. `nil` when `fullName` is not an instance of `serviceType`.
    static func instanceName(fullName: String, serviceType: String) -> String? {
        let suffix = ".\(serviceType).local".dnsLowercased
        let lowered = fullName.dnsLowercased
        guard lowered.utf8.count > suffix.utf8.count, lowered.hasSuffix(suffix) else { return nil }
        // ASCII lowercasing keeps every byte's position, so the suffix
        // length applies to the name as received.
        return String(decoding: fullName.utf8.dropLast(suffix.utf8.count), as: UTF8.self)
    }

    // MARK: Private

    private mutating func prune(now: ContinuousClock.Instant) {
        pointers = pointers.compactMapValues { targets in
            let live = targets.filter { $0.value.expiry > now }
            return live.isEmpty ? nil : live
        }
        services = services.filter { $0.value.expiry > now }
        texts = texts.filter { $0.value.expiry > now }
        addressRecords = addressRecords.compactMapValues { entries in
            let live = entries.filter { $0.expiry > now }
            return live.isEmpty ? nil : live
        }
    }

    private static func sameAddress(_ record: DNSRecord, _ type: DNSRecordType, _ bytes: Data) -> Bool {
        guard record.type == type else { return false }
        switch record.rdata {
        case .a(let existing), .aaaa(let existing): return existing == bytes
        default: return false
        }
    }
}

// MARK: - DNS name case

extension String {
    /// The name with ASCII letters lowercased and everything else untouched —
    /// DNS name comparison is case-insensitive over ASCII only (RFC 4343).
    var dnsLowercased: String {
        String(decoding: utf8.map { (0x41 ... 0x5A).contains($0) ? $0 | 0x20 : $0 }, as: UTF8.self)
    }
}

// TXTLookup.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Network)
import Foundation
import dnssd
import MDNSCore

// MARK: - TXTLookup

/// One `DNSServiceResolve` lookup of an instance's TXT record, bridged to async.
///
/// The reply callback is a C function pointer, so it reaches this object
/// through a retained context pointer. Whichever of the reply, a failure or
/// cancellation arrives first wins (`finished`); it resumes the continuation
/// and, if the ref was started, deallocates it **on the ref's dispatch queue**
/// — so no reply can run concurrently with, or after, deallocation — before
/// releasing the context.
final class TXTLookup: @unchecked Sendable {

    let name: String
    let type: String
    private let queue: DispatchQueue

    // `continuation`, `ref` and `finished` are guarded by `lock`.
    private let lock = NSLock()
    private var continuation: CheckedContinuation<[String: String], Error>?
    private var ref: DNSServiceRef?
    private var finished = false

    init(name: String, type: String, queue: DispatchQueue) {
        self.name = name
        self.type = type
        self.queue = queue
    }

    func run() async throws -> [String: String] {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<[String: String], Error>) in
                lock.lock()
                if finished {
                    lock.unlock()
                    cont.resume(throwing: CancellationError())
                    return
                }
                continuation = cont
                lock.unlock()
                start()
            }
        } onCancel: {
            finish(.failure(CancellationError()))
        }
    }

    private func start() {
        let context = Unmanaged.passRetained(self)
        var sdRef: DNSServiceRef?
        let err = DNSServiceResolve(
            &sdRef,
            0,          // flags
            0,          // any interface
            name,
            type,
            "local.",
            TXTLookup.reply,
            context.toOpaque()
        )
        guard err == kDNSServiceErr_NoError, let sdRef else {
            context.release()
            finish(.failure(ServiceDiscoveryError.resolveFailed(name)))
            return
        }

        lock.lock()
        if finished {
            // Cancelled before the ref was published; nothing is scheduled
            // on a queue yet, so it can be deallocated here.
            lock.unlock()
            DNSServiceRefDeallocate(sdRef)
            context.release()
            return
        }
        // Schedule before publishing, so `finish` never deallocates a ref
        // that is still being attached to the queue.
        DNSServiceSetDispatchQueue(sdRef, queue)
        ref = sdRef
        lock.unlock()
    }

    private func finish(_ result: Result<[String: String], Error>) {
        lock.lock()
        guard !finished else {
            lock.unlock()
            return
        }
        finished = true
        let cont = continuation
        continuation = nil
        let started = ref != nil
        lock.unlock()

        cont?.resume(with: result)

        if started {
            queue.async {
                self.deallocateRef()
                Unmanaged.passUnretained(self).release()
            }
        }
    }

    private func deallocateRef() {
        lock.lock()
        let sdRef = ref
        ref = nil
        lock.unlock()
        if let sdRef {
            DNSServiceRefDeallocate(sdRef)
        }
    }

    private static let reply: DNSServiceResolveReply = { _, _, _, errorCode, _, _, _, txtLen, txtRecord, context in
        guard let context else { return }
        let lookup = Unmanaged<TXTLookup>.fromOpaque(context).takeUnretainedValue()
        guard errorCode == kDNSServiceErr_NoError else {
            lookup.finish(.failure(ServiceDiscoveryError.resolveFailed(lookup.name)))
            return
        }
        let bytes = txtRecord.map { UnsafeBufferPointer(start: $0, count: Int(txtLen)) }
        lookup.finish(.success(bytes.map { TXTRecord.decode(wireFormat: $0) } ?? [:]))
    }
}
#endif

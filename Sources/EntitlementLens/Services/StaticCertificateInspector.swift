import CryptoKit
import Foundation
import Security

/// Decodes CMS certificates without asking CMSDecoder for signature status or evaluating trust.
enum StaticCertificateInspector {
    static let maximumCMSBytes = 32 * 1_024 * 1_024
    static let maximumCertificates = 256
    private static let maximumCertificateBytes = 1_024 * 1_024
    private static let maximumNameFields = 256
    private static let maximumStringBytes = 65_536

    static let limits: [StaticCollectionLimit] = [
        StaticCollectionLimit(name: "cms_bytes", value: UInt64(maximumCMSBytes), unit: .bytes),
        StaticCollectionLimit(name: "embedded_certificates", value: UInt64(maximumCertificates), unit: .records),
        StaticCollectionLimit(name: "certificate_der_bytes", value: UInt64(maximumCertificateBytes), unit: .bytes),
        StaticCollectionLimit(name: "certificate_name_fields", value: UInt64(maximumNameFields), unit: .records),
        StaticCollectionLimit(name: "certificate_string_bytes", value: UInt64(maximumStringBytes), unit: .bytes)
    ]

    private struct DERElement {
        let tag: UInt8
        let contentStart: Int
        let end: Int
    }

    static func inspect(
        cms: Data, chain: [SecCertificate], location: StaticEvidenceLocation
    ) throws -> StaticFeatureCollection<StaticCertificate> {
        guard !cms.isEmpty, cms.count <= maximumCMSBytes else {
            throw StaticSignatureCollectionError.limitExceeded("CMS bytes", cms.count, maximumCMSBytes)
        }
        try requireDetachedSignatureCMS(cms)
        try Task.checkCancellation()
        var decoder: CMSDecoder?
        let createStatus = CMSDecoderCreate(&decoder)
        guard createStatus == errSecSuccess, let decoder else {
            throw StaticSignatureCollectionError.nativeOperation("CMSDecoderCreate", createStatus)
        }
        let updateStatus = try cms.withUnsafeBytes { bytes -> OSStatus in
            guard let baseAddress = bytes.baseAddress else {
                throw StaticSignatureCollectionError.invalidNativeField("CMS bytes", "nonempty native byte buffer")
            }
            return CMSDecoderUpdateMessage(decoder, baseAddress, bytes.count)
        }
        guard updateStatus == errSecSuccess else {
            throw StaticSignatureCollectionError.nativeOperation("CMSDecoderUpdateMessage", updateStatus)
        }
        try Task.checkCancellation()
        let finalizeStatus = CMSDecoderFinalizeMessage(decoder)
        guard finalizeStatus == errSecSuccess else {
            throw StaticSignatureCollectionError.nativeOperation("CMSDecoderFinalizeMessage", finalizeStatus)
        }
        var rawCertificates: CFArray?
        let copyStatus = CMSDecoderCopyAllCerts(decoder, &rawCertificates)
        guard copyStatus == errSecSuccess else {
            throw StaticSignatureCollectionError.nativeOperation("CMSDecoderCopyAllCerts", copyStatus)
        }
        let certificates: [SecCertificate]
        if let rawCertificates {
            guard let decoded = rawCertificates as? [SecCertificate],
                decoded.allSatisfy({ CFGetTypeID($0) == SecCertificateGetTypeID() }) else {
                throw StaticSignatureCollectionError.invalidNativeField("CMSDecoderCopyAllCerts", "SecCertificate array")
            }
            guard decoded.count <= maximumCertificates else {
                throw StaticSignatureCollectionError.limitExceeded("CMS certificate count", decoded.count, maximumCertificates)
            }
            certificates = decoded
        } else {
            certificates = []
        }
        let chainFingerprints = try chain.map { certificate -> String in
            try certificateFingerprint(certificate)
        }
        var records: [StaticCertificate] = []
        var failures: [String] = []
        for (index, certificate) in certificates.enumerated() {
            try Task.checkCancellation()
            do {
                let record = try certificateRecord(certificate: certificate, index: index,
                    chainFingerprints: chainFingerprints, location: location)
                records.append(record)
                failures.append(contentsOf: record.warnings.map { "CMS certificate \(index): \($0)" })
            } catch is CancellationError {
                throw CancellationError()
            } catch let error as StaticSignatureCollectionError {
                failures.append("CMS certificate \(index) metadata could not be collected: \(error.localizedDescription)")
            }
        }
        return StaticFeatureCollection(state: failures.isEmpty ? .complete : (records.isEmpty ? .unavailable : .partial),
            reason: failures.first, records: records, limitations: [
                "Only detached DER SignedData wrapping id-data is decoded; encrypted, nested, and indefinite-length CMS envelopes are unsupported.",
                "CMS enumeration order is preserved; it does not establish certificate-chain order.",
                "chain_index is a fingerprint match to Security.framework's returned chain, starting at zero for its leaf.",
                "Certificates are metadata only. No certificate trust, revocation, reputation, or network assessment was performed."
            ] + failures, limits: limits)
    }

    private static func certificateRecord(
        certificate: SecCertificate, index: Int, chainFingerprints: [String], location: StaticEvidenceLocation
    ) throws -> StaticCertificate {
        let data = SecCertificateCopyData(certificate) as Data
        guard !data.isEmpty, data.count <= maximumCertificateBytes else {
            throw StaticSignatureCollectionError.limitExceeded("certificate DER bytes", data.count, maximumCertificateBytes)
        }
        let fingerprint = hex(Data(SHA256.hash(data: data)))
        var warnings: [String] = []
        let subject: [StaticCertificateNameField]
        let issuer: [StaticCertificateNameField]
        let notBefore: Date?
        let notAfter: Date?
        var valueError: Unmanaged<CFError>?
        let keys: [CFString] = [kSecOIDX509V1SubjectName, kSecOIDX509V1IssuerName,
            kSecOIDX509V1ValidityNotBefore, kSecOIDX509V1ValidityNotAfter]
        if let rawValues = SecCertificateCopyValues(certificate, keys as CFArray, &valueError) {
            let values = rawValues as NSDictionary
            do {
                subject = try nameFields(values: values, key: kSecOIDX509V1SubjectName)
            } catch let error as StaticSignatureCollectionError {
                subject = []
                warnings.append("Subject fields unavailable: \(error.localizedDescription)")
            }
            do {
                issuer = try nameFields(values: values, key: kSecOIDX509V1IssuerName)
            } catch let error as StaticSignatureCollectionError {
                issuer = []
                warnings.append("Issuer fields unavailable: \(error.localizedDescription)")
            }
            do {
                notBefore = try certificateDate(values: values, key: kSecOIDX509V1ValidityNotBefore)
            } catch let error as StaticSignatureCollectionError {
                notBefore = nil
                warnings.append("Validity start unavailable: \(error.localizedDescription)")
            }
            do {
                notAfter = try certificateDate(values: values, key: kSecOIDX509V1ValidityNotAfter)
            } catch let error as StaticSignatureCollectionError {
                notAfter = nil
                warnings.append("Validity end unavailable: \(error.localizedDescription)")
            }
        } else {
            subject = []
            issuer = []
            notBefore = nil
            notAfter = nil
            warnings.append("SecCertificateCopyValues returned no certificate metadata.")
        }
        if let valueError {
            let error = valueError.takeRetainedValue()
            warnings.append("SecCertificateCopyValues reported \(nativeErrorDescription(error)).")
        }
        if let notBefore, let notAfter, notBefore > notAfter {
            warnings.append("The certificate validity start is later than its validity end; no trust interpretation was made.")
        }
        var serialError: Unmanaged<CFError>?
        let serialData = SecCertificateCopySerialNumberData(certificate, &serialError)
        let serial: String?
        if let serialData, CFDataGetLength(serialData) > 0, CFDataGetLength(serialData) <= maximumStringBytes {
            serial = hex(serialData as Data)
        } else {
            serial = nil
            warnings.append("SecCertificateCopySerialNumberData returned no bounded serial number.")
        }
        if let serialError {
            let error = serialError.takeRetainedValue()
            warnings.append("SecCertificateCopySerialNumberData reported \(nativeErrorDescription(error)).")
        }
        let summary = SecCertificateCopySubjectSummary(certificate) as String?
        if let summary, summary.utf8.count > maximumStringBytes {
            throw StaticSignatureCollectionError.limitExceeded("certificate subject-summary bytes", summary.utf8.count, maximumStringBytes)
        }
        return StaticCertificate(location: location, source: .cmsEmbedded,
            cmsIndex: index, chainIndex: chainFingerprints.firstIndex(of: fingerprint),
            derSHA256: fingerprint, derByteCount: data.count, subjectSummary: summary,
            subject: subject, issuer: issuer, serialNumber: serial, notBefore: notBefore, notAfter: notAfter,
            metadataState: warnings.isEmpty ? .complete : .partial, warnings: warnings)
    }

    /// Only detached SignedData wrapping id-data reaches CMSDecoder. This prevents its
    /// automatic encrypted-content decryption path from consulting keychain identities.
    /// BER indefinite lengths are unsupported here and produce an explicit collection error.
    private static func requireDetachedSignatureCMS(_ data: Data) throws {
        let signedDataOID = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])
        let dataOID = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01])
        let outer = try derElement(data: data, offset: 0, containerEnd: data.count)
        guard outer.tag == 0x30, outer.end == data.count else {
            throw StaticSignatureCollectionError.invalidNativeField("CMS ContentInfo", "one bounded DER sequence")
        }
        let type = try derElement(data: data, offset: outer.contentStart, containerEnd: outer.end)
        guard type.tag == 0x06, Data(data[type.contentStart..<type.end]) == signedDataOID else {
            throw StaticSignatureCollectionError.invalidNativeField("CMS content type", "SignedData; encrypted CMS is not collected")
        }
        let wrapper = try derElement(data: data, offset: type.end, containerEnd: outer.end)
        guard wrapper.tag == 0xA0, wrapper.end == outer.end else {
            throw StaticSignatureCollectionError.invalidNativeField("CMS SignedData wrapper", "explicit bounded content")
        }
        let signed = try derElement(data: data, offset: wrapper.contentStart, containerEnd: wrapper.end)
        guard signed.tag == 0x30, signed.end == wrapper.end else {
            throw StaticSignatureCollectionError.invalidNativeField("CMS SignedData", "one bounded sequence")
        }
        let version = try derElement(data: data, offset: signed.contentStart, containerEnd: signed.end)
        guard version.tag == 0x02 else {
            throw StaticSignatureCollectionError.invalidNativeField("CMS SignedData version", "DER integer")
        }
        let algorithms = try derElement(data: data, offset: version.end, containerEnd: signed.end)
        guard algorithms.tag == 0x31 else {
            throw StaticSignatureCollectionError.invalidNativeField("CMS digest algorithms", "DER set")
        }
        let encapsulated = try derElement(data: data, offset: algorithms.end, containerEnd: signed.end)
        guard encapsulated.tag == 0x30 else {
            throw StaticSignatureCollectionError.invalidNativeField("CMS encapsulated content", "bounded content-info sequence")
        }
        let encapsulatedType = try derElement(data: data, offset: encapsulated.contentStart, containerEnd: encapsulated.end)
        guard encapsulatedType.tag == 0x06,
            Data(data[encapsulatedType.contentStart..<encapsulatedType.end]) == dataOID,
            encapsulatedType.end == encapsulated.end else {
            throw StaticSignatureCollectionError.invalidNativeField("CMS encapsulated content",
                "detached id-data; nested or encrypted content is not collected")
        }
    }

    private static func derElement(data: Data, offset: Int, containerEnd: Int) throws -> DERElement {
        guard offset >= 0, containerEnd <= data.count, offset <= containerEnd, 2 <= containerEnd - offset else {
            throw StaticSignatureCollectionError.invalidNativeField("CMS DER header", "two bounded tag and length bytes")
        }
        let tag = data[offset]
        let initialLength = data[offset + 1]
        let contentStart: Int
        let length: UInt64
        if initialLength < 0x80 {
            contentStart = offset + 2
            length = UInt64(initialLength)
        } else {
            let count = Int(initialLength & 0x7F)
            guard count > 0, count <= 4, count <= containerEnd - offset - 2 else {
                throw StaticSignatureCollectionError.invalidNativeField("CMS DER length", "bounded definite length; BER indefinite lengths are unsupported")
            }
            contentStart = offset + 2 + count
            let encoded = data[(offset + 2)..<contentStart]
            length = encoded.reduce(0) { ($0 << 8) | UInt64($1) }
            guard encoded.first != 0, length >= 0x80 else {
                throw StaticSignatureCollectionError.invalidNativeField("CMS DER length", "minimal definite-length encoding")
            }
        }
        guard length <= UInt64(containerEnd - contentStart) else {
            throw StaticSignatureCollectionError.invalidNativeField("CMS DER element", "content within its enclosing byte range")
        }
        return DERElement(tag: tag, contentStart: contentStart, end: contentStart + Int(length))
    }

    private static func nameFields(values: NSDictionary, key: CFString) throws -> [StaticCertificateNameField] {
        guard let section = values[key] as? NSDictionary,
            section[kSecPropertyKeyType] as? String == kSecPropertyTypeSection as String,
            let fields = section[kSecPropertyKeyValue] as? [NSDictionary] else {
            throw StaticSignatureCollectionError.invalidNativeField(key as String, "certificate name section")
        }
        guard fields.count <= maximumNameFields else {
            throw StaticSignatureCollectionError.limitExceeded("certificate name fields", fields.count, maximumNameFields)
        }
        return try fields.map { field in
            guard field[kSecPropertyKeyType] as? String == kSecPropertyTypeString as String,
                let oid = field[kSecPropertyKeyLabel] as? String,
                let value = field[kSecPropertyKeyValue] as? String else {
                throw StaticSignatureCollectionError.invalidNativeField(key as String, "OID and string certificate-name values")
            }
            guard !oid.isEmpty, oid.utf8.allSatisfy({ $0 == 46 || (48...57).contains($0) }) else {
                throw StaticSignatureCollectionError.invalidNativeField(key as String, "numeric certificate-name OID")
            }
            guard oid.utf8.count <= maximumStringBytes, value.utf8.count <= maximumStringBytes else {
                throw StaticSignatureCollectionError.limitExceeded("certificate name-string bytes",
                    max(oid.utf8.count, value.utf8.count), maximumStringBytes)
            }
            return StaticCertificateNameField(oid: oid, value: value)
        }
    }

    /// Security.framework's numeric validity properties are CFAbsoluteTime, relative to 2001-01-01 UTC.
    private static func certificateDate(values: NSDictionary, key: CFString) throws -> Date {
        guard let property = values[key] as? NSDictionary,
            let type = property[kSecPropertyKeyType] as? String else {
            throw StaticSignatureCollectionError.invalidNativeField(key as String, "certificate validity property")
        }
        if type == kSecPropertyTypeDate as String, let date = property[kSecPropertyKeyValue] as? Date {
            return date
        }
        guard type == kSecPropertyTypeNumber as String,
            let number = property[kSecPropertyKeyValue] as? NSNumber,
            CFGetTypeID(number) == CFNumberGetTypeID() else {
            throw StaticSignatureCollectionError.invalidNativeField(key as String, "CFAbsoluteTime validity value")
        }
        let interval = number.doubleValue
        guard interval.isFinite, interval >= -63_113_904_000, interval <= 252_423_993_599 else {
            throw StaticSignatureCollectionError.invalidNativeField(key as String, "finite X.509 validity date")
        }
        return Date(timeIntervalSinceReferenceDate: interval)
    }

    private static func certificateFingerprint(_ certificate: SecCertificate) throws -> String {
        guard CFGetTypeID(certificate) == SecCertificateGetTypeID() else {
            throw StaticSignatureCollectionError.invalidNativeField("kSecCodeInfoCertificates", "SecCertificate entry")
        }
        let data = SecCertificateCopyData(certificate) as Data
        guard !data.isEmpty, data.count <= maximumCertificateBytes else {
            throw StaticSignatureCollectionError.limitExceeded("chain certificate DER bytes", data.count, maximumCertificateBytes)
        }
        return hex(Data(SHA256.hash(data: data)))
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static func nativeErrorDescription(_ error: CFError) -> String {
        if let domain = CFErrorGetDomain(error) {
            return "\(domain as String) code \(CFErrorGetCode(error))"
        }
        return "a CFError with no domain and code \(CFErrorGetCode(error))"
    }
}

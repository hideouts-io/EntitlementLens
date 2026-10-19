import Foundation

private struct PersistenceStaticPart {
    let records: [StaticPersistenceCharacteristic]
    let failures: [String]
}

enum PersistenceStaticFeatureCollector {
    private static let maximumConfigurationFiles = 128
    private static let maximumRecords = 512
    private static let launchdKeys = ["Label", "Program", "ProgramArguments", "BundleProgram", "RunAtLoad", "KeepAlive"]
    private static let limitations = [
        "Only selected property lists and conventional Contents bundle configuration/layout paths are inspected.",
        "Declarations and contained login-item layouts do not establish installation, registration, enabled persistence, or execution.",
        "Declared external executables are not followed; privileged helper identifiers are not matched to files by basename.",
        "API references and raw string indications are not collected by this configuration/layout method."
    ]

    static func inspect(sourceURL: URL, kind: FileKind, analyzedPath: String) throws -> StaticFeatureCollection<StaticPersistenceCharacteristic> {
        try Task.checkCancellation()
        let url = sourceURL.standardizedFileURL
        switch kind {
        case .machO, .other:
            return collection(state: .notApplicable, reason: "The selected artifact is neither a property list nor a bundle; configuration/layout collection is not applicable to \(analyzedPath).", records: [])
        case .propertyList:
            do {
                let part = try PersistenceStaticFileReader.withDirectory(at: url.deletingLastPathComponent()) { descriptor in
                    try launchdPart(root: descriptor, relativePath: url.lastPathComponent,
                                    rootURL: url.deletingLastPathComponent(), bundleURL: nil, association: .selectedPropertyList)
                }
                return collection(state: part.records.isEmpty ? .notApplicable : .complete,
                                  reason: part.records.isEmpty ? "The selected property list contains no supported launchd executable declaration." : nil,
                                  records: part.records)
            } catch let error as PersistenceStaticCollectionError {
                if error.containsCancellation { throw error }
                return collection(state: .unavailable, reason: error.localizedDescription, records: [])
            }
        case .bundle:
            do {
                return try PersistenceStaticFileReader.withDirectory(at: url) { descriptor in
                    try bundleCollection(root: descriptor, rootURL: url)
                }
            } catch let error as PersistenceStaticCollectionError {
                if error.containsCancellation { throw error }
                return collection(state: .unavailable, reason: error.localizedDescription, records: [])
            }
        }
    }

    private static func bundleCollection(root: Int32, rootURL: URL) throws -> StaticFeatureCollection<StaticPersistenceCharacteristic> {
        // Frameworks and alternate bundle layouts are reported as unsupported, never silently searched elsewhere.
        do { try PersistenceStaticFileReader.confirmDirectory(root: root, relativePath: "Contents", rootURL: rootURL) }
        catch PersistenceStaticCollectionError.missingPath {
            return collection(state: .unsupported, reason: "This bundle has no conventional Contents directory; alternate bundle layouts are not collected.", records: [])
        }
        var parts: [PersistenceStaticPart] = []
        do { parts.append(try helperPart(root: root, rootURL: rootURL)) }
        catch let error as PersistenceStaticCollectionError { parts.append(try failedPart(error)) }

        var configurationCount = 1
        for directory in ["Contents/Library/LaunchAgents", "Contents/Library/LaunchDaemons"] {
            try Task.checkCancellation()
            let entries: [String]
            do { entries = try PersistenceStaticFileReader.directoryEntries(root: root, relativePath: directory, rootURL: rootURL) }
            catch PersistenceStaticCollectionError.missingPath { continue }
            catch let error as PersistenceStaticCollectionError { parts.append(try failedPart(error)); continue }
            for entry in entries where (entry as NSString).pathExtension.lowercased() == "plist" {
                try Task.checkCancellation()
                guard configurationCount < maximumConfigurationFiles else {
                    parts.append(try failedPart(.limitExceeded(path: rootURL.appendingPathComponent(directory).path, limit: "configuration file count")))
                    break
                }
                configurationCount += 1
                do {
                    parts.append(try launchdPart(root: root, relativePath: directory + "/" + entry, rootURL: rootURL,
                                                bundleURL: rootURL, association: .bundleContained))
                } catch let error as PersistenceStaticCollectionError { parts.append(try failedPart(error)) }
            }
        }
        let loginDirectory = "Contents/Library/LoginItems"
        do {
            let entries = try PersistenceStaticFileReader.directoryEntries(root: root, relativePath: loginDirectory, rootURL: rootURL)
            for entry in entries where (entry as NSString).pathExtension.lowercased() == "app" {
                try Task.checkCancellation()
                guard configurationCount < maximumConfigurationFiles else {
                    parts.append(try failedPart(.limitExceeded(path: rootURL.appendingPathComponent(loginDirectory).path, limit: "configuration file count")))
                    break
                }
                configurationCount += 1
                do { parts.append(try loginItemPart(root: root, relativePath: loginDirectory + "/" + entry, rootURL: rootURL)) }
                catch let error as PersistenceStaticCollectionError { parts.append(try failedPart(error)) }
            }
        } catch PersistenceStaticCollectionError.missingPath { /* An absent scoped directory is a complete observation. */ }
        catch let error as PersistenceStaticCollectionError { parts.append(try failedPart(error)) }

        var failures = parts.flatMap(\.failures)
        let records = parts.flatMap(\.records)
        if records.count > maximumRecords {
            failures.append(PersistenceStaticCollectionError.limitExceeded(path: rootURL.path, limit: "export record count").localizedDescription)
        }
        return collection(state: failures.isEmpty ? .complete : .partial,
                          reason: failures.isEmpty ? nil : failures.joined(separator: "\n"),
                          records: Array(records.prefix(maximumRecords)))
    }

    private static func launchdPart(root: Int32, relativePath: String, rootURL: URL, bundleURL: URL?,
                                    association: StaticPersistenceAssociation) throws -> PersistenceStaticPart {
        let plist = try PersistenceStaticFileReader.propertyList(root: root, relativePath: relativePath, rootURL: rootURL, keys: launchdKeys)
        let path = rootURL.appendingPathComponent(relativePath).path
        let values = plist.values
        guard ["Program", "ProgramArguments", "BundleProgram"].contains(where: { values[$0] != nil }) else {
            return PersistenceStaticPart(records: [], failures: [])
        }
        try validateLaunchd(values: values, path: path)
        let identifier: String?
        if case let .string(label) = values["Label"] { identifier = label }
        else { identifier = nil }
        let records: [StaticPersistenceCharacteristic] = launchdKeys.compactMap { key in
            guard let value = values[key] else { return nil }
            let executablePaths: [String]
            switch (key, value) {
            case ("Program", .string(let program)), ("BundleProgram", .string(let program)):
                executablePaths = [program]
            case ("ProgramArguments", .array(let arguments)):
                if values["Program"] != nil || values["BundleProgram"] != nil { executablePaths = [] }
                else if case let .string(program) = arguments.first { executablePaths = [program] }
                else { executablePaths = [] }
            default: executablePaths = []
            }
            let candidatePath: String?
            if key == "BundleProgram", case let .string(program) = value, let bundleURL {
                candidatePath = bundleURL.appendingPathComponent(program).path
            } else { candidatePath = nil }
            return StaticPersistenceCharacteristic(kind: .launchdDeclaration, declarationKey: key, declarationValue: value,
                declaredIdentifier: identifier, declaredExecutablePaths: executablePaths, association: association,
                bundleProgramCandidatePath: candidatePath, sourceSHA256: plist.sha256, apiReference: nil,
                location: location(path: path, key: key, byteCount: plist.byteCount, method: .propertyList))
        }
        return PersistenceStaticPart(records: records, failures: [])
    }

    private static func helperPart(root: Int32, rootURL: URL) throws -> PersistenceStaticPart {
        let relativePath = "Contents/Info.plist"
        let path = rootURL.appendingPathComponent(relativePath).path
        let plist = try PersistenceStaticFileReader.propertyList(root: root, relativePath: relativePath, rootURL: rootURL, keys: ["SMPrivilegedExecutables"])
        guard let declaration = plist.values["SMPrivilegedExecutables"] else {
            return PersistenceStaticPart(records: [], failures: [])
        }
        guard case let .dictionary(helpers) = declaration,
              helpers.allSatisfy({ nonemptyString($0.value) && !$0.key.isEmpty && !$0.key.contains("\0") }) else {
            throw PersistenceStaticCollectionError.malformedPropertyList(path: path, key: "SMPrivilegedExecutables", expected: "a dictionary of nonempty helper identifiers to requirement strings")
        }
        let records = helpers.sorted { $0.key < $1.key }.map { identifier, requirement in
            StaticPersistenceCharacteristic(kind: .privilegedHelperDeclaration, declarationKey: "SMPrivilegedExecutables",
                declarationValue: .dictionary([identifier: requirement]), declaredIdentifier: identifier,
                declaredExecutablePaths: [], association: .explicitBundleDeclaration, bundleProgramCandidatePath: nil,
                sourceSHA256: plist.sha256, apiReference: nil,
                location: location(path: path, key: "SMPrivilegedExecutables", byteCount: plist.byteCount, method: .propertyList))
        }
        return PersistenceStaticPart(records: records, failures: [])
    }

    private static func loginItemPart(root: Int32, relativePath: String, rootURL: URL) throws -> PersistenceStaticPart {
        let path = rootURL.appendingPathComponent(relativePath).path
        try PersistenceStaticFileReader.confirmDirectory(root: root, relativePath: relativePath, rootURL: rootURL)
        let layout = StaticPersistenceCharacteristic(kind: .loginItemBundle, declarationKey: nil, declarationValue: nil,
            declaredIdentifier: nil, declaredExecutablePaths: [], association: .bundleContained,
            bundleProgramCandidatePath: nil, sourceSHA256: nil, apiReference: nil,
            location: location(path: path, key: nil, byteCount: nil, method: .bundleLayout))
        let infoPath = relativePath + "/Contents/Info.plist"
        do {
            let plist = try PersistenceStaticFileReader.propertyList(root: root, relativePath: infoPath, rootURL: rootURL, keys: ["CFBundleIdentifier", "CFBundleExecutable"])
            let infoURL = rootURL.appendingPathComponent(infoPath)
            guard let executable = plist.values["CFBundleExecutable"], case let .string(name) = executable,
                  validPathComponent(name) else {
                throw PersistenceStaticCollectionError.malformedPropertyList(path: infoURL.path, key: "CFBundleExecutable", expected: "one nonempty executable filename")
            }
            let identifier: String?
            if let value = plist.values["CFBundleIdentifier"] {
                guard case let .string(value) = value, !value.isEmpty, !value.contains("\0") else {
                    throw PersistenceStaticCollectionError.malformedPropertyList(path: infoURL.path, key: "CFBundleIdentifier", expected: "a nonempty identifier string")
                }
                identifier = value
            } else { identifier = nil }
            let declaration = StaticPersistenceCharacteristic(kind: .loginItemExecutableDeclaration, declarationKey: "CFBundleExecutable",
                declarationValue: executable, declaredIdentifier: identifier, declaredExecutablePaths: [name],
                association: .explicitBundleDeclaration, bundleProgramCandidatePath: nil, sourceSHA256: plist.sha256, apiReference: nil,
                location: location(path: infoURL.path, key: "CFBundleExecutable", byteCount: plist.byteCount, method: .propertyList))
            return PersistenceStaticPart(records: [layout, declaration], failures: [])
        } catch let error as PersistenceStaticCollectionError {
            if error.containsCancellation { throw error }
            return PersistenceStaticPart(records: [layout], failures: [error.localizedDescription])
        }
    }

    private static func validateLaunchd(values: [String: EntitlementValue], path: String) throws {
        guard let label = values["Label"], nonemptyString(label) else {
            throw PersistenceStaticCollectionError.malformedPropertyList(path: path, key: "Label", expected: "a nonempty job identifier together with an executable declaration")
        }
        if let program = values["Program"], !nonemptyString(program) {
            throw PersistenceStaticCollectionError.malformedPropertyList(path: path, key: "Program", expected: "a nonempty string")
        }
        if let value = values["ProgramArguments"] {
            guard case let .array(arguments) = value, let first = arguments.first, nonemptyString(first),
                  arguments.allSatisfy({ if case let .string(value) = $0 { return !value.contains("\0") }; return false }) else {
                throw PersistenceStaticCollectionError.malformedPropertyList(path: path, key: "ProgramArguments", expected: "a nonempty array of strings with an executable in the first element")
            }
        }
        if let value = values["BundleProgram"] {
            guard case let .string(program) = value, validRelativePath(program) else {
                throw PersistenceStaticCollectionError.malformedPropertyList(path: path, key: "BundleProgram", expected: "a contained bundle-relative executable path without parent traversal")
            }
        }
        if let value = values["RunAtLoad"], !boolean(value) {
            throw PersistenceStaticCollectionError.malformedPropertyList(path: path, key: "RunAtLoad", expected: "a boolean")
        }
        if let value = values["KeepAlive"], !validKeepAlive(value) {
            throw PersistenceStaticCollectionError.malformedPropertyList(path: path, key: "KeepAlive", expected: "a boolean or supported launchd predicate dictionary")
        }
    }

    private static func validKeepAlive(_ value: EntitlementValue) -> Bool {
        if boolean(value) { return true }
        guard case let .dictionary(predicates) = value else { return false }
        let booleanKeys: Set<String> = ["SuccessfulExit", "NetworkState", "Crashed", "AfterInitialDemand"]
        return predicates.allSatisfy { key, predicate in
            if booleanKeys.contains(key) { return boolean(predicate) }
            if ["PathState", "OtherJobEnabled"].contains(key), case let .dictionary(states) = predicate {
                return states.allSatisfy { !$0.key.isEmpty && !$0.key.contains("\0") && boolean($0.value) }
            }
            return false
        }
    }

    private static func nonemptyString(_ value: EntitlementValue) -> Bool {
        if case let .string(value) = value { return !value.isEmpty && !value.contains("\0") }
        return false
    }

    private static func boolean(_ value: EntitlementValue) -> Bool {
        if case .boolean = value { return true }
        return false
    }

    private static func validPathComponent(_ value: String) -> Bool {
        !value.isEmpty && value != "." && value != ".." && !value.contains("/") && !value.contains("\0")
    }

    private static func validRelativePath(_ value: String) -> Bool {
        let components = value.split(separator: "/", omittingEmptySubsequences: false)
        return !components.isEmpty && components.count <= PersistenceStaticFileReader.maximumPathDepth
            && components.allSatisfy { validPathComponent(String($0)) }
    }

    private static func location(path: String, key: String?, byteCount: UInt64?, method: StaticEvidenceMethod) -> StaticEvidenceLocation {
        StaticEvidenceLocation(sourcePath: path, architecture: nil, sliceOffset: nil, fileOffset: nil,
                               byteCount: byteCount, propertyListKey: key, method: method)
    }

    private static func failedPart(_ error: PersistenceStaticCollectionError) throws -> PersistenceStaticPart {
        if error.containsCancellation { throw error }
        return PersistenceStaticPart(records: [], failures: [error.localizedDescription])
    }

    private static func collection(state: StaticCollectionState, reason: String?, records: [StaticPersistenceCharacteristic]) -> StaticFeatureCollection<StaticPersistenceCharacteristic> {
        StaticFeatureCollection(state: state, reason: reason, records: records, limitations: limitations, limits: [
            StaticCollectionLimit(name: "property_list_bytes", value: UInt64(PersistenceStaticFileReader.maximumFileBytes), unit: .bytes),
            StaticCollectionLimit(name: "configuration_files", value: UInt64(maximumConfigurationFiles), unit: .records),
            StaticCollectionLimit(name: "directory_entries", value: UInt64(PersistenceStaticFileReader.maximumDirectoryEntries), unit: .records),
            StaticCollectionLimit(name: "persistence_records", value: UInt64(maximumRecords), unit: .records),
            StaticCollectionLimit(name: "container_members", value: UInt64(PersistenceStaticFileReader.maximumContainerMembers), unit: .records),
            StaticCollectionLimit(name: "value_nodes", value: UInt64(PersistenceStaticFileReader.maximumValueNodes), unit: .records),
            StaticCollectionLimit(name: "value_depth", value: UInt64(PersistenceStaticFileReader.maximumValueDepth), unit: .depth),
            StaticCollectionLimit(name: "relative_path_depth", value: UInt64(PersistenceStaticFileReader.maximumPathDepth), unit: .depth),
            StaticCollectionLimit(name: "string_bytes", value: UInt64(PersistenceStaticFileReader.maximumStringBytes), unit: .bytes)
        ])
    }
}

import AppKit
import CryptoKit
import Foundation
import Virtualization

private let gibibyte = UInt64(1024 * 1024 * 1024)
private let guestProtocol: UInt16 = 2
private let guestPort: UInt32 = 10250

private enum ToolFailure: Error {
  case invalidArguments
  case invalidArtifact
  case unsupportedRestoreImage
  case installationFailed
}

private final class ResultBox<Value> {
  var value: Result<Value, Error>?
}

private final class BootController: NSObject, NSWindowDelegate {
  private let machine: VZVirtualMachine
  private let window: NSWindow

  init(machine: VZVirtualMachine) {
    self.machine = machine
    let frame = NSRect(x: 0, y: 0, width: 1280, height: 800)
    window = NSWindow(
      contentRect: frame,
      styleMask: [.titled, .closable, .miniaturizable, .resizable],
      backing: .buffered,
      defer: false
    )
    let view = VZVirtualMachineView(frame: frame)
    view.autoresizingMask = [.width, .height]
    view.virtualMachine = machine
    view.capturesSystemKeys = true
    window.contentView = view
    window.title = "Automata macOS template provisioning"
    super.init()
    window.delegate = self
  }

  func start() {
    window.center()
    window.makeKeyAndOrderFront(nil)
    NSApplication.shared.activate(ignoringOtherApps: true)
    machine.start { result in
      if case .failure = result {
        NSApplication.shared.terminate(nil)
      }
    }
  }

  func windowWillClose(_ notification: Notification) {
    guard machine.canStop else {
      NSApplication.shared.terminate(nil)
      return
    }
    machine.stop { _ in NSApplication.shared.terminate(nil) }
  }
}

private struct GuestIdentity: Decodable {
  let profileID: String
  let guestAgentSHA256: String
  let macOSVersion: String
  let macOSBuild: String
  let architecture: String
  let jobUID: UInt32
  let jobGID: UInt32
  let processLimit: UInt32

  private enum CodingKeys: String, CodingKey {
    case profileID = "profile_id"
    case guestAgentSHA256 = "guest_agent_sha256"
    case macOSVersion = "macos_version"
    case macOSBuild = "macos_build"
    case architecture
    case jobUID = "job_uid"
    case jobGID = "job_gid"
    case processLimit = "process_limit"
  }
}

private struct InstallRequirements: Codable {
  let minimumCPUCount: UInt32
  let minimumMemoryBytes: UInt64

  private enum CodingKeys: String, CodingKey {
    case minimumCPUCount = "minimum_cpu_count"
    case minimumMemoryBytes = "minimum_memory_bytes"
  }
}

private struct Artifact: Encodable {
  let path: String
  let sha256: String
}

private struct TemplateManifest: Encodable {
  let schemaVersion: UInt16
  let profileID: String
  let macOSVersion: String
  let macOSBuild: String
  let architecture: String
  let diskImage: Artifact
  let auxiliaryStorage: Artifact
  let hardwareModelBase64: String
  let guestAgentSHA256: String
  let guestProtocol: UInt16
  let guestPort: UInt32
  let jobUID: UInt32
  let jobGID: UInt32
  let processLimit: UInt32
  let minimumCPUCount: UInt32
  let minimumMemoryBytes: UInt64

  private enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case profileID = "profile_id"
    case macOSVersion = "macos_version"
    case macOSBuild = "macos_build"
    case architecture
    case diskImage = "disk_image"
    case auxiliaryStorage = "auxiliary_storage"
    case hardwareModelBase64 = "hardware_model_base64"
    case guestAgentSHA256 = "guest_agent_sha256"
    case guestProtocol = "guest_protocol"
    case guestPort = "guest_port"
    case jobUID = "job_uid"
    case jobGID = "job_gid"
    case processLimit = "process_limit"
    case minimumCPUCount = "minimum_cpu_count"
    case minimumMemoryBytes = "minimum_memory_bytes"
  }
}

private func normalizedAbsolute(_ value: String) -> URL? {
  guard value.hasPrefix("/"), !value.contains("\0") else { return nil }
  let url = URL(fileURLWithPath: value).standardizedFileURL
  return url.path == value ? url : nil
}

private func disjoint(_ left: URL, _ right: URL) -> Bool {
  let leftComponents = left.pathComponents
  let rightComponents = right.pathComponents
  return !leftComponents.starts(with: rightComponents)
    && !rightComponents.starts(with: leftComponents)
}

private func supportedMacOSVersion(_ value: String) -> Bool {
  let components = value.split(separator: ".", omittingEmptySubsequences: false)
  guard let first = components.first, let major = UInt(first), major >= 15 else { return false }
  return components.allSatisfy { component in
    !component.isEmpty && component.utf8.count <= 4
      && component.utf8.allSatisfy { byte in byte >= 48 && byte <= 57 }
  }
}

private func wait<Value>(
  start: (@escaping (Result<Value, Error>) -> Void) -> Void
) throws -> Value {
  let semaphore = DispatchSemaphore(value: 0)
  let box = ResultBox<Value>()
  start { result in
    box.value = result
    semaphore.signal()
  }
  semaphore.wait()
  guard let result = box.value else { throw ToolFailure.installationFailed }
  return try result.get()
}

private func loadRestoreImage(_ url: URL) throws -> VZMacOSRestoreImage {
  try wait { completion in
    VZMacOSRestoreImage.load(from: url, completionHandler: completion)
  }
}

private func createDisk(at url: URL, bytes: UInt64) throws {
  guard FileManager.default.createFile(atPath: url.path, contents: nil) else {
    throw ToolFailure.invalidArtifact
  }
  let handle = try FileHandle(forWritingTo: url)
  try handle.truncate(atOffset: bytes)
  try handle.synchronize()
  try handle.close()
}

private func virtualMachineConfiguration(
  disk: URL,
  auxiliary: VZMacAuxiliaryStorage,
  hardwareModel: VZMacHardwareModel,
  machineIdentifier: VZMacMachineIdentifier,
  cpuCount: Int,
  memoryBytes: UInt64,
  provisioningDirectory: URL? = nil,
  outputDirectory: URL? = nil
) throws -> VZVirtualMachineConfiguration {
  let platform = VZMacPlatformConfiguration()
  platform.hardwareModel = hardwareModel
  platform.machineIdentifier = machineIdentifier
  platform.auxiliaryStorage = auxiliary
  let attachment = try VZDiskImageStorageDeviceAttachment(
    url: disk,
    readOnly: false,
    cachingMode: .automatic,
    synchronizationMode: .full
  )
  let display = VZMacGraphicsDisplayConfiguration(
    widthInPixels: 1280,
    heightInPixels: 800,
    pixelsPerInch: 80
  )
  let graphics = VZMacGraphicsDeviceConfiguration()
  graphics.displays = [display]
  let configuration = VZVirtualMachineConfiguration()
  configuration.platform = platform
  configuration.bootLoader = VZMacOSBootLoader()
  configuration.cpuCount = cpuCount
  configuration.memorySize = memoryBytes
  configuration.storageDevices = [VZVirtioBlockDeviceConfiguration(attachment: attachment)]
  configuration.graphicsDevices = [graphics]
  configuration.keyboards = [VZUSBKeyboardConfiguration()]
  configuration.pointingDevices = [VZUSBScreenCoordinatePointingDeviceConfiguration()]
  configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
  configuration.socketDevices = [VZVirtioSocketDeviceConfiguration()]
  configuration.networkDevices = []
  if let provisioningDirectory, let outputDirectory {
    let share = VZMultipleDirectoryShare(directories: [
      "Output": VZSharedDirectory(url: outputDirectory, readOnly: false),
      "Provisioning": VZSharedDirectory(url: provisioningDirectory, readOnly: true),
    ])
    let sharing = VZVirtioFileSystemDeviceConfiguration(
      tag: VZVirtioFileSystemDeviceConfiguration.macOSGuestAutomountTag
    )
    sharing.share = share
    configuration.directorySharingDevices = [sharing]
  } else {
    configuration.directorySharingDevices = []
  }
  try configuration.validate()
  return configuration
}

private func install(arguments: ArraySlice<String>) throws {
  guard arguments.count == 5,
    let restoreURL = normalizedAbsolute(arguments[arguments.startIndex]),
    let outputURL = normalizedAbsolute(
      arguments[arguments.index(arguments.startIndex, offsetBy: 1)]),
    let diskGiB = UInt64(arguments[arguments.index(arguments.startIndex, offsetBy: 2)]),
    let cpuCount = Int(arguments[arguments.index(arguments.startIndex, offsetBy: 3)]),
    let memoryGiB = UInt64(arguments[arguments.index(arguments.startIndex, offsetBy: 4)]),
    FileManager.default.fileExists(atPath: restoreURL.path),
    !FileManager.default.fileExists(atPath: outputURL.path),
    (64...1024).contains(diskGiB),
    (1...1024).contains(memoryGiB),
    cpuCount > 0
  else {
    throw ToolFailure.invalidArguments
  }
  let (diskBytes, diskOverflow) = diskGiB.multipliedReportingOverflow(by: gibibyte)
  let (memoryBytes, memoryOverflow) = memoryGiB.multipliedReportingOverflow(by: gibibyte)
  guard !diskOverflow, !memoryOverflow else { throw ToolFailure.invalidArguments }
  try FileManager.default.createDirectory(
    at: outputURL,
    withIntermediateDirectories: false,
    attributes: [.posixPermissions: 0o700]
  )
  let restore = try loadRestoreImage(restoreURL)
  guard let requirements = restore.mostFeaturefulSupportedConfiguration,
    requirements.hardwareModel.isSupported,
    cpuCount >= requirements.minimumSupportedCPUCount,
    memoryBytes >= requirements.minimumSupportedMemorySize
  else {
    throw ToolFailure.unsupportedRestoreImage
  }
  let diskURL = outputURL.appendingPathComponent("Disk.img")
  let auxiliaryURL = outputURL.appendingPathComponent("AuxiliaryStorage")
  let hardwareURL = outputURL.appendingPathComponent("HardwareModel.bin")
  let machineURL = outputURL.appendingPathComponent("MachineIdentifier.bin")
  let requirementsURL = outputURL.appendingPathComponent("InstallRequirements.json")
  try createDisk(at: diskURL, bytes: diskBytes)
  let hardwareModel = requirements.hardwareModel
  let auxiliary = try VZMacAuxiliaryStorage(
    creatingStorageAt: auxiliaryURL,
    hardwareModel: hardwareModel,
    options: []
  )
  let machineIdentifier = VZMacMachineIdentifier()
  try hardwareModel.dataRepresentation.write(to: hardwareURL, options: .atomic)
  try machineIdentifier.dataRepresentation.write(to: machineURL, options: .atomic)
  try JSONEncoder().encode(
    InstallRequirements(
      minimumCPUCount: UInt32(requirements.minimumSupportedCPUCount),
      minimumMemoryBytes: requirements.minimumSupportedMemorySize
    )
  ).write(to: requirementsURL, options: .atomic)
  let configuration = try virtualMachineConfiguration(
    disk: diskURL,
    auxiliary: auxiliary,
    hardwareModel: hardwareModel,
    machineIdentifier: machineIdentifier,
    cpuCount: cpuCount,
    memoryBytes: memoryBytes
  )
  let queue = DispatchQueue(label: "dev.automata.macos-template-install")
  let machine = VZVirtualMachine(configuration: configuration, queue: queue)
  let installer: VZMacOSInstaller = queue.sync {
    VZMacOSInstaller(virtualMachine: machine, restoringFromImageAt: restoreURL)
  }
  try wait { completion in
    queue.async { installer.install(completionHandler: completion) }
  } as Void
}

private func sha256(_ url: URL) throws -> String {
  let handle = try FileHandle(forReadingFrom: url)
  defer { try? handle.close() }
  var digest = SHA256()
  while let data = try handle.read(upToCount: 1024 * 1024), !data.isEmpty {
    digest.update(data: data)
  }
  return digest.finalize().map { String(format: "%02x", $0) }.joined()
}

private func seal(arguments: ArraySlice<String>) throws {
  guard arguments.count == 4,
    let templateURL = normalizedAbsolute(arguments[arguments.startIndex]),
    let identityURL = normalizedAbsolute(
      arguments[arguments.index(arguments.startIndex, offsetBy: 1)]),
    let guestAgentURL = normalizedAbsolute(
      arguments[arguments.index(arguments.startIndex, offsetBy: 2)]),
    let manifestURL = normalizedAbsolute(
      arguments[arguments.index(arguments.startIndex, offsetBy: 3)])
  else {
    throw ToolFailure.invalidArguments
  }
  let diskURL = templateURL.appendingPathComponent("Disk.img")
  let auxiliaryURL = templateURL.appendingPathComponent("AuxiliaryStorage")
  let hardwareURL = templateURL.appendingPathComponent("HardwareModel.bin")
  let requirementsURL = templateURL.appendingPathComponent("InstallRequirements.json")
  guard
    [diskURL, auxiliaryURL, hardwareURL, requirementsURL, identityURL, guestAgentURL].allSatisfy({
      FileManager.default.fileExists(atPath: $0.path)
    }), !FileManager.default.fileExists(atPath: manifestURL.path)
  else {
    throw ToolFailure.invalidArtifact
  }
  let identity = try JSONDecoder().decode(GuestIdentity.self, from: Data(contentsOf: identityURL))
  let requirements = try JSONDecoder().decode(
    InstallRequirements.self,
    from: Data(contentsOf: requirementsURL)
  )
  let observedGuestAgentSHA256 = try sha256(guestAgentURL)
  guard identity.architecture == "arm64",
    identity.jobUID >= 500,
    identity.jobGID >= 500,
    identity.processLimit > 0,
    requirements.minimumCPUCount > 0,
    requirements.minimumMemoryBytes >= 16 * 1024 * 1024,
    identity.guestAgentSHA256 == observedGuestAgentSHA256,
    !identity.profileID.isEmpty,
    supportedMacOSVersion(identity.macOSVersion),
    !identity.macOSBuild.isEmpty
  else {
    throw ToolFailure.invalidArtifact
  }
  let manifest = TemplateManifest(
    schemaVersion: 1,
    profileID: identity.profileID,
    macOSVersion: identity.macOSVersion,
    macOSBuild: identity.macOSBuild,
    architecture: identity.architecture,
    diskImage: Artifact(path: diskURL.path, sha256: try sha256(diskURL)),
    auxiliaryStorage: Artifact(path: auxiliaryURL.path, sha256: try sha256(auxiliaryURL)),
    hardwareModelBase64: try Data(contentsOf: hardwareURL).base64EncodedString(),
    guestAgentSHA256: identity.guestAgentSHA256,
    guestProtocol: guestProtocol,
    guestPort: guestPort,
    jobUID: identity.jobUID,
    jobGID: identity.jobGID,
    processLimit: identity.processLimit,
    minimumCPUCount: requirements.minimumCPUCount,
    minimumMemoryBytes: requirements.minimumMemoryBytes
  )
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
  var data = try encoder.encode(manifest)
  data.append(0x0a)
  try data.write(to: manifestURL, options: .withoutOverwriting)
}

private func boot(arguments: ArraySlice<String>) throws {
  guard arguments.count == 3 || arguments.count == 7,
    let templateURL = normalizedAbsolute(arguments[arguments.startIndex]),
    let cpuCount = Int(arguments[arguments.index(arguments.startIndex, offsetBy: 1)]),
    let memoryGiB = UInt64(arguments[arguments.index(arguments.startIndex, offsetBy: 2)]),
    cpuCount > 0,
    (1...1024).contains(memoryGiB)
  else {
    throw ToolFailure.invalidArguments
  }
  let provisioningDirectory: URL?
  let outputDirectory: URL?
  if arguments.count == 7 {
    guard
      arguments[arguments.index(arguments.startIndex, offsetBy: 3)] == "--provisioning-directory",
      let provisioning = normalizedAbsolute(
        arguments[arguments.index(arguments.startIndex, offsetBy: 4)]),
      arguments[arguments.index(arguments.startIndex, offsetBy: 5)] == "--output-directory",
      let output = normalizedAbsolute(
        arguments[arguments.index(arguments.startIndex, offsetBy: 6)]),
      (try? provisioning.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true,
      (try? output.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true,
      disjoint(provisioning, output),
      (try? FileManager.default.contentsOfDirectory(atPath: output.path).isEmpty) == true
    else {
      throw ToolFailure.invalidArguments
    }
    provisioningDirectory = provisioning
    outputDirectory = output
  } else {
    provisioningDirectory = nil
    outputDirectory = nil
  }
  let (memoryBytes, overflow) = memoryGiB.multipliedReportingOverflow(by: gibibyte)
  guard !overflow,
    let hardwareModel = VZMacHardwareModel(
      dataRepresentation: try Data(
        contentsOf: templateURL.appendingPathComponent("HardwareModel.bin")
      )
    ),
    hardwareModel.isSupported,
    let machineIdentifier = VZMacMachineIdentifier(
      dataRepresentation: try Data(
        contentsOf: templateURL.appendingPathComponent("MachineIdentifier.bin")
      )
    )
  else {
    throw ToolFailure.invalidArtifact
  }
  let auxiliary = VZMacAuxiliaryStorage(
    contentsOf: templateURL.appendingPathComponent("AuxiliaryStorage")
  )
  let configuration = try virtualMachineConfiguration(
    disk: templateURL.appendingPathComponent("Disk.img"),
    auxiliary: auxiliary,
    hardwareModel: hardwareModel,
    machineIdentifier: machineIdentifier,
    cpuCount: cpuCount,
    memoryBytes: memoryBytes,
    provisioningDirectory: provisioningDirectory,
    outputDirectory: outputDirectory
  )
  let application = NSApplication.shared
  application.setActivationPolicy(.regular)
  let machine = VZVirtualMachine(configuration: configuration, queue: .main)
  let controller = BootController(machine: machine)
  controller.start()
  withExtendedLifetime(controller) { application.run() }
}

private func main() -> Int32 {
  guard CommandLine.arguments.count >= 2 else { return 64 }
  do {
    switch CommandLine.arguments[1] {
    case "install":
      try install(arguments: CommandLine.arguments.dropFirst(2))
    case "boot":
      try boot(arguments: CommandLine.arguments.dropFirst(2))
    case "seal":
      try seal(arguments: CommandLine.arguments.dropFirst(2))
    default:
      throw ToolFailure.invalidArguments
    }
    return 0
  } catch {
    return 70
  }
}

exit(main())

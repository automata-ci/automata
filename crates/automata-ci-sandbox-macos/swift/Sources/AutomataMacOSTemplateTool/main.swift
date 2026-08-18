import AppKit
import CryptoKit
import Darwin
import Foundation
import Virtualization

private let gibibyte = UInt64(1024 * 1024 * 1024)
private let guestProtocol: UInt16 = 2
private let guestPort: UInt32 = 10250

private enum ToolFailure: Error, CustomStringConvertible {
  case invalidArguments
  case invalidArtifact
  case unsupportedRestoreImage
  case installationFailed

  var description: String {
    switch self {
    case .invalidArguments:
      return "invalid arguments"
    case .invalidArtifact:
      return "invalid or incomplete template artifact"
    case .unsupportedRestoreImage:
      return "restore image is not supported by this host or the requested VM resources"
    case .installationFailed:
      return "macOS installation did not return a result"
    }
  }
}

private func report(_ error: Error) {
  let message: String
  if let failure = error as? ToolFailure {
    message = failure.description
  } else {
    let failure = error as NSError
    message = "\(failure.localizedDescription) (\(failure.domain) error \(failure.code))"
  }
  FileHandle.standardError.write(Data("automata-macos-template-tool: \(message)\n".utf8))
}

private final class ResultBox<Value> {
  var value: Result<Value, Error>?
}

private final class BootController: NSObject, NSWindowDelegate, VZVirtualMachineDelegate {
  private let machine: VZVirtualMachine
  private let screenshotURL: URL?
  private let view: VZVirtualMachineView
  private let window: NSWindow
  private var inputBuffer = Data()
  private var inputSource: DispatchSourceRead?
  private var stopping = false

  init(machine: VZVirtualMachine, screenshotURL: URL?) {
    self.machine = machine
    self.screenshotURL = screenshotURL
    let frame = NSRect(x: 0, y: 0, width: 1280, height: 800)
    window = NSWindow(
      contentRect: frame,
      styleMask: [.titled, .closable, .miniaturizable, .resizable],
      backing: .buffered,
      defer: false
    )
    view = VZVirtualMachineView(frame: frame)
    view.autoresizingMask = [.width, .height]
    view.virtualMachine = machine
    view.capturesSystemKeys = true
    window.contentView = view
    window.title = "Automata macOS template provisioning"
    super.init()
    window.delegate = self
    machine.delegate = self
  }

  func start() {
    window.center()
    window.makeKeyAndOrderFront(nil)
    window.makeFirstResponder(view)
    NSApplication.shared.activate(ignoringOtherApps: true)
    machine.start { result in
      if case .failure = result {
        NSApplication.shared.terminate(nil)
      }
    }
    if screenshotURL != nil {
      startInput()
      respond("ready")
    }
  }

  func windowWillClose(_ notification: Notification) {
    stop()
  }

  func guestDidStop(_ virtualMachine: VZVirtualMachine) {
    inputSource?.cancel()
    NSApplication.shared.terminate(nil)
  }

  func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: any Error) {
    report(error)
    inputSource?.cancel()
    NSApplication.shared.terminate(nil)
  }

  private func stop() {
    guard !stopping else { return }
    stopping = true
    inputSource?.cancel()
    guard machine.canStop else {
      NSApplication.shared.terminate(nil)
      return
    }
    machine.stop { _ in NSApplication.shared.terminate(nil) }
  }

  private func startInput() {
    let source = DispatchSource.makeReadSource(fileDescriptor: STDIN_FILENO, queue: .main)
    source.setEventHandler { [weak self] in self?.readInput() }
    inputSource = source
    source.resume()
  }

  private func readInput() {
    var bytes = [UInt8](repeating: 0, count: 4096)
    let count = Darwin.read(STDIN_FILENO, &bytes, bytes.count)
    guard count > 0 else {
      stop()
      return
    }
    inputBuffer.append(contentsOf: bytes.prefix(count))
    guard inputBuffer.count <= 64 * 1024 else {
      respond("error input-too-large")
      stop()
      return
    }
    while let newline = inputBuffer.firstIndex(of: 0x0a) {
      let line = inputBuffer.prefix(upTo: newline)
      inputBuffer.removeSubrange(...newline)
      guard let command = String(data: line, encoding: .utf8) else {
        respond("error invalid-utf8")
        continue
      }
      handle(command)
    }
  }

  private func handle(_ command: String) {
    let fields = command.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
    guard let operation = fields.first else {
      respond("error empty-command")
      return
    }
    do {
      switch operation {
      case "capture" where fields.count == 1:
        try capture()
      case "click" where fields.count == 3:
        guard let x = Double(fields[1]), let y = Double(fields[2]) else {
          throw ToolFailure.invalidArguments
        }
        try click(x: x, y: y)
      case "key" where fields.count == 2:
        guard let keyCode = UInt16(fields[1]) else {
          throw ToolFailure.invalidArguments
        }
        sendKey(keyCode, characters: "")
      case "type" where fields.count == 2:
        guard let data = Data(base64Encoded: String(fields[1])),
          let text = String(data: data, encoding: .utf8)
        else {
          throw ToolFailure.invalidArguments
        }
        try type(text)
      case "stop" where fields.count == 1:
        respond("ok stop")
        stop()
        return
      case "shutdown" where fields.count == 1:
        try machine.requestStop()
      default:
        throw ToolFailure.invalidArguments
      }
      respond("ok \(operation)")
    } catch {
      respond("error \(error)")
    }
  }

  private func capture() throws {
    guard let screenshotURL,
      let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds)
    else {
      throw ToolFailure.invalidArtifact
    }
    view.cacheDisplay(in: view.bounds, to: bitmap)
    guard let png = bitmap.representation(using: .png, properties: [:]) else {
      throw ToolFailure.invalidArtifact
    }
    try png.write(to: screenshotURL, options: .atomic)
  }

  private func click(x: Double, y: Double) throws {
    guard x >= 0, y >= 0, x < view.bounds.width, y < view.bounds.height else {
      throw ToolFailure.invalidArguments
    }
    let location = NSPoint(x: x, y: view.bounds.height - y)
    guard
      let move = NSEvent.mouseEvent(
        with: .mouseMoved,
        location: location,
        modifierFlags: [],
        timestamp: ProcessInfo.processInfo.systemUptime,
        windowNumber: window.windowNumber,
        context: nil,
        eventNumber: 0,
        clickCount: 0,
        pressure: 0
      )
    else {
      throw ToolFailure.invalidArguments
    }
    view.mouseMoved(with: move)
    usleep(50_000)
    for type: NSEvent.EventType in [.leftMouseDown, .leftMouseUp] {
      guard
        let event = NSEvent.mouseEvent(
          with: type,
          location: location,
          modifierFlags: [],
          timestamp: ProcessInfo.processInfo.systemUptime,
          windowNumber: window.windowNumber,
          context: nil,
          eventNumber: 0,
          clickCount: 1,
          pressure: type == .leftMouseDown ? 1 : 0
        )
      else {
        throw ToolFailure.invalidArguments
      }
      if type == .leftMouseDown {
        view.mouseDown(with: event)
        usleep(50_000)
      } else {
        view.mouseUp(with: event)
      }
    }
  }

  private func type(_ text: String) throws {
    guard text.utf8.count <= 16 * 1024 else { throw ToolFailure.invalidArguments }
    let keyCodes = try text.map { character in
      guard let keyCode = keyCode(for: character) else { throw ToolFailure.invalidArguments }
      return (keyCode, String(character))
    }
    for (keyCode, character) in keyCodes {
      sendKey(keyCode, characters: character)
      usleep(1_000)
    }
  }

  private func sendKey(_ keyCode: UInt16, characters: String) {
    for type: NSEvent.EventType in [.keyDown, .keyUp] {
      guard
        let event = NSEvent.keyEvent(
          with: type,
          location: .zero,
          modifierFlags: [],
          timestamp: ProcessInfo.processInfo.systemUptime,
          windowNumber: window.windowNumber,
          context: nil,
          characters: characters,
          charactersIgnoringModifiers: characters,
          isARepeat: false,
          keyCode: keyCode
        )
      else { continue }
      if type == .keyDown {
        view.keyDown(with: event)
      } else {
        view.keyUp(with: event)
      }
      usleep(1_000)
    }
  }

  private func respond(_ response: String) {
    FileHandle.standardOutput.write(Data("\(response)\n".utf8))
  }
}

private let unmodifiedKeyCodes: [Character: UInt16] = [
  "a": 0, "s": 1, "d": 2, "f": 3, "h": 4, "g": 5, "z": 6, "x": 7,
  "c": 8, "v": 9, "b": 11, "q": 12, "w": 13, "e": 14, "r": 15,
  "y": 16, "t": 17, "1": 18, "2": 19, "3": 20, "4": 21, "6": 22,
  "5": 23, "=": 24, "9": 25, "7": 26, "-": 27, "8": 28, "0": 29,
  "]": 30, "o": 31, "u": 32, "[": 33, "i": 34, "p": 35, "\n": 36,
  "l": 37, "j": 38, "'": 39, "k": 40, ";": 41, "\\": 42, ",": 43,
  "/": 44, "n": 45, "m": 46, ".": 47, "\t": 48, " ": 49, "`": 50,
]

private func keyCode(for character: Character) -> UInt16? {
  unmodifiedKeyCodes[character]
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

private func prepareInstallDirectory(_ url: URL) throws {
  let manager = FileManager.default
  var isDirectory = ObjCBool(false)
  if manager.fileExists(atPath: url.path, isDirectory: &isDirectory) {
    let attributes = try manager.attributesOfItem(atPath: url.path)
    guard isDirectory.boolValue,
      attributes[.type] as? FileAttributeType == .typeDirectory,
      (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == geteuid(),
      (attributes[.posixPermissions] as? NSNumber)?.uint16Value == 0o700,
      try manager.contentsOfDirectory(atPath: url.path).isEmpty
    else {
      throw ToolFailure.invalidArtifact
    }
    return
  }
  try manager.createDirectory(
    at: url,
    withIntermediateDirectories: false,
    attributes: [.posixPermissions: 0o700]
  )
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
    (64...1024).contains(diskGiB),
    (1...1024).contains(memoryGiB),
    cpuCount > 0
  else {
    throw ToolFailure.invalidArguments
  }
  let (diskBytes, diskOverflow) = diskGiB.multipliedReportingOverflow(by: gibibyte)
  let (memoryBytes, memoryOverflow) = memoryGiB.multipliedReportingOverflow(by: gibibyte)
  guard !diskOverflow, !memoryOverflow else { throw ToolFailure.invalidArguments }
  try prepareInstallDirectory(outputURL)
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
  guard [3, 5, 7, 9].contains(arguments.count),
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
  if arguments.count == 7 || arguments.count == 9 {
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
  let screenshotURL: URL?
  if arguments.count == 5 || arguments.count == 9 {
    let optionOffset = arguments.count == 5 ? 3 : 7
    guard
      arguments[arguments.index(arguments.startIndex, offsetBy: optionOffset)]
        == "--control-screenshot",
      let screenshot = normalizedAbsolute(
        arguments[arguments.index(arguments.startIndex, offsetBy: optionOffset + 1)]),
      !FileManager.default.fileExists(atPath: screenshot.path),
      (try? screenshot.deletingLastPathComponent().resourceValues(forKeys: [.isDirectoryKey]))?
        .isDirectory == true
    else {
      throw ToolFailure.invalidArguments
    }
    screenshotURL = screenshot
  } else {
    screenshotURL = nil
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
  let controller = BootController(machine: machine, screenshotURL: screenshotURL)
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
    report(error)
    return 70
  }
}

exit(main())

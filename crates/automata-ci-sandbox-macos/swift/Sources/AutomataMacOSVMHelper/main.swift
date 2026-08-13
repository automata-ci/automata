import Darwin
import Foundation
import Virtualization

private let helperProtocol: UInt16 = 1
private let maximumFrameBytes = 32 * 1024 * 1024
private let launchRequestKeys: Set<String> = [
  "protocol", "attempt_id", "source_disk_image", "source_auxiliary_storage",
  "attempt_directory", "hardware_model_base64", "cpu_count", "memory_bytes",
  "process_limit", "guest_port", "guest_protocol", "expected_profile_id",
  "guest_agent_sha256", "expected_macos_version", "expected_macos_build",
  "expected_architecture", "expected_job_uid", "expected_job_gid",
  "expected_process_limit", "minimum_cpu_count", "minimum_memory_bytes",
  "handshake_nonce", "boot_timeout_millis", "stop_timeout_millis",
]

private struct LaunchRequest: Decodable {
  let protocolVersion: UInt16
  let attemptID: String
  let sourceDiskImage: String
  let sourceAuxiliaryStorage: String
  let attemptDirectory: String
  let hardwareModelBase64: String
  let cpuCount: UInt32
  let memoryBytes: UInt64
  let processLimit: UInt32
  let guestPort: UInt32
  let guestProtocol: UInt16
  let expectedProfileID: String
  let guestAgentSHA256: String
  let expectedMacOSVersion: String
  let expectedMacOSBuild: String
  let expectedArchitecture: String
  let expectedJobUID: UInt32
  let expectedJobGID: UInt32
  let expectedProcessLimit: UInt32
  let minimumCPUCount: UInt32
  let minimumMemoryBytes: UInt64
  let handshakeNonce: String
  let bootTimeoutMillis: UInt64
  let stopTimeoutMillis: UInt64

  private enum CodingKeys: String, CodingKey {
    case protocolVersion = "protocol"
    case attemptID = "attempt_id"
    case sourceDiskImage = "source_disk_image"
    case sourceAuxiliaryStorage = "source_auxiliary_storage"
    case attemptDirectory = "attempt_directory"
    case hardwareModelBase64 = "hardware_model_base64"
    case cpuCount = "cpu_count"
    case memoryBytes = "memory_bytes"
    case processLimit = "process_limit"
    case guestPort = "guest_port"
    case guestProtocol = "guest_protocol"
    case expectedProfileID = "expected_profile_id"
    case guestAgentSHA256 = "guest_agent_sha256"
    case expectedMacOSVersion = "expected_macos_version"
    case expectedMacOSBuild = "expected_macos_build"
    case expectedArchitecture = "expected_architecture"
    case expectedJobUID = "expected_job_uid"
    case expectedJobGID = "expected_job_gid"
    case expectedProcessLimit = "expected_process_limit"
    case minimumCPUCount = "minimum_cpu_count"
    case minimumMemoryBytes = "minimum_memory_bytes"
    case handshakeNonce = "handshake_nonce"
    case bootTimeoutMillis = "boot_timeout_millis"
    case stopTimeoutMillis = "stop_timeout_millis"
  }
}

private enum Rejection: String {
  case invalidRequest = "invalid_request"
  case cloneFailed = "clone_failed"
  case invalidConfiguration = "invalid_configuration"
  case startFailed = "start_failed"
  case handshakeFailed = "handshake_failed"
  case resourceConfigurationFailed = "resource_configuration_failed"
}

private struct HelperFailure: Error {
  let rejection: Rejection
}

private final class ResultBox<Value> {
  var value: Result<Value, Error>?
}

private func readExact(_ handle: FileHandle, count: Int) throws -> Data {
  var result = Data()
  while result.count < count {
    guard let chunk = try handle.read(upToCount: count - result.count), !chunk.isEmpty else {
      throw HelperFailure(rejection: .invalidRequest)
    }
    result.append(chunk)
  }
  return result
}

private func readFrame(_ handle: FileHandle, allowEOF: Bool = false) throws -> Data? {
  guard let header = try handle.read(upToCount: 4) else {
    if allowEOF { return nil }
    throw HelperFailure(rejection: .invalidRequest)
  }
  if header.isEmpty && allowEOF {
    return nil
  }
  var completeHeader = header
  if completeHeader.count < 4 {
    completeHeader.append(try readExact(handle, count: 4 - completeHeader.count))
  }
  let length = completeHeader.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
  guard length > 0, length <= maximumFrameBytes else {
    throw HelperFailure(rejection: .invalidRequest)
  }
  var frame = completeHeader
  frame.append(try readExact(handle, count: Int(length)))
  return frame
}

private func payload(_ frame: Data) throws -> Data {
  guard frame.count >= 4 else { throw HelperFailure(rejection: .invalidRequest) }
  return frame.dropFirst(4)
}

private func hasExactKeys(_ value: [String: Any], _ expected: Set<String>) -> Bool {
  Set(value.keys) == expected
}

private func exactUInt32(_ value: Any?) -> UInt32? {
  guard let number = value as? NSNumber else { return nil }
  return UInt32(number.stringValue)
}

private func frame(_ object: Any) throws -> Data {
  let body = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  guard !body.isEmpty, body.count <= maximumFrameBytes else {
    throw HelperFailure(rejection: .invalidRequest)
  }
  var length = UInt32(body.count).bigEndian
  var framed = Data(bytes: &length, count: 4)
  framed.append(body)
  return framed
}

private func writeFrame(_ frame: Data, to handle: FileHandle) throws {
  try handle.write(contentsOf: frame)
}

private func emit(status: String, kind: Rejection? = nil) {
  var value: [String: Any] = ["status": status, "protocol": helperProtocol]
  if let kind { value["kind"] = kind.rawValue }
  if let encoded = try? frame(value) {
    try? FileHandle.standardOutput.write(contentsOf: encoded)
  }
}

private func validPortableID(_ value: String) -> Bool {
  !value.isEmpty && value.utf8.count <= 128
    && value.utf8.allSatisfy {
      ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122)
        || [45, 46, 95].contains($0)
    }
}

private func normalizedAbsolute(_ value: String) -> String? {
  guard value.hasPrefix("/"), !value.contains("\0") else { return nil }
  let normalized = URL(fileURLWithPath: value).standardizedFileURL.path
  return normalized == value ? normalized : nil
}

private func supportedMacOSVersion(_ value: String) -> Bool {
  let components = value.split(separator: ".", omittingEmptySubsequences: false)
  guard let first = components.first, let major = UInt(first), major >= 15 else { return false }
  return components.allSatisfy { component in
    !component.isEmpty && component.utf8.count <= 4
      && component.utf8.allSatisfy { byte in byte >= 48 && byte <= 57 }
  }
}

private func openAttemptDirectory(_ path: String) throws -> Int32 {
  let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
  guard descriptor >= 0 else { throw HelperFailure(rejection: .cloneFailed) }
  var status = stat()
  guard fstat(descriptor, &status) == 0,
    status.st_mode & S_IFMT == S_IFDIR,
    status.st_uid == geteuid(),
    status.st_mode & 0o077 == 0
  else {
    close(descriptor)
    throw HelperFailure(rejection: .cloneFailed)
  }
  return descriptor
}

private func openTemplateArtifact(_ path: String) throws -> Int32 {
  guard secureRootOwnedParents(path) else {
    throw HelperFailure(rejection: .cloneFailed)
  }
  let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
  guard descriptor >= 0 else { throw HelperFailure(rejection: .cloneFailed) }
  var status = stat()
  guard fstat(descriptor, &status) == 0,
    status.st_mode & S_IFMT == S_IFREG,
    status.st_uid == 0,
    status.st_nlink == 1,
    status.st_mode & 0o022 == 0
  else {
    close(descriptor)
    throw HelperFailure(rejection: .cloneFailed)
  }
  return descriptor
}

private func secureRootOwnedParents(_ path: String) -> Bool {
  var parent = URL(fileURLWithPath: path).deletingLastPathComponent()
  while true {
    var status = stat()
    guard lstat(parent.path, &status) == 0,
      status.st_mode & S_IFMT == S_IFDIR,
      status.st_uid == 0,
      status.st_mode & 0o022 == 0
    else {
      return false
    }
    if parent.path == "/" { return true }
    let next = parent.deletingLastPathComponent()
    guard next.path != parent.path else { return false }
    parent = next
  }
}

private func cloneFile(
  from source: String,
  into destinationDirectory: Int32,
  named name: String
) throws {
  let sourceDescriptor = try openTemplateArtifact(source)
  defer { close(sourceDescriptor) }
  let result = name.withCString {
    fclonefileat(
      sourceDescriptor,
      destinationDirectory,
      $0,
      UInt32(CLONE_NOOWNERCOPY)
    )
  }
  guard result == 0,
    name.withCString({ fchmodat(destinationDirectory, $0, S_IRUSR | S_IWUSR, 0) }) == 0
  else {
    name.withCString { _ = unlinkat(destinationDirectory, $0, 0) }
    throw HelperFailure(rejection: .cloneFailed)
  }
}

private func makeConfiguration(_ request: LaunchRequest) throws -> VZVirtualMachineConfiguration {
  guard
    let hardwareData = Data(base64Encoded: request.hardwareModelBase64),
    let hardwareModel = VZMacHardwareModel(dataRepresentation: hardwareData),
    hardwareModel.isSupported,
    request.cpuCount >= VZVirtualMachineConfiguration.minimumAllowedCPUCount,
    request.cpuCount <= VZVirtualMachineConfiguration.maximumAllowedCPUCount,
    request.memoryBytes >= VZVirtualMachineConfiguration.minimumAllowedMemorySize,
    request.memoryBytes <= VZVirtualMachineConfiguration.maximumAllowedMemorySize
  else {
    throw HelperFailure(rejection: .invalidConfiguration)
  }

  let diskURL = URL(fileURLWithPath: request.attemptDirectory).appendingPathComponent("Disk.img")
  let auxiliaryURL = URL(fileURLWithPath: request.attemptDirectory)
    .appendingPathComponent("AuxiliaryStorage")
  let platform = VZMacPlatformConfiguration()
  platform.hardwareModel = hardwareModel
  platform.machineIdentifier = VZMacMachineIdentifier()
  platform.auxiliaryStorage = VZMacAuxiliaryStorage(contentsOf: auxiliaryURL)

  let storageAttachment: VZDiskImageStorageDeviceAttachment
  do {
    storageAttachment = try VZDiskImageStorageDeviceAttachment(
      url: diskURL,
      readOnly: false,
      cachingMode: .automatic,
      synchronizationMode: .full
    )
  } catch {
    throw HelperFailure(rejection: .invalidConfiguration)
  }

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
  configuration.cpuCount = Int(request.cpuCount)
  configuration.memorySize = request.memoryBytes
  configuration.storageDevices = [VZVirtioBlockDeviceConfiguration(attachment: storageAttachment)]
  configuration.graphicsDevices = [graphics]
  configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
  configuration.socketDevices = [VZVirtioSocketDeviceConfiguration()]
  configuration.networkDevices = []
  configuration.directorySharingDevices = []
  do {
    try configuration.validate()
  } catch {
    throw HelperFailure(rejection: .invalidConfiguration)
  }
  return configuration
}

private func wait<Value>(
  timeout: DispatchTimeInterval,
  start: (@escaping (Result<Value, Error>) -> Void) -> Void
) throws -> Value {
  let semaphore = DispatchSemaphore(value: 0)
  let box = ResultBox<Value>()
  start { result in
    box.value = result
    semaphore.signal()
  }
  guard semaphore.wait(timeout: .now() + timeout) == .success, let result = box.value else {
    throw HelperFailure(rejection: .startFailed)
  }
  return try result.get()
}

private func startVM(
  configuration: VZVirtualMachineConfiguration,
  timeoutMillis: UInt64,
  stopTimeoutMillis: UInt64
) throws -> (VZVirtualMachine, DispatchQueue) {
  let queue = DispatchQueue(label: "dev.automata.macos-vm")
  let machine = VZVirtualMachine(configuration: configuration, queue: queue)
  try startControlPipeWatchdog(
    machine: machine,
    queue: queue,
    timeoutMillis: stopTimeoutMillis
  )
  do {
    try wait(timeout: .milliseconds(Int(clamping: timeoutMillis))) { completion in
      queue.async {
        machine.start(completionHandler: completion)
      }
    } as Void
  } catch {
    throw HelperFailure(rejection: .startFailed)
  }
  return (machine, queue)
}

private func connect(
  device: VZVirtioSocketDevice,
  port: UInt32,
  queue: DispatchQueue,
  deadline: DispatchTime
) throws -> VZVirtioSocketConnection {
  while DispatchTime.now() < deadline {
    let remaining = deadline.uptimeNanoseconds - DispatchTime.now().uptimeNanoseconds
    let timeout = DispatchTimeInterval.nanoseconds(Int(clamping: remaining))
    do {
      return try wait(timeout: timeout) { completion in
        queue.async {
          device.connect(toPort: port, completionHandler: completion)
        }
      }
    } catch {
      usleep(100_000)
    }
  }
  throw HelperFailure(rejection: .handshakeFailed)
}

private func exchange(
  _ requestFrame: Data,
  device: VZVirtioSocketDevice,
  port: UInt32,
  queue: DispatchQueue,
  deadline: DispatchTime
) throws -> Data {
  let connection = try connect(device: device, port: port, queue: queue, deadline: deadline)
  defer { connection.close() }
  let handle = FileHandle(fileDescriptor: connection.fileDescriptor, closeOnDealloc: false)
  try handle.write(contentsOf: requestFrame)
  guard let response = try readFrame(handle) else {
    throw HelperFailure(rejection: .handshakeFailed)
  }
  return response
}

private func startControlPipeWatchdog(
  machine: VZVirtualMachine,
  queue: DispatchQueue,
  timeoutMillis: UInt64
) throws {
  let queueDescriptor = kqueue()
  guard queueDescriptor >= 0 else {
    throw HelperFailure(rejection: .invalidRequest)
  }
  var registration = kevent(
    ident: UInt(STDIN_FILENO),
    filter: Int16(EVFILT_READ),
    flags: UInt16(EV_ADD | EV_ENABLE | EV_CLEAR),
    fflags: 0,
    data: 0,
    udata: nil
  )
  guard kevent(queueDescriptor, &registration, 1, nil, 0, nil) == 0 else {
    close(queueDescriptor)
    throw HelperFailure(rejection: .invalidRequest)
  }
  DispatchQueue(label: "dev.automata.macos-vm.pipe-watchdog").async {
    var event = kevent()
    while true {
      let observed = kevent(queueDescriptor, nil, 0, &event, 1, nil)
      if observed > 0, event.flags & UInt16(EV_EOF) != 0 {
        close(queueDescriptor)
        stopVM(machine, queue: queue, timeoutMillis: timeoutMillis)
        _exit(0)
      }
      if observed < 0, errno != EINTR {
        close(queueDescriptor)
        _exit(70)
      }
    }
  }
}

private func attestGuest(
  request: LaunchRequest,
  device: VZVirtioSocketDevice,
  queue: DispatchQueue,
  deadline: DispatchTime
) throws {
  let hello = try frame([
    "operation": "hello",
    "protocol": request.guestProtocol,
    "operation_id": "\(request.attemptID)-hello",
    "nonce": request.handshakeNonce,
  ])
  var attested = false
  while DispatchTime.now() < deadline {
    do {
      let response = try exchange(
        hello,
        device: device,
        port: request.guestPort,
        queue: queue,
        deadline: deadline
      )
      guard
        let value = try JSONSerialization.jsonObject(with: payload(response)) as? [String: Any],
        hasExactKeys(
          value,
          [
            "result", "protocol", "nonce", "profile_id", "guest_agent_sha256", "macos_version",
            "macos_build", "architecture", "job_uid", "job_gid", "process_limit",
          ]
        ),
        value["result"] as? String == "hello",
        exactUInt32(value["protocol"]) == UInt32(request.guestProtocol),
        value["nonce"] as? String == request.handshakeNonce,
        value["profile_id"] as? String == request.expectedProfileID,
        value["guest_agent_sha256"] as? String == request.guestAgentSHA256,
        value["macos_version"] as? String == request.expectedMacOSVersion,
        value["macos_build"] as? String == request.expectedMacOSBuild,
        value["architecture"] as? String == request.expectedArchitecture,
        exactUInt32(value["job_uid"]) == request.expectedJobUID,
        exactUInt32(value["job_gid"]) == request.expectedJobGID,
        exactUInt32(value["process_limit"]) == request.expectedProcessLimit
      else {
        throw HelperFailure(rejection: .handshakeFailed)
      }
      attested = true
      break
    } catch {
      usleep(100_000)
    }
  }
  guard attested else {
    throw HelperFailure(rejection: .handshakeFailed)
  }

  let configure = try frame([
    "operation": "configure",
    "protocol": request.guestProtocol,
    "operation_id": "\(request.attemptID)-configure",
    "process_limit": request.processLimit,
  ])
  let configured = try exchange(
    configure,
    device: device,
    port: request.guestPort,
    queue: queue,
    deadline: deadline
  )
  guard
    let value = try JSONSerialization.jsonObject(with: payload(configured)) as? [String: Any],
    hasExactKeys(value, ["result", "protocol"]),
    value["result"] as? String == "configured",
    exactUInt32(value["protocol"]) == UInt32(request.guestProtocol)
  else {
    throw HelperFailure(rejection: .resourceConfigurationFailed)
  }
}

private func stopVM(_ machine: VZVirtualMachine, queue: DispatchQueue, timeoutMillis: UInt64) {
  let semaphore = DispatchSemaphore(value: 0)
  queue.async {
    guard machine.canStop else {
      semaphore.signal()
      return
    }
    machine.stop { _ in semaphore.signal() }
  }
  _ = semaphore.wait(timeout: .now() + .milliseconds(Int(clamping: timeoutMillis)))
}

private func run(lockPath: String) throws {
  guard let normalizedLock = normalizedAbsolute(lockPath) else {
    throw HelperFailure(rejection: .invalidRequest)
  }
  let lockDescriptor = open(
    normalizedLock,
    O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
    S_IRUSR | S_IWUSR
  )
  guard lockDescriptor >= 0, flock(lockDescriptor, LOCK_EX | LOCK_NB) == 0 else {
    if lockDescriptor >= 0 { close(lockDescriptor) }
    throw HelperFailure(rejection: .invalidRequest)
  }
  defer { close(lockDescriptor) }
  var lockStatus = stat()
  guard fstat(lockDescriptor, &lockStatus) == 0,
    lockStatus.st_mode & S_IFMT == S_IFREG,
    lockStatus.st_uid == geteuid(),
    lockStatus.st_nlink == 1,
    lockStatus.st_mode & 0o077 == 0
  else {
    throw HelperFailure(rejection: .invalidRequest)
  }

  guard let launchFrame = try readFrame(FileHandle.standardInput) else {
    throw HelperFailure(rejection: .invalidRequest)
  }
  let launchPayload = try payload(launchFrame)
  guard
    let launchObject = try JSONSerialization.jsonObject(with: launchPayload) as? [String: Any],
    hasExactKeys(launchObject, launchRequestKeys)
  else {
    throw HelperFailure(rejection: .invalidRequest)
  }
  let request = try JSONDecoder().decode(LaunchRequest.self, from: launchPayload)
  guard
    VZVirtualMachine.isSupported,
    request.protocolVersion == helperProtocol,
    validPortableID(request.attemptID),
    request.processLimit > 0,
    request.processLimit == request.expectedProcessLimit,
    request.cpuCount >= request.minimumCPUCount,
    request.memoryBytes >= request.minimumMemoryBytes,
    request.guestPort > 1024,
    request.guestProtocol > 0,
    request.expectedArchitecture == "arm64",
    request.expectedJobUID >= 500,
    request.expectedJobGID >= 500,
    supportedMacOSVersion(request.expectedMacOSVersion),
    !request.expectedMacOSBuild.isEmpty,
    let attemptDirectory = normalizedAbsolute(request.attemptDirectory),
    let sourceDisk = normalizedAbsolute(request.sourceDiskImage),
    let sourceAuxiliary = normalizedAbsolute(request.sourceAuxiliaryStorage),
    URL(fileURLWithPath: normalizedLock).deletingLastPathComponent().path == attemptDirectory,
    URL(fileURLWithPath: attemptDirectory).lastPathComponent == request.attemptID
  else {
    throw HelperFailure(rejection: .invalidRequest)
  }
  let attemptDescriptor = try openAttemptDirectory(attemptDirectory)
  defer { close(attemptDescriptor) }
  try cloneFile(from: sourceDisk, into: attemptDescriptor, named: "Disk.img")
  do {
    try cloneFile(
      from: sourceAuxiliary,
      into: attemptDescriptor,
      named: "AuxiliaryStorage"
    )
  } catch {
    _ = unlinkat(attemptDescriptor, "Disk.img", 0)
    throw error
  }

  let configuration = try makeConfiguration(request)
  let (machine, queue) = try startVM(
    configuration: configuration,
    timeoutMillis: request.bootTimeoutMillis,
    stopTimeoutMillis: request.stopTimeoutMillis
  )
  defer { stopVM(machine, queue: queue, timeoutMillis: request.stopTimeoutMillis) }
  guard let device = machine.socketDevices.first as? VZVirtioSocketDevice else {
    throw HelperFailure(rejection: .invalidConfiguration)
  }
  let deadline = DispatchTime.now() + .milliseconds(Int(clamping: request.bootTimeoutMillis))
  try attestGuest(request: request, device: device, queue: queue, deadline: deadline)
  emit(status: "ready")

  while let requestFrame = try readFrame(FileHandle.standardInput, allowEOF: true) {
    let response = try exchange(
      requestFrame,
      device: device,
      port: request.guestPort,
      queue: queue,
      deadline: .now() + .seconds(24 * 60 * 60)
    )
    try writeFrame(response, to: FileHandle.standardOutput)
  }
}

private func main() -> Int32 {
  let arguments = CommandLine.arguments
  guard arguments.count == 4, arguments[1] == "run", arguments[2] == "--lock" else {
    emit(status: "rejected", kind: .invalidRequest)
    return 64
  }
  do {
    try run(lockPath: arguments[3])
    return 0
  } catch let failure as HelperFailure {
    emit(status: "rejected", kind: failure.rejection)
    return 70
  } catch {
    emit(status: "rejected", kind: .invalidRequest)
    return 70
  }
}

exit(main())

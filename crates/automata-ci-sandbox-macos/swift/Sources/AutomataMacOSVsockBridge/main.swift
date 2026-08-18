import Darwin
import Foundation

private let maximumFrameBytes = 32 * 1024 * 1024
private let guestProtocol: UInt16 = 3
private let runtimeProxyGuestPort: UInt16 = 18081
private let runtimeProxyHostPort: UInt32 = 10251
private let runtimeProxySessionLimit = 16

private enum BridgeFailure: String, Error {
  case guestClientExit = "guest_client_exit"
  case guestClientInput = "guest_client_input"
  case guestClientLaunch = "guest_client_launch"
  case guestClientResponse = "guest_client_response"
  case invalidArguments = "invalid_arguments"
  case requestEnvelope = "request_envelope"
  case requestFrame = "request_frame"
  case requestRejected = "request_rejected"
  case responseWrite = "response_write"
  case runtimeProxyBind = "runtime_proxy_bind"
  case runtimeProxyConnect = "runtime_proxy_connect"
  case runtimeProxyListen = "runtime_proxy_listen"
  case socketBind = "socket_bind"
  case socketCreate = "socket_create"
  case socketListen = "socket_listen"
  case socketAccept = "socket_accept"
}

private func setCloseOnExec(_ descriptor: Int32) {
  _ = fcntl(descriptor, F_SETFD, FD_CLOEXEC)
}

private func runtimeProxyListener() throws -> Int32 {
  let descriptor = socket(AF_INET, SOCK_STREAM, 0)
  guard descriptor >= 0 else { throw BridgeFailure.runtimeProxyListen }
  setCloseOnExec(descriptor)
  var reuse: Int32 = 1
  _ = setsockopt(
    descriptor,
    SOL_SOCKET,
    SO_REUSEADDR,
    &reuse,
    socklen_t(MemoryLayout<Int32>.size)
  )
  var address = sockaddr_in()
  address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
  address.sin_family = sa_family_t(AF_INET)
  address.sin_port = runtimeProxyGuestPort.bigEndian
  address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
  let bound = withUnsafePointer(to: &address) {
    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
      Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
    }
  }
  guard bound == 0 else {
    close(descriptor)
    throw BridgeFailure.runtimeProxyBind
  }
  guard Darwin.listen(descriptor, Int32(runtimeProxySessionLimit)) == 0 else {
    close(descriptor)
    throw BridgeFailure.runtimeProxyListen
  }
  return descriptor
}

private func connectRuntimeProxyHost() throws -> Int32 {
  let descriptor = socket(AF_VSOCK, SOCK_STREAM, 0)
  guard descriptor >= 0 else { throw BridgeFailure.runtimeProxyConnect }
  setCloseOnExec(descriptor)
  var address = sockaddr_vm()
  address.svm_len = UInt8(MemoryLayout<sockaddr_vm>.size)
  address.svm_family = sa_family_t(AF_VSOCK)
  address.svm_port = runtimeProxyHostPort
  address.svm_cid = UInt32(VMADDR_CID_HOST)
  let connected = withUnsafePointer(to: &address) {
    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
      Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_vm>.size))
    }
  }
  guard connected == 0 else {
    close(descriptor)
    throw BridgeFailure.runtimeProxyConnect
  }
  return descriptor
}

private func copyStream(from source: Int32, to destination: Int32) {
  var buffer = [UInt8](repeating: 0, count: 64 * 1024)
  while true {
    let count = Darwin.read(source, &buffer, buffer.count)
    if count == 0 { break }
    if count < 0 {
      if errno == EINTR { continue }
      break
    }
    var offset = 0
    while offset < count {
      let written = buffer.withUnsafeBytes { bytes in
        Darwin.write(destination, bytes.baseAddress!.advanced(by: offset), count - offset)
      }
      if written < 0, errno == EINTR { continue }
      if written <= 0 {
        _ = shutdown(destination, SHUT_WR)
        return
      }
      offset += written
    }
  }
  _ = shutdown(destination, SHUT_WR)
}

private func relayRuntimeProxy(client: Int32, host: Int32) {
  let pumps = DispatchGroup()
  for (source, destination) in [(client, host), (host, client)] {
    pumps.enter()
    DispatchQueue.global(qos: .utility).async {
      copyStream(from: source, to: destination)
      pumps.leave()
    }
  }
  pumps.wait()
  close(client)
  close(host)
}

private func serveRuntimeProxy(listener: Int32) -> Never {
  let slots = DispatchSemaphore(value: runtimeProxySessionLimit)
  while true {
    let client = accept(listener, nil, nil)
    if client < 0 {
      if errno == EINTR { continue }
      diagnose(.socketAccept)
      continue
    }
    setCloseOnExec(client)
    guard slots.wait(timeout: .now()) == .success else {
      close(client)
      continue
    }
    let host: Int32
    do {
      host = try connectRuntimeProxyHost()
    } catch {
      close(client)
      slots.signal()
      continue
    }
    DispatchQueue.global(qos: .utility).async {
      relayRuntimeProxy(client: client, host: host)
      slots.signal()
    }
  }
}

private struct RequestEnvelope: Decodable {
  let operation: String
  let processLimit: UInt32?

  private enum CodingKeys: String, CodingKey {
    case operation
    case processLimit = "process_limit"
  }
}

private func portablePort(_ value: String) -> UInt32? {
  guard let port = UInt32(value), port > 1024 else { return nil }
  return port
}

private func diagnose(_ failure: BridgeFailure) {
  let message = Data("automata vsock bridge rejected: \(failure.rawValue)\n".utf8)
  try? FileHandle.standardError.write(contentsOf: message)
}

private func listen(port: UInt32) throws -> Int32 {
  let descriptor = socket(AF_VSOCK, SOCK_STREAM, 0)
  guard descriptor >= 0 else { throw BridgeFailure.socketCreate }
  _ = fcntl(descriptor, F_SETFD, FD_CLOEXEC)
  var address = sockaddr_vm()
  address.svm_len = UInt8(MemoryLayout<sockaddr_vm>.size)
  address.svm_family = sa_family_t(AF_VSOCK)
  address.svm_port = port
  address.svm_cid = VMADDR_CID_ANY
  let bound = withUnsafePointer(to: &address) {
    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
      Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_vm>.size))
    }
  }
  guard bound == 0 else {
    close(descriptor)
    throw BridgeFailure.socketBind
  }
  guard Darwin.listen(descriptor, 8) == 0 else {
    close(descriptor)
    throw BridgeFailure.socketListen
  }
  return descriptor
}

private func readExact(_ handle: FileHandle, count: Int) throws -> Data {
  var result = Data()
  while result.count < count {
    guard let chunk = try handle.read(upToCount: count - result.count), !chunk.isEmpty else {
      throw CocoaError(.fileReadCorruptFile)
    }
    result.append(chunk)
  }
  return result
}

private func readFrame(_ handle: FileHandle) throws -> Data {
  let header = try readExact(handle, count: 4)
  let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
  guard length > 0, length <= maximumFrameBytes else {
    throw CocoaError(.fileReadTooLarge)
  }
  var result = header
  result.append(try readExact(handle, count: Int(length)))
  return result
}

private func requestEnvelope(_ frame: Data) throws -> RequestEnvelope {
  guard frame.count > 4 else { throw CocoaError(.fileReadCorruptFile) }
  return try JSONDecoder().decode(RequestEnvelope.self, from: frame.dropFirst(4))
}

private func configuredResponse(_ frame: Data) -> Bool {
  guard frame.count > 4,
    let value = try? JSONSerialization.jsonObject(with: frame.dropFirst(4)) as? [String: Any]
  else {
    return false
  }
  return Set(value.keys) == Set(["result", "protocol"])
    && value["result"] as? String == "configured"
    && (value["protocol"] as? NSNumber).flatMap { UInt16($0.stringValue) } == guestProtocol
}

private func forward(
  _ frame: Data,
  guestClient: String,
  unixSocket: String
) throws -> Data {
  let input = Pipe()
  let output = Pipe()
  let client = Process()
  client.executableURL = URL(fileURLWithPath: guestClient)
  client.arguments = ["client", unixSocket]
  client.environment = [:]
  client.standardInput = input
  client.standardOutput = output
  client.standardError = FileHandle.standardError
  do {
    try client.run()
  } catch {
    throw BridgeFailure.guestClientLaunch
  }
  do {
    try input.fileHandleForWriting.write(contentsOf: frame)
    try input.fileHandleForWriting.close()
  } catch {
    throw BridgeFailure.guestClientInput
  }
  let response: Data
  do {
    response = try readFrame(output.fileHandleForReading)
  } catch {
    throw BridgeFailure.guestClientResponse
  }
  client.waitUntilExit()
  guard client.terminationReason == .exit, client.terminationStatus == 0 else {
    throw BridgeFailure.guestClientExit
  }
  return response
}

private func serve(listener: Int32, guestClient: String, unixSocket: String) -> Never {
  var configureFrame: Data?
  var configuredLimit: UInt32?
  var diagnosed = Set<BridgeFailure>()
  while true {
    let connection = accept(listener, nil, nil)
    if connection < 0 {
      if diagnosed.insert(.socketAccept).inserted { diagnose(.socketAccept) }
      continue
    }
    _ = fcntl(connection, F_SETFD, FD_CLOEXEC)
    let handle = FileHandle(fileDescriptor: connection, closeOnDealloc: true)
    do {
      let request: Data
      do {
        request = try readFrame(handle)
      } catch {
        throw BridgeFailure.requestFrame
      }
      let envelope: RequestEnvelope
      do {
        envelope = try requestEnvelope(request)
      } catch {
        throw BridgeFailure.requestEnvelope
      }
      let response: Data
      switch envelope.operation {
      case "hello":
        response = try forward(request, guestClient: guestClient, unixSocket: unixSocket)
      case "configure":
        guard let limit = envelope.processLimit,
          limit > 0,
          configuredLimit == nil || configuredLimit == limit
        else {
          throw BridgeFailure.requestRejected
        }
        response = try forward(request, guestClient: guestClient, unixSocket: unixSocket)
        guard configuredResponse(response) else {
          throw BridgeFailure.requestRejected
        }
        configureFrame = request
        configuredLimit = limit
      default:
        guard let configureFrame else {
          throw BridgeFailure.requestRejected
        }
        let configured = try forward(
          configureFrame,
          guestClient: guestClient,
          unixSocket: unixSocket
        )
        guard configuredResponse(configured) else {
          throw BridgeFailure.requestRejected
        }
        response = try forward(request, guestClient: guestClient, unixSocket: unixSocket)
      }
      do {
        try handle.write(contentsOf: response)
      } catch {
        throw BridgeFailure.responseWrite
      }
    } catch let failure as BridgeFailure {
      if diagnosed.insert(failure).inserted { diagnose(failure) }
    } catch {
      if diagnosed.insert(.requestRejected).inserted { diagnose(.requestRejected) }
    }
    try? handle.close()
  }
}

private func main() -> Int32 {
  let arguments = CommandLine.arguments
  guard arguments.count == 7,
    arguments[1] == "--port",
    arguments[3] == "--guest-client",
    arguments[5] == "--unix-socket",
    let port = portablePort(arguments[2]),
    arguments[4].hasPrefix("/"),
    arguments[6].hasPrefix("/"),
    access(arguments[4], X_OK) == 0,
    geteuid() == 0
  else {
    diagnose(.invalidArguments)
    return 64
  }
  do {
    let runtimeListener = try runtimeProxyListener()
    DispatchQueue(label: "dev.automata.macos-vm.runtime-proxy").async {
      serveRuntimeProxy(listener: runtimeListener)
    }
    let listener = try listen(port: port)
    serve(listener: listener, guestClient: arguments[4], unixSocket: arguments[6])
  } catch let failure as BridgeFailure {
    diagnose(failure)
  } catch {
    diagnose(.requestRejected)
  }
  return 70
}

exit(main())

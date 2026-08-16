import Darwin
import Foundation

private let maximumFrameBytes = 32 * 1024 * 1024
private let guestProtocol: UInt16 = 5

private enum BridgeFailure: Error {
  case rejected
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

private func listen(port: UInt32) -> Int32? {
  let descriptor = socket(AF_VSOCK, SOCK_STREAM, 0)
  guard descriptor >= 0 else { return nil }
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
  guard bound == 0, Darwin.listen(descriptor, 8) == 0 else {
    close(descriptor)
    return nil
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
  client.standardError = FileHandle.nullDevice
  try client.run()
  try input.fileHandleForWriting.write(contentsOf: frame)
  try input.fileHandleForWriting.close()
  let response = try readFrame(output.fileHandleForReading)
  client.waitUntilExit()
  guard client.terminationReason == .exit, client.terminationStatus == 0 else {
    throw CocoaError(.fileReadUnknown)
  }
  return response
}

private func serve(listener: Int32, guestClient: String, unixSocket: String) -> Never {
  var configureFrame: Data?
  var configuredLimit: UInt32?
  while true {
    let connection = accept(listener, nil, nil)
    if connection < 0 { continue }
    _ = fcntl(connection, F_SETFD, FD_CLOEXEC)
    let handle = FileHandle(fileDescriptor: connection, closeOnDealloc: true)
    do {
      let request = try readFrame(handle)
      let envelope = try requestEnvelope(request)
      let response: Data
      switch envelope.operation {
      case "hello":
        response = try forward(request, guestClient: guestClient, unixSocket: unixSocket)
      case "configure":
        guard let limit = envelope.processLimit,
          limit > 0,
          configuredLimit == nil || configuredLimit == limit
        else {
          throw BridgeFailure.rejected
        }
        response = try forward(request, guestClient: guestClient, unixSocket: unixSocket)
        guard configuredResponse(response) else {
          throw BridgeFailure.rejected
        }
        configureFrame = request
        configuredLimit = limit
      default:
        guard let configureFrame else {
          throw BridgeFailure.rejected
        }
        let configured = try forward(
          configureFrame,
          guestClient: guestClient,
          unixSocket: unixSocket
        )
        guard configuredResponse(configured) else {
          throw BridgeFailure.rejected
        }
        response = try forward(request, guestClient: guestClient, unixSocket: unixSocket)
      }
      try handle.write(contentsOf: response)
    } catch {}
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
    geteuid() == 0,
    let listener = listen(port: port)
  else {
    return 64
  }
  serve(listener: listener, guestClient: arguments[4], unixSocket: arguments[6])
}

exit(main())

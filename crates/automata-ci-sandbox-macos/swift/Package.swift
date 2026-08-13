// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "AutomataMacOSVirtualization",
  platforms: [.macOS(.v15)],
  products: [
    .executable(name: "automata-macos-vm-helper", targets: ["AutomataMacOSVMHelper"]),
    .executable(name: "automata-macos-vsock-bridge", targets: ["AutomataMacOSVsockBridge"]),
    .executable(
      name: "automata-macos-template-tool",
      targets: ["AutomataMacOSTemplateTool"]
    ),
  ],
  targets: [
    .executableTarget(name: "AutomataMacOSVMHelper"),
    .executableTarget(name: "AutomataMacOSVsockBridge"),
    .executableTarget(name: "AutomataMacOSTemplateTool"),
  ],
  swiftLanguageModes: [.v5]
)

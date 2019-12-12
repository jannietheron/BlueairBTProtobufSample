// DO NOT EDIT.
//
// Generated by the Swift generator plugin for the protocol buffer compiler.
// Source: wifi_constants.proto
//
// For information on using the generated types, please see the documentation:
//   https://github.com/apple/swift-protobuf/

// Copyright 2018 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
import SwiftProtobuf

// If the compiler emits an error on this type, it is because this file
// was generated by a version of the `protoc` Swift plug-in that is
// incompatible with the version of SwiftProtobuf to which you are linking.
// Please ensure that your are building against the same version of the API
// that was used to generate this file.
fileprivate struct _GeneratedWithProtocGenSwiftVersion: SwiftProtobuf.ProtobufAPIVersionCheck {
  struct _2: SwiftProtobuf.ProtobufAPIVersion_2 {}
  typealias Version = _2
}

enum Espressif_WifiStationState: SwiftProtobuf.Enum {
  typealias RawValue = Int
  case connected // = 0
  case connecting // = 1
  case disconnected // = 2
  case connectionFailed // = 3
  case UNRECOGNIZED(Int)

  init() {
    self = .connected
  }

  init?(rawValue: Int) {
    switch rawValue {
    case 0: self = .connected
    case 1: self = .connecting
    case 2: self = .disconnected
    case 3: self = .connectionFailed
    default: self = .UNRECOGNIZED(rawValue)
    }
  }

  var rawValue: Int {
    switch self {
    case .connected: return 0
    case .connecting: return 1
    case .disconnected: return 2
    case .connectionFailed: return 3
    case .UNRECOGNIZED(let i): return i
    }
  }

}

#if swift(>=4.2)

extension Espressif_WifiStationState: CaseIterable {
  // The compiler won't synthesize support with the UNRECOGNIZED case.
  static var allCases: [Espressif_WifiStationState] = [
    .connected,
    .connecting,
    .disconnected,
    .connectionFailed,
  ]
}

#endif  // swift(>=4.2)

enum Espressif_WifiConnectFailedReason: SwiftProtobuf.Enum {
  typealias RawValue = Int
  case authError // = 0
  case networkNotFound // = 1
  case UNRECOGNIZED(Int)

  init() {
    self = .authError
  }

  init?(rawValue: Int) {
    switch rawValue {
    case 0: self = .authError
    case 1: self = .networkNotFound
    default: self = .UNRECOGNIZED(rawValue)
    }
  }

  var rawValue: Int {
    switch self {
    case .authError: return 0
    case .networkNotFound: return 1
    case .UNRECOGNIZED(let i): return i
    }
  }

}

#if swift(>=4.2)

extension Espressif_WifiConnectFailedReason: CaseIterable {
  // The compiler won't synthesize support with the UNRECOGNIZED case.
  static var allCases: [Espressif_WifiConnectFailedReason] = [
    .authError,
    .networkNotFound,
  ]
}

#endif  // swift(>=4.2)

enum Espressif_WifiAuthMode: SwiftProtobuf.Enum {
  typealias RawValue = Int
  case `open` // = 0
  case wep // = 1
  case wpaPsk // = 2
  case wpa2Psk // = 3
  case wpaWpa2Psk // = 4
  case wpa2Enterprise // = 5
  case UNRECOGNIZED(Int)

  init() {
    self = .open
  }

  init?(rawValue: Int) {
    switch rawValue {
    case 0: self = .open
    case 1: self = .wep
    case 2: self = .wpaPsk
    case 3: self = .wpa2Psk
    case 4: self = .wpaWpa2Psk
    case 5: self = .wpa2Enterprise
    default: self = .UNRECOGNIZED(rawValue)
    }
  }

  var rawValue: Int {
    switch self {
    case .open: return 0
    case .wep: return 1
    case .wpaPsk: return 2
    case .wpa2Psk: return 3
    case .wpaWpa2Psk: return 4
    case .wpa2Enterprise: return 5
    case .UNRECOGNIZED(let i): return i
    }
  }

}

#if swift(>=4.2)

extension Espressif_WifiAuthMode: CaseIterable {
  // The compiler won't synthesize support with the UNRECOGNIZED case.
  static var allCases: [Espressif_WifiAuthMode] = [
    .open,
    .wep,
    .wpaPsk,
    .wpa2Psk,
    .wpaWpa2Psk,
    .wpa2Enterprise,
  ]
}

#endif  // swift(>=4.2)

struct Espressif_WifiConnectedState {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  var ip4Addr: String = String()

  var authMode: Espressif_WifiAuthMode = .open

  var ssid: Data = SwiftProtobuf.Internal.emptyData

  var bssid: Data = SwiftProtobuf.Internal.emptyData

  var channel: Int32 = 0

  var unknownFields = SwiftProtobuf.UnknownStorage()

  init() {}
}

// MARK: - Code below here is support for the SwiftProtobuf runtime.

fileprivate let _protobuf_package = "espressif"

extension Espressif_WifiStationState: SwiftProtobuf._ProtoNameProviding {
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    0: .same(proto: "Connected"),
    1: .same(proto: "Connecting"),
    2: .same(proto: "Disconnected"),
    3: .same(proto: "ConnectionFailed"),
  ]
}

extension Espressif_WifiConnectFailedReason: SwiftProtobuf._ProtoNameProviding {
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    0: .same(proto: "AuthError"),
    1: .same(proto: "NetworkNotFound"),
  ]
}

extension Espressif_WifiAuthMode: SwiftProtobuf._ProtoNameProviding {
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    0: .same(proto: "Open"),
    1: .same(proto: "WEP"),
    2: .same(proto: "WPA_PSK"),
    3: .same(proto: "WPA2_PSK"),
    4: .same(proto: "WPA_WPA2_PSK"),
    5: .same(proto: "WPA2_ENTERPRISE"),
  ]
}

extension Espressif_WifiConnectedState: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".WifiConnectedState"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .standard(proto: "ip4_addr"),
    2: .standard(proto: "auth_mode"),
    3: .same(proto: "ssid"),
    4: .same(proto: "bssid"),
    5: .same(proto: "channel"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      switch fieldNumber {
      case 1: try decoder.decodeSingularStringField(value: &self.ip4Addr)
      case 2: try decoder.decodeSingularEnumField(value: &self.authMode)
      case 3: try decoder.decodeSingularBytesField(value: &self.ssid)
      case 4: try decoder.decodeSingularBytesField(value: &self.bssid)
      case 5: try decoder.decodeSingularInt32Field(value: &self.channel)
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.ip4Addr.isEmpty {
      try visitor.visitSingularStringField(value: self.ip4Addr, fieldNumber: 1)
    }
    if self.authMode != .open {
      try visitor.visitSingularEnumField(value: self.authMode, fieldNumber: 2)
    }
    if !self.ssid.isEmpty {
      try visitor.visitSingularBytesField(value: self.ssid, fieldNumber: 3)
    }
    if !self.bssid.isEmpty {
      try visitor.visitSingularBytesField(value: self.bssid, fieldNumber: 4)
    }
    if self.channel != 0 {
      try visitor.visitSingularInt32Field(value: self.channel, fieldNumber: 5)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Espressif_WifiConnectedState, rhs: Espressif_WifiConnectedState) -> Bool {
    if lhs.ip4Addr != rhs.ip4Addr {return false}
    if lhs.authMode != rhs.authMode {return false}
    if lhs.ssid != rhs.ssid {return false}
    if lhs.bssid != rhs.bssid {return false}
    if lhs.channel != rhs.channel {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

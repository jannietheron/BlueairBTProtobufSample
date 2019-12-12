import Curve25519
import Foundation
import Security
import SwiftProtobuf

enum SecuritySessionState: Int {
    case request1
    case response1Request2
    case response2
    case finished
}

enum SecurityError: Error {
    case sessionStateError(String)
    case handshakeError(String)
    case keygenError(String)
}

class Security {
    private static let basePoint = Data([9] + [UInt8](repeating: 0, count: 31))

    private var sessionState: SecuritySessionState = .request1
    private var proofOfPossession: Data?
    private var privateKey: Data?
    private var publicKey: Data?
    private var clientVerify: Data?
    private var cryptoAES: CryptoAES?

    private var sharedKey: Data?
    private var deviceRandom: Data?

    /// Create Security 1 implementation with given proof of possession
    ///
    /// - Parameter proofOfPossession: proof of possession identifying the physical device
    init(proofOfPossession: String) {
        self.proofOfPossession = proofOfPossession.data(using: .utf8)
        generateKeyPair()
    }
    
    func getNextRequestInSession(data: Data?) throws -> Data? {
         var request: Data?
         do {
             switch sessionState {
             case .request1:
                 sessionState = .response1Request2
                 request = try getStep0Request()
             case .response1Request2:
                 sessionState = .response2
                 try processStep0Response(response: data)
                 request = try getStep1Request()
             case .response2:
                 sessionState = .finished
                 try processStep1Response(response: data)
             default:
                 request = nil
             }
         } catch {
             throw error
         }

         return request
     }
     

    func encrypt(data: Data) -> Data? {
        guard let cryptoAES = self.cryptoAES else {
            return nil
        }
        return cryptoAES.encrypt(data: data)
    }

    func decrypt(data: Data) -> Data? {
        guard let cryptoAES = self.cryptoAES else {
            return nil
        }
        return cryptoAES.encrypt(data: data)
    }

    private func generatePrivateKey() -> Data? {
        var keyData = Data(count: 32)
        let result = keyData.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        if result == errSecSuccess {
            return keyData
        } else {
            print("Problem generating random bytes")
            return nil
        }
    }

    private func generateKeyPair() {
        self.privateKey = generatePrivateKey()
        guard let privateKey = self.privateKey else {
            publicKey = nil
            return
        }
        do {
            publicKey = try Curve25519.publicKey(for: privateKey, basepoint: Security.basePoint)
        } catch {
            print(error)
        }
    }

    private func getStep0Request() throws -> Data? {
        guard let publicKey = self.publicKey else {
            throw SecurityError.keygenError("Could not generate keypair")
        }
        var sessionData = Espressif_SessionData()
        sessionData.secVer = .secScheme1
        sessionData.sec1.sc0.clientPubkey = publicKey
        do {
            return try sessionData.serializedData()
        } catch {
            throw SecurityError.handshakeError("Cannot create handshake request 0")
        }
    }

    private func getStep1Request() throws -> Data? {
        guard let verifyData = self.clientVerify else {
            throw SecurityError.keygenError("Could not generate keypair")
        }

        var sessionData = Espressif_SessionData()
        sessionData.secVer = .secScheme1
        sessionData.sec1.msg = .sessionCommand1
        sessionData.sec1.sc1.clientVerifyData = verifyData
        do {
            return try sessionData.serializedData()
        } catch {
            throw SecurityError.handshakeError("Cannot create handshake request 1")
        }
    }

    private func processStep0Response(response: Data?) throws {
        guard let response = response else {
            throw SecurityError.handshakeError("Response 0 is nil")
        }
        var sessionData = try Espressif_SessionData(serializedData: response)
        if sessionData.secVer != .secScheme1 {
            throw SecurityError.handshakeError("Security version mismatch")
        }

        let devicePublicKey = sessionData.sec1.sr0.devicePubkey
        let deviceRandom = sessionData.sec1.sr0.deviceRandom
        do {
            var sharedKey = try Curve25519.calculateAgreement(privateKey: privateKey!, publicKey: devicePublicKey)
            if let pop = self.proofOfPossession, pop.count > 0 {
                let digest = pop.sha256()
                sharedKey = HexUtils.xor(first: sharedKey, second: digest)
            }

            cryptoAES = CryptoAES(key: sharedKey, iv: deviceRandom)

            let verifyBytes = encrypt(data: devicePublicKey)

            if verifyBytes == nil {
                throw SecurityError.handshakeError("Cannot encrypt device key")
            }

            clientVerify = verifyBytes
        } catch {
            print(error)
        }
    }

    private func processStep1Response(response: Data?) throws {
        guard let response = response else {
            throw SecurityError.handshakeError("Response 1 is nil")
        }
        let sessionData = try Espressif_SessionData(serializedData: response)
        if sessionData.secVer != .secScheme1 {
            throw SecurityError.handshakeError("Security version mismatch")
        }

        let deviceVerify = sessionData.sec1.sr1.deviceVerifyData
        let decryptedDeviceVerify = decrypt(data: deviceVerify)
        if let decryptedDeviceVerify = decryptedDeviceVerify,
            !decryptedDeviceVerify.bytes.elementsEqual(self.publicKey!.bytes) {
            throw SecurityError.handshakeError("Key mismatch")
        }
    }
}

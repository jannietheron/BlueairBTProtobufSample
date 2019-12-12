import Foundation
import Curve25519
import CoreBluetooth

class BLESession: NSObject, CBPeripheralDelegate {
    
    var configUUIDMap = [String: CBUUID]()
    let security = Security(proofOfPossession: "abcd1234")
    var currentService: CBService?
    let peripheral: CBPeripheral
    var capabilities: [String]?
    var readCounter = 0
    private var transportToken = DispatchSemaphore(value: 1)
    var wifiScanFinished: (([String: Espressif_WiFiScanResult]) -> Void)?
    
    private var configPath = "prov-config"
    private var versionPath = "proto-ver"
    private var scanPath = "prov-scan"
    private var sessionPath = "prov-session"
    private var peripheralConfigured = false
    private var sessionCharacteristic: CBCharacteristic!
    private var isSessionEstablished = false
    private var deviceVersionInfo: NSDictionary?
    private var currentRequestCompletionHandler: ((Data?, Error?) -> Void)?
    
    private var scanResult: [String: Espressif_WiFiScanResult] = [:]
    
    init(peripheral: CBPeripheral) {
        self.peripheral = peripheral
        self.configUUIDMap[configPath] = CBUUID(string: "ff52")
        self.configUUIDMap[sessionPath] = CBUUID(string: "ff51")
        super.init()
        peripheral.delegate = self
    }
    
    func initialiseSession() {
        initialise(response: nil) { error in
            guard error == nil else {
                print("Error in establishing session \(error.debugDescription)")
                return
            }
        }
    }
    
    func updateDeviceVersionInfo() {
        
        sendConfigData(path: versionPath, data: Data("ESP".utf8), completionHandler: { response, error in
            guard error == nil else {
                print("Error reading device version info")
                return
            }
            do {
                if let result = try JSONSerialization.jsonObject(with: response!, options: .mutableContainers) as? NSDictionary {
                    self.deviceVersionInfo = result
                    if let prov = result[BLESessionConstants.provKey] as? NSDictionary,
                        let capabilities = prov[BLESessionConstants.capabilitiesKey] as? [String] {
                        self.capabilities = capabilities
                        DispatchQueue.main.async {
                            self.initialiseSession()
                        }
                    }
                }
            } catch {
                self.initialiseSession()
                print(error)
            }
        })
    }
    
    func initialise(response: Data?, completionHandler: @escaping (Error?) -> Swift.Void) {
        do {
            let request = try security.getNextRequestInSession(data: response)
            if let request = request {
                sendSessionData(data: request) { responseData, error in
                    guard error == nil else {
                        completionHandler(error)
                        return
                    }
                    
                    if let responseData = responseData {
                        self.initialise(response: responseData,
                                        completionHandler: completionHandler)
                    } else {
                        completionHandler(SecurityError.handshakeError("Session establish failed"))
                    }
                }
            } else {
                isSessionEstablished = true
                completionHandler(nil)
            }
        } catch {
            completionHandler(error)
        }
    }
    
    func startWifiScan() {
        do {
            if let payloadData = try createStartScanRequest() {
                sendConfigData(path: scanPath, data: payloadData) { response, error in
                    guard error == nil,
                        response != nil else {
                            //self.wifiScanFinished?(nil)
                            return
                    }
                    self.processStartScan(responseData: response!)
                    self.getWiFiScanStatus()
                }
            } else {
                //                delegate?.wifiScanFinished(wifiList: nil, error: CustomError.emptyConfigData)
            }
        } catch {
            //            delegate?.wifiScanFinished(wifiList: nil, error: error)
        }
    }
    
    func sendConfigData(path: String,
                        data: Data,
                        completionHandler: @escaping (Data?, Error?) -> Void) {
        
        var characteristic: CBCharacteristic?
        if let characteristics = currentService?.characteristics {
            for c in characteristics {
                if c.uuid == configUUIDMap[path] {
                    characteristic = c
                    break
                }
            }
        }
        transportToken.wait()
        
        if let characteristic = characteristic {
            peripheral.writeValue(data, for: characteristic, type: .withResponse)
            currentRequestCompletionHandler = completionHandler
        } else {
            transportToken.signal()
        }
    }
    
    private func createStartScanRequest() throws -> Data? {
        var configRequest = Espressif_CmdScanStart()
        configRequest.blocking = true
        configRequest.passive = false
        configRequest.groupChannels = 0
        configRequest.periodMs = 120
        let msgType = Espressif_WiFiScanMsgType.typeCmdScanStart
        var payload = Espressif_WiFiScanPayload()
        payload.msg = msgType
        payload.cmdScanStart = configRequest
        return try security.encrypt(data: payload.serializedData())
    }
    
    private func processStartScan(responseData: Data) {
        let decryptedResponse = (security.encrypt(data: responseData))!
        do {
            _ = try Espressif_WiFiScanPayload(serializedData: decryptedResponse)
        } catch {
            print(error)
        }
    }
    
    private func getWiFiScanStatus() {
        do {
            let payloadData = try createWifiScanConfigRequest()
            if let data = payloadData {
                sendConfigData(path: scanPath, data: data) { response, error in
                    guard error == nil, response != nil else {
                        //                        self.delegate?.wifiScanFinished(wifiList: nil, error: error)
                        return
                    }
                    let scanCount = self.processGetWiFiScanStatus(responseData: response!)
                    if scanCount > 0 {
                        self.getScannedWiFiListResponse(count: scanCount)
                    } else {
                        print("empty result")
                        //self.delegate?.wifiScanFinished(wifiList: nil, error: CustomError.emptyResultCount)
                    }
                }
            }
        } catch {
            print(error)
            //               delegate?.wifiScanFinished(wifiList: nil, error: error)
        }
    }
    
    func processGetWiFiScanStatus(responseData: Data) -> UInt32 {
        let resultCount: UInt32 = 0
        if let decryptedResponse = security.decrypt(data: responseData) {
            do {
                let payload = try Espressif_WiFiScanPayload(serializedData: decryptedResponse)
                let response = payload.respScanStatus
                return response.resultCount
            } catch {
                print(error)
                //                delegate?.wifiScanFinished(wifiList: nil, error: error)
            }
        }
        return resultCount
    }
    
    func getScannedWiFiListResponse(count: UInt32, startIndex: UInt32 = 0) {
        do {
            var lastFetch = false
            var fetchCount: UInt32 = 4
            if startIndex + 4 >= count {
                fetchCount = count - startIndex
                lastFetch = true
            }
            let payloadData = try createWifiListConfigRequest(startIndex: startIndex, count: fetchCount)
            if let data = payloadData {
                sendConfigData(path: scanPath, data: data) { response, error in
                    guard error == nil, response != nil else {
                        //                           self.delegate?.wifiScanFinished(wifiList: nil, error: error)
                        return
                    }
                    self.getScannedWifiSSIDs(response: response!, fetchFinish: lastFetch)
                    if startIndex + fetchCount < count {
                        self.getScannedWiFiListResponse(count: count, startIndex: startIndex + 4)
                    }
                }
            } else {
                print("No data")
                //delegate?.wifiScanFinished(wifiList: nil, error: CustomError.emptyConfigData)
            }
        } catch {
            print(error)
            //delegate?.wifiScanFinished(wifiList: nil, error: error)
        }
    }
    
    private func createWifiListConfigRequest(startIndex: UInt32, count: UInt32) throws -> Data? {
        var configRequest = Espressif_CmdScanResult()
        configRequest.startIndex = startIndex
        configRequest.count = count
        var payload = Espressif_WiFiScanPayload()
        payload.msg = Espressif_WiFiScanMsgType.typeCmdScanResult
        payload.cmdScanResult = configRequest
        return try security.encrypt(data: payload.serializedData())
    }
    private func getScannedWifiSSIDs(response: Data, fetchFinish: Bool) {
        do {
            if let decryptedResponse = try security.decrypt(data: response) {
                let payload = try Espressif_WiFiScanPayload(serializedData: decryptedResponse)
                let responseList = payload.respScanResult
                for index in 0 ... responseList.entries.count - 1 {
                    let ssid = String(decoding: responseList.entries[index].ssid, as: UTF8.self)
                    let rssi = responseList.entries[index].rssi
                    if let val = scanResult[ssid] {
                        if rssi > val.rssi {
                            scanResult[ssid] = val
                        }
                    } else {
                        scanResult[ssid] = responseList.entries[index]
                    }
                }
                if fetchFinish {
                    let ssids = scanResult.values.map { $0.ssid }
                    print("Finished: \(ssids)")
                    wifiScanFinished?(scanResult)
                }
            }
        } catch {
            print(error)
            //               delegate?.wifiScanFinished(wifiList: nil, error: error)
        }
    }
    private func createWifiScanConfigRequest() throws -> Data? {
        let configRequest = Espressif_CmdScanStatus()
        let msgType = Espressif_WiFiScanMsgType.typeCmdScanStatus
        var payload = Espressif_WiFiScanPayload()
        payload.msg = msgType
        payload.cmdScanStatus = configRequest
        return try security.encrypt(data: payload.serializedData())
    }
    
    
    func processDescriptor(descriptor: CBDescriptor) {
        if let value = descriptor.value as? String {
            if value.contains(BLESessionConstants.scanCharacteristic) {
                scanPath = value
                configUUIDMap.updateValue(descriptor.characteristic.uuid, forKey: scanPath)
            } else if value.contains(BLESessionConstants.sessionCharacterstic) {
                sessionPath = value
                peripheralConfigured = true
                sessionCharacteristic = descriptor.characteristic
                configUUIDMap.updateValue(descriptor.characteristic.uuid, forKey: sessionPath)
            } else if value.contains(BLESessionConstants.configCharacterstic) {
                configPath = value
                configUUIDMap.updateValue(descriptor.characteristic.uuid, forKey: configPath)
            } else if value.contains(BLESessionConstants.versionCharacterstic) {
                versionPath = value
                configUUIDMap.updateValue(descriptor.characteristic.uuid, forKey: versionPath)
            }
        }
    }
    
    func sendSessionData(data: Data,
                         completionHandler: @escaping (Data?, Error?) -> Void) {
        transportToken.wait()
        peripheral.writeValue(data, for: sessionCharacteristic, type: .withResponse)
        currentRequestCompletionHandler = completionHandler
    }
    
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        if let services = peripheral.services {
            if let service = services.first {
                peripheral.discoverCharacteristics(nil, for: service)
                currentService = service
                return
            }
        }
    }
    
    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        print("Did discover characteristics \(service.characteristics)")
        if let characteristics = service.characteristics {
            readCounter = characteristics.count
            for characteristic in characteristics {
                peripheral.discoverDescriptors(for: characteristic)
            }
        }
    }
    
    func peripheral(_ peripheral: CBPeripheral, didDiscoverDescriptorsFor characteristic: CBCharacteristic, error _: Error?) {
        for descriptor in characteristic.descriptors! {
            peripheral.readValue(for: descriptor)
        }
    }
    
    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        guard error == nil else {
            currentRequestCompletionHandler?(nil, error)
            return
        }
        
        peripheral.readValue(for: characteristic)
    }
    
    func peripheral(_: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard error == nil else {
            currentRequestCompletionHandler?(nil, error)
            return
        }
        
        if let currentRequestCompletionHandler = currentRequestCompletionHandler {
            DispatchQueue.global().async {
                currentRequestCompletionHandler(characteristic.value, nil)
            }
            self.currentRequestCompletionHandler = nil
        }
        transportToken.signal()
    }
    
    func peripheral(_: CBPeripheral, didUpdateValueFor descriptor: CBDescriptor, error _: Error?) {
        processDescriptor(descriptor: descriptor)
        readCounter -= 1
        if readCounter < 1 {
            updateDeviceVersionInfo()
        }
    }
    
    func configureWifi(ssid: String,
                       passphrase: String,
                       completionHandler: @escaping (Bool, Error?) -> Swift.Void) {
        do {
            let message = try createSetWifiConfigRequest(ssid: ssid, passphrase: passphrase)
            if let message = message {
                sendConfigData(path: configPath, data: message) { response, error in
                    guard error == nil, response != nil else {
                        completionHandler(false, error)
                        return
                    }
                    let status = self.processSetWifiConfigResponse(response: response)
                    if status == Espressif_Status.success {
                        self.applyConfigurations(completionHandler: completionHandler)

                    }
                }
            }
        } catch {
            completionHandler(false, error)
        }
    }
    
    private func createSetWifiConfigRequest(ssid: String, passphrase: String) throws -> Data? {
        var configData = Espressif_WiFiConfigPayload()
        configData.msg = Espressif_WiFiConfigMsgType.typeCmdSetConfig
        configData.cmdSetConfig.ssid = Data(ssid.bytes)
        configData.cmdSetConfig.passphrase = Data(passphrase.bytes)
        
        return try security.encrypt(data: configData.serializedData())
    }
    
    private func processSetWifiConfigResponse(response: Data?) -> Espressif_Status {
        guard let response = response else {
            return Espressif_Status.invalidArgument
        }
        
        let decryptedResponse = security.decrypt(data: response)!
        var responseStatus: Espressif_Status = .invalidArgument
        do {
            let configResponse = try Espressif_WiFiConfigPayload(serializedData: decryptedResponse)
            responseStatus = configResponse.respGetStatus.status
        } catch {
            print(error)
        }
        return responseStatus
    }
    
    func applyConfigurations(completionHandler: @escaping (Bool, Error?) -> Void) {
        do {
            let message = try createApplyConfigRequest()
            if let message = message {
                sendConfigData(path: configPath, data: message) { response, error in
                    guard error == nil, response != nil else {
                        completionHandler(false, error)
                        return
                    }
                    
                    let status = self.processApplyConfigResponse(response: response)
                    if status == .success {
                    self.pollForWifiConnectionStatus { wifiStatus, failReason, error in
                        completionHandler(wifiStatus == .connected, nil)  }
                    } else {
                        completionHandler(false, nil)
                    }
                }
            }
        } catch {
            completionHandler(false, error)
        }
    }
    
    private func createApplyConfigRequest() throws -> Data? {
        var configData = Espressif_WiFiConfigPayload()
        configData.cmdApplyConfig = Espressif_CmdApplyConfig()
        configData.msg = Espressif_WiFiConfigMsgType.typeCmdApplyConfig
        
        return try security.encrypt(data: configData.serializedData())
    }
    
    private func processApplyConfigResponse(response: Data?) -> Espressif_Status {
        guard let response = response else {
            return Espressif_Status.invalidArgument
        }
        
        let decryptedResponse = security.decrypt(data: response)!
        var responseStatus: Espressif_Status = .invalidArgument
        do {
            let configResponse = try Espressif_WiFiConfigPayload(serializedData: decryptedResponse)
            responseStatus = configResponse.respApplyConfig.status
        } catch {
            print(error)
        }
        return responseStatus
    }
    
    private func pollForWifiConnectionStatus(completionHandler: @escaping (Espressif_WifiStationState, Espressif_WifiConnectFailedReason, Error?) -> Swift.Void) {
        do {
            let message = try createGetWifiConfigRequest()
            if let message = message {
                sendConfigData(path: configPath,
                               data: message) { response, error in
                                guard error == nil, response != nil else {
                                    completionHandler(Espressif_WifiStationState.disconnected, Espressif_WifiConnectFailedReason.UNRECOGNIZED(0), error)
                                    return
                                }
                                
                                do {
                                    let (stationState, failReason) = try self.processGetWifiConfigStatusResponse(response: response)
                                    if stationState == .connected {
                                        completionHandler(stationState, Espressif_WifiConnectFailedReason.UNRECOGNIZED(0), nil)
                                    } else if stationState == .connecting {
                                        sleep(5)
                                        self.pollForWifiConnectionStatus(completionHandler: completionHandler)
                                    } else {
                                        completionHandler(stationState, failReason, nil)
                                    }
                                } catch {
                                    completionHandler(Espressif_WifiStationState.disconnected, Espressif_WifiConnectFailedReason.UNRECOGNIZED(0), error)
                                }
                }
            }
        } catch {
            completionHandler(Espressif_WifiStationState.connectionFailed, Espressif_WifiConnectFailedReason.UNRECOGNIZED(0), error)
        }
    }
    
    private func createGetWifiConfigRequest() throws -> Data? {
        var configData = Espressif_WiFiConfigPayload()
        configData.cmdGetStatus = Espressif_CmdGetStatus()
        configData.msg = Espressif_WiFiConfigMsgType.typeCmdGetStatus
        
        return try security.encrypt(data: configData.serializedData())
    }
    
    private func processGetWifiConfigStatusResponse(response: Data?) throws -> (Espressif_WifiStationState, Espressif_WifiConnectFailedReason) {
        guard let response = response else {
            return (Espressif_WifiStationState.disconnected, Espressif_WifiConnectFailedReason.UNRECOGNIZED(-1))
        }
        
        let decryptedResponse = security.decrypt(data: response)!
        var responseStatus = Espressif_WifiStationState.disconnected
        var failReason = Espressif_WifiConnectFailedReason.UNRECOGNIZED(-1)
        let configResponse = try Espressif_WiFiConfigPayload(serializedData: decryptedResponse)
        responseStatus = configResponse.respGetStatus.staState
        failReason = configResponse.respGetStatus.failReason
        
        return (responseStatus, failReason)
    }
}

struct BLESessionConstants {
    
    static let scanCharacteristic = "scan"
    static let sessionCharacterstic = "session"
    static let configCharacterstic = "config"
    static let versionCharacterstic = "ver"
    static let deviceInfoStoryboardID = "versionInfo"
    
    // Device version info
    static let provKey = "prov"
    static let capabilitiesKey = "cap"
    static let wifiScanCapability = "wifi_scan"
    static let noProofCapability = "no_pop"
    
    static let prefixKey = "com.espressif.prefix"
    static let proofOfPossession = "com.espressif.prefix"
}

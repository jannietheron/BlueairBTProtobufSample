import UIKit
import CoreBluetooth

class ViewController: UIViewController, CBCentralManagerDelegate {
    
    private var centralManager: CBCentralManager!
    private var peripherals = [CBPeripheral]()
    @IBOutlet weak var output: UITextView!
    @IBOutlet weak var tableView: UITableView!
    private var descriptors = [String: CBUUID]()
    private var session: BLESession?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        centralManager = CBCentralManager(delegate: self, queue: nil)
    }
    
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        print(central)
        if central.state != .poweredOn {
            output.text += "Central manager not turned on\n"
        } else {
            output.text += "Central manager scanning...\n"
            centralManager.scanForPeripherals(withServices: [], options: [CBCentralManagerScanOptionAllowDuplicatesKey : true])
        }
    }
    
    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String : Any], rssi RSSI: NSNumber) {
        //        centralManager.stopScan()
        if !peripherals.contains(peripheral),
            let name = peripheral.name {
            output.text += "Disovered \(name)\n"
            peripherals.append(peripheral)
            tableView.reloadData()
        }
    }
    
    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        output.text += "Connected \(peripheral)\n"
        peripheral.discoverServices([])
        session = BLESession(peripheral: peripheral)
    }
    
    @IBAction func send(_ sender: Any) {
        //        session?.updateDeviceVersionInfo()
        session?.wifiScanFinished = { [weak self] list in
            DispatchQueue.main.async {
                if let self = self,
                    let controller = self.storyboard?.instantiateViewController(withIdentifier: "List") as? SSIDListViewController {
                    var temp = [(String, Espressif_WiFiScanResult)]()
                    list.forEach { arg in
                        temp.append((arg.key, arg.value))
                    }
                    controller.list = temp
                    controller.session = self.session
                    self.navigationController?.pushViewController(controller, animated: true)
                }
            }
        }
        session?.startWifiScan()
        
    }
}

extension ViewController: UITableViewDataSource, UITableViewDelegate {
    func numberOfSections(in tableView: UITableView) -> Int {
        return 1
    }
    
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return peripherals.count
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        
        let cell = tableView.dequeueReusableCell(withIdentifier: "cell", for: indexPath)
        
        let peripheral = peripherals[indexPath.row]
        cell.textLabel?.text = peripheral.name
        return cell
    }
    
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        centralManager.stopScan()
        output.text = ""
        let peripheral = peripherals[indexPath.row]
        centralManager.connect(peripheral, options: nil)
    }
}

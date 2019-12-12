import UIKit

class SSIDListViewController: UIViewController, UITableViewDataSource {
    
    var session: BLESession!
    var list: [(String, Espressif_WiFiScanResult)]! {
        didSet {
            table?.reloadData()
        }
    }
    
    @IBOutlet weak var table: UITableView!
    @IBOutlet weak var phrase: UITextField!
    
    
    override func viewDidLoad() {
        table.reloadData()
    }
    
    func numberOfSections(in tableView: UITableView) -> Int {
        return 1
    }
    
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return list.count
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "ssidCell", for: indexPath)
        
        cell.textLabel?.text = list[indexPath.row].0
        
        return cell
    }
    
    @IBAction func provision(_ sender: Any) {
        view.endEditing(true)
        if let row = table.indexPathForSelectedRow?.row {
            let ssid = list[row].0
            let pass = phrase.text ?? ""
            session.configureWifi(ssid: ssid, passphrase: pass) { [weak self] (status, error) in
                print("Status: \(status)")
                DispatchQueue.main.async {
                    let alert = UIAlertController(title: "\(status)", message: error?.localizedDescription, preferredStyle: .alert)
                    let ok = UIAlertAction(title: "OK", style: .default) { _ in
                        alert.dismiss(animated: true, completion: nil)
                    }
                    alert.addAction(ok)
                    self?.present(alert, animated: true, completion: nil)
                }
            }
        }
    }
}

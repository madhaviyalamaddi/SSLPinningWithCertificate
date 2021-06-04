//
//  SSLPinningManager.swift
//  SSLPinningWithCertificate
//
//  Created by madhavi.yalamaddi on 04/06/21.
//

import Foundation
import Security
import CommonCrypto

class SSLPinningManager: NSObject, URLSessionDelegate {
    static let shared = SSLPinningManager()
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        let remoteCertificate = SecTrustGetCertificateAtIndex(serverTrust, 2)
        let policy = NSMutableArray()
        policy.add(SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString))
        let isSecureServer = SecTrustEvaluateWithError(serverTrust, nil)
        let remoteCertificateData = SecCertificateCopyData(remoteCertificate!) as Data
        
        guard let localCertificatePath = Bundle.main.path(forResource: "GoogleCertificate", ofType: ".cer") else {
            fatalError("Local certificate not found")
        }
        let localCertificateData = NSData(contentsOfFile: localCertificatePath)
        if isSecureServer && (remoteCertificateData == localCertificateData! as Data) {
            print("Certificate pinning is successful")
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
    
    func callRemoteService(urlString: String, response: @escaping((String) -> ())) {
        let sessionObject = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
        
        guard let url = URL(string: urlString) else {
            fatalError("Wrong URL entered")
        }
        
        let task = sessionObject.dataTask(with: url) { (data, result, error) in
            if error?.localizedDescription == "canclled" {
                response("ssl pinning failed")
            }
            
            if let dataReceived = data {
                let decodedString = String(decoding: dataReceived, as: UTF8.self)
                //print(decodedString)
            }
        }
        task.resume()
    }
}

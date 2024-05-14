'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/


async function KDF_RK(root_key, root_input) {
  const [rkBuf, chainKeyBuf] = await HKDF(root_key, root_input, 'ratchet-str')
  return [rkBuf, chainKeyBuf]
}


async function KDF_CK(chain_key) {
  chain_key = await HMACtoHMACKey(chain_key, 'chain-key')
  const message_key = await HMACtoAESKey(chain_key, 'message-key')
  const mk_buffer = await HMACtoAESKey(chain_key, 'message-key', true)
  return [chain_key, message_key, mk_buffer]

}




class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // received certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate

    this.sendCount = {}
    this.receiveCount = {}

    this.messageQueue = {}
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate(username) {
    this.EGKeyPair = await generateEG()
    const certificate = {
      username: username,
      publicKey: this.EGKeyPair.pub
    }
    return certificate
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: ArrayBuffer
 *
 * Return Type: void
 */
  async receiveCertificate(certificate, signature) {
    // The signature will be on the output of stringifying the certificate
    // rather than on the certificate directly.

    //signing with private key and verifying with caPublickey
    const certString = JSON.stringify(certificate)
    const isValid = await verifyWithECDSA(this.caPublicKey, certString, signature)
    if (isValid) {
      this.certs[certificate.username] = certificate
    }
    else {
      throw ('Invalid Certificate')
    }
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, ArrayBuffer]
 */

  // await alice.sendMessage('bob', 'Hello, Bob')
  async sendMessage(name, plaintext) {
    const receiverPublicKey = this.certs[name].publicKey
    const senderPrivateKey = this.EGKeyPair.sec // 
    if (!(name in this.conns)) {
      //input to root key kdf which will give us the chain keys
      var eg_key = await generateEG()
      //first key which will be one the input to kdf key generation
      var root_key = await computeDH(senderPrivateKey, receiverPublicKey)
      //calculated the the in
      var root_input = await computeDH(eg_key.sec, receiverPublicKey)
      var ck_sender = await KDF_RK(root_key, root_input)
      ck_sender = ck_sender[1]

      this.sendCount[name] = 0

      this.conns[name] = {
        DHsend_pair: eg_key, // DHs pair for sending chain
        DHreceive: receiverPublicKey, // reciver public key for receiving chain
        root_key_chain: root_key, // root key chain
        chain_key_sender: ck_sender,
        chain_key_receiver: null
      }
    }
    //current connection
    const current_conn = this.conns[name]

    //which situation does it trigger?
    //chain_key_sender being null likely indicates that a chain key hasn't been established or initialized for the current connection. This means that no previous chain key has been fed into the key derivation function (KDF) to derive subsequent chain keys and message keys.
    if (current_conn.chain_key_sender == null) {
      //first key input to the kdf
      var root_key = await computeDH(senderPrivateKey, receiverPublicKey)
      //as CKs=null,then need to recalculate keys
      var eg_key = await generateEG()
      var root_input = await computeDH(eg_key.sec, receiverPublicKey)
      var ck_sender = await KDF_RK(root_key, root_input)
      ck_sender = ck_sender[1]
      current_conn.DHsend_pair = eg_key
      current_conn.chain_key_sender = ck_sender

      this.sendCount[name] = 0

    }


    const [chain_key, message_key, mk_buffer] = await KDF_CK(current_conn.chain_key_sender)
    current_conn.chain_key_sender = chain_key

    const IV = genRandomSalt() // Initialization vector needed along side secret key
    const gov_IV = genRandomSalt()
    const gov_DH = await generateEG() // GOV key pair so that gov can read the messages 

    const gov_shared_key = await computeDH(gov_DH.sec, this.govPublicKey)
    const gov_aes_key = await HMACtoAESKey(gov_shared_key, govEncryptionDataStr)
    const cipherkey = await encryptWithGCM(gov_aes_key, mk_buffer, gov_IV) //message encryption key
    const header = {
      publicKey: current_conn.DHsend_pair.pub, //public key of sender 
      receiverIV: IV,//IV needed
      ivGov: gov_IV,
      vGov: gov_DH.pub,//only public key known of third parties
      cGov: cipherkey,
      sendCount: this.sendCount[name],

    }
 //AEAD  
 /* 
  in the context of the provided code snippet, the associated data might include details about the sender, receiver, message sequence numbers, or other cryptographic parameters needed for decryption.
 */
    const ciphertext = await encryptWithGCM(message_key, plaintext, IV, JSON.stringify(header))

    if (name in this.sendCount) {
      this.sendCount[name] += 1
    }
    else {
      this.sendCount[name] = 1
    }
    //output
    return [header, ciphertext]
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
 *
 * Return Type: string
 */

  //const ct = await alice.sendMessage('bob', message)
  //const result = await bob.receiveMessage('alice', ct)
  //bob.receiveMessage(alice,[header,ciphertext])
  async receiveMessage(name, [header, ciphertext]) {

    const senderPublicKey = this.certs[name].publicKey
    const receiverPrivateKey = this.EGKeyPair.sec
//This condition checks if there is no existing connection stored for the sender's name (name) in the conns object. If no connection exists, it means that Bob has not established a connection with Alice yet.
    if (!(name in this.conns)) {
      //first key which will be one the input to kdf key generation
      var root_key = await computeDH(receiverPrivateKey, senderPublicKey)
      //shared secret key var root_input = await computeDH(eg_key.sec, receiverPublicKey)
      var root_input = await computeDH(receiverPrivateKey, header.publicKey)
      var ck_receiver = await KDF_RK(root_key, root_input)
      ck_receiver = ck_receiver[1]

      this.receiveCount[name] = 0

      this.conns[name] = {
        DHsend_pair: this.EGKeyPair, // DHs pair for sending chain
        DHreceive: header.publicKey, // receiver public key for receiving chain
        root_key_chain: root_key, // root key chain
        //the receiver may reset the sender's chain key by setting it to null. This triggers the generation of new keys for subsequent message exchanges, reducing the risk associated with prolonged key usage.
        chain_key_sender: null,
        chain_key_receiver: ck_receiver
      }
    }

    const current_conn = this.conns[name]


    //test 19 : 



    if (header.sendCount != this.receiveCount[name]) {
      //the message count indicated by the sender in the received message header. 
      //represents the count of messages that the receiver has actually received from the sender.
      var missed = header.sendCount - this.receiveCount[name] //missed messages
      /* 
      
      It then iterates through each missed message (for (var i = 0; i < missed; i++)) to perform the following tasks:
Derive the chain key and message key using KDF_CK.
Store the message key in the message queue under the respective sender's name and receive count.
Update the chain key for the recipient.
Increment the receive count for the sender.
      */
      for (var i = 0; i < missed; i++) {
        const [chain_key, message_key, mk_buffer] = await KDF_CK(current_conn.chain_key_receiver)
        
        if (name in this.messageQueue) {
          this.messageQueue[name][this.receiveCount[name]] = message_key
        } else {
          this.messageQueue[name] = {}
          this.messageQueue[name][this.receiveCount[name]] = message_key
        }
        //By updating current_conn.chain_key_receiver with the latest chain key (chain_key), the receiver ensures that subsequent messages are encrypted using fresh keys, contributing to forward secrecy.
        current_conn.chain_key_receiver = chain_key
        this.receiveCount[name] += 1
      }
    }


//maintaining the order of messages
    if (header.sendCount < this.receiveCount[name]) {
      // take message key from message queue
      const message_key = this.messageQueue[name][header.sendCount]

      const plaintext = bufferToString(await decryptWithGCM(message_key, ciphertext, header.receiverIV, JSON.stringify(header)))


      return plaintext

    }
    //CK has not been initialized cause messgae still have not decrypted and receive chain has not started
    if (current_conn.chain_key_receiver == null) {
      var root_key = await computeDH(receiverPrivateKey, senderPublicKey)
      var root_input = await computeDH(receiverPrivateKey, header.publicKey) // sender er public key
      var ck_receiver = await KDF_RK(root_key, root_input)
      ck_receiver = ck_receiver[1]

      current_conn.chain_key_receiver = ck_receiver
      current_conn.DHreceive = header.publicKey

      this.receiveCount[name] = 0
    }

    if (header.publicKey !== current_conn.DHreceive) {
      //new public key generated
      // Generate new DH key pair for sending
      current_conn.DHsend_pair = generateEG();

      // Update receiver's public key and derive new root key and chain keys
      current_conn.DHreceive = header.publicKey;
      
      const [new_root_key, new_chain_key_receiver] = await KDF_RK(current_conn.root_key_chain, await computeDH(current_conn.DHsend_pair.sec, current_conn.DHreceive));
      current_conn.root_key_chain = new_root_key;
      current_conn.chain_key_receiver = new_chain_key_receiver;

      // Generate new DH key pair for sending
      current_conn.DHsend_pair = generateEG();

      // Derive new root key and chain key for sending
      const [new_root_key_send, new_chain_key_sender] = await KDF_RK(current_conn.root_key_chain, await computeDH(current_conn.DHsend_pair.sec, current_conn.DHreceive));
      current_conn.root_key_chain = new_root_key_send;
      current_conn.chain_key_sender = new_chain_key_sender;
  }
    

    const [chain_key, message_key, mk_buffer] = await KDF_CK(current_conn.chain_key_receiver)
    current_conn.chain_key_receiver = chain_key

    const plaintext = bufferToString(await decryptWithGCM(message_key, ciphertext, header.receiverIV, JSON.stringify(header)))


    if (name in this.receiveCount) {
      this.receiveCount[name] += 1
    }
    else {
      this.receiveCount[name] = 1
    }
    //output 
    return plaintext
  }
};

module.exports = {
  MessengerClient
}

/* 
User
if(header.publicKey !== current_conn.DHreceive){ //performs dh ratchet
      current_conn.DHsend  = generateEG()
      current_conn.DHreceive = header.publicKey
      const [rk_rcv, chain_key_receiver] = await KDF_RK(current_conn.root_key, await computeDH(current_conn.DHsend_pair.sec, current_conn.DHreceive));
      current_conn.CKr = ck_receiver;
      current_conn.DHsend = await generateEG();
      const [rk_send, ck_send] = await KDF_RK(current_conn.RK, await computeDH(current_conn.DHs.sec, current_conn.DHr));
      current_conn.CKs = ck_send;
    }

*/
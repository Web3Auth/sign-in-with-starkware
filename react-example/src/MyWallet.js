import { Header, Payload, SIWStarkware } from '@web3auth/sign-in-with-starkware';
import { getStarknet } from "get-starknet";
import { useState } from 'react';
import { starknetKeccak } from 'starknet/dist/utils/hash';
import Swal from 'sweetalert';
import './App.css';

import StarkwareLogo from './starknet-logo.png';

const MyWallet = () => {
  
  let typedMessage; 
  
  const [isConnected, setIsConnected] = useState(false);
  const [provider, setProvider] = useState();
  // Domain and origin
  const domain = window.location.host;
  const origin = window.location.origin;

  
  let statement = "Sign in with Starkware to the app.";

  const [siwsMessage, setSiwsMessage] = useState();
  const [nonce, setNonce] = useState("");
  const [sign, setSignature] = useState("");
  const [address, setAddress] = useState("");

  async function connectWallet() {
    
    const starknet = await getStarknet()
    
    const[add] = await starknet.enable();
    if (add.length > 0) {
      setAddress(add);
      setIsConnected(true);
      setProvider(starknet);
    }
    
  }
  
  // if (connector.connected && connector.accounts[0] && address != connector.accounts[0]) {
  //   setAddress(connector.accounts[0])
  // }

  // Generate a message for signing
  // The nonce is generated on the server side 
  async function createStarkwareMessage() {
      const payload = new Payload();
      payload.domain = domain;
      
      payload.address = address;
      payload.uri = origin;
      payload.statement = statement;
      payload.version = '1';
      payload.chainId = 1;
      payload.issuedAt = new Date().toISOString();

      const header = new Header();
      header.t = "eip191";
      
      let message = new SIWStarkware({ header, payload });
      // we need the nonce for verification so getting it in a global variable
      setNonce(message.payload.nonce);
      setSiwsMessage(message);
      console.log(JSON.stringify(message));
      const messageText = message.prepareMessage();
      console.log(messageText.replace(/\n/g, '\\n'));
      const starknet = await getStarknet()  
      const result = await signMessage(messageText);
      setSignature(result.join(','));
      
      // signMessage(messageEncoded).then(resp => setSignature(
      //     bs58.encode(resp)));
  }

  
const networkId = () => {
  const starknet = getStarknet()
  if (!starknet?.isConnected) {
    return
  }
  try {
    const { baseUrl } = starknet.provider
    if (baseUrl.includes("alpha-mainnet.starknet.io")) {
      return "mainnet-alpha"
    } else if (baseUrl.includes("alpha4.starknet.io")) {
      return "goerli-alpha"
    } else if (baseUrl.match(/^https?:\/\/localhost.*/)) {
      return "localhost"
    }
  } catch {}
}

  const signMessage = async (message) => {
    
    message = starknetKeccak(message).toString('hex').substring(0, 31);
    
    typedMessage = {
      domain: {
        name: "Example DApp",
        chainId: networkId() === "mainnet-alpha" ? "SN_MAIN" : "SN_GOERLI",
        version: "0.0.1",
      },
      types: {
        StarkNetDomain: [
          { name: "name", type: "felt" },
          { name: "chainId", type: "felt" },
          { name: "version", type: "felt" },
        ],
        Message: [{ name: "message", type: "felt" }],
      },
      primaryType: "Message",
      message: {
        message,
      },
    }
    
    return provider.account.signMessage(typedMessage)
  }

  return (
    <>
          {isConnected &&
              sign == "" &&
              <span>
                  <p className='center'>Sign Transaction</p>
                  <input className='publicKey' type="text" id="publicKey" value={address} readOnly/>
              </span>
          }
          {
              isConnected != true &&
              sign=="" &&
              <div>
                  <div className="logo-wrapper">
                      <img className='starkware-logo' src={StarkwareLogo} />
                  </div>
                  <p className="sign">Sign in With Starkware</p>
              </div>
          }
                  
          {isConnected &&
              sign == "" &&
              <div>
                  <button className='web3auth' id='w3aBtn' onClick={createStarkwareMessage}>Sign-in with Starkware</button>
                  {/* <WalletDisconnectButton className='walletButtons' /> */}
              </div>
          }
          {isConnected != true &&
            sign == "" &&
            <button className='web3auth' id='w3aBtn' onClick={connectWallet}>Connect Wallet</button>
              // <WalletModalProvider >
              // <WalletMultiButton className='walletButtons' />
              // </WalletModalProvider>
          }

          {
              sign &&
              <>
                  <p className='center'>Verify Signature</p>
                  <input className='signature' type="text" id="signature" value={sign} onChange={ e=> setSignature(e.target.value)} />
                  <button className='web3auth' id='verify' onClick={e => {
                      const signature = {
                          t: "eip191",
                          s: sign.split(",")
                      } 
                      const payload = siwsMessage.payload;
                      siwsMessage.verify({ payload, networkId,signature, kp: provider }).then(resp => {
                          if (resp.success == true) {
                              new Swal("Success","Signature Verified","success")
                          } else {
                              new Swal("Error",resp.error.type,"error")
                          }
                      }).catch(err => { 
                        new Swal("Error",err.error.toString(),"error")
                      });
                  }}>Verify</button>
                  <button className='web3auth' id='verify' onClick={e => {
                      setSiwsMessage(null);
                      setNonce("");
                      setSignature("")
                  }}>Back to Wallet</button>
              </>
          }

      </>
  );
};

export default MyWallet;

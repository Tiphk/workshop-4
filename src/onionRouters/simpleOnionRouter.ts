import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT,REGISTRY_PORT } from "../config";
import * as Crypto from "../crypto";
import {error} from "console";
import {rsaDecrypt, symDecrypt} from "../crypto";


export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  const { publicKey, privateKey } = await Crypto.generateRsaKeyPair();
  const publicKeyBase64 = await Crypto.exportPubKey(publicKey);
  const privateKeyBase64 = await Crypto.exportPrvKey(privateKey);

  const nodeInfo = {
    nodeId,
    publicKey: publicKeyBase64,
    privateKey: privateKeyBase64
  };

  // TODO implement the status route
  onionRouter.get("/status", (req, res) => {
    res.status(200).send('live');
  });

  // 2.1 get routes
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
      res.json({ result: lastReceivedEncryptedMessage });
  });

  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
      res.json({ result: lastReceivedDecryptedMessage });
  });

  onionRouter.get("/getLastMessageDestination", (req, res) => {
      res.json({ result: lastMessageDestination });
  });

  onionRouter.get('/getPrivateKey', (req, res) => {
    //error(privateKeyBase64 + "\n");
    res.json({result: privateKeyBase64});
  });

  onionRouter.post('/message', async (req, res) => {
    const {message} = req.body;

    //on fait dans l'autre sens
    //decrypt rsa
    const decrypt_rsa = await Crypto.rsaDecrypt(message.slice(0,344),privateKey);

    //decrypt symki
    const decrypt_symki = await Crypto.symDecrypt(decrypt_rsa, message.slice(344));

    //back to number
    const back_to_number = parseInt(decrypt_symki.slice(0,10),10);
    const TheMessage = decrypt_symki.slice(10); //on récupère le message
    error(TheMessage);

    //on met à jour
    lastReceivedEncryptedMessage = message;
    lastReceivedDecryptedMessage = TheMessage;
    lastMessageDestination = back_to_number;

    //on appelle la suite
    await fetch(`http://localhost:${back_to_number}/message`,{
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({message: TheMessage})
    });

    res.json({success: true});
  });

  // @ts-ignore
  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );

  });

  //on appelle le post
  await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`,{
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({nodeId: nodeId, pubKey: publicKeyBase64})
  });

  return server;
}

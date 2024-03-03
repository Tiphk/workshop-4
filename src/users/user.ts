import bodyParser from "body-parser";
import express from "express";
import {BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT} from "../config";
import{error} from "console";
import { Node, GetNodeRegistryBody } from "../registry/registry";
import * as Crypto from "../crypto";
import {createRandomSymmetricKey, exportSymKey, rsaEncrypt, symEncrypt} from "../crypto";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;

  // TODO implement the status route
  _user.get('/status', (req, res) => {
    res.send('live');
  });

  //2.2 User get routes
  _user.get('/getLastReceivedMessage', (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  _user.get('/getLastSentMessage', (req, res) => {
    res.json({ result: lastSentMessage });
  });

  _user.post('/message', (req, res) => {
    const { message} = req.body;
    lastReceivedMessage = message; //on met à jour
    return res.send("success");
  });

  _user.post('/sendMessage', async (req, res) => {
    const {message, destinationUserId} = req.body;
    lastReceivedMessage = message; //on met à jour

    //create a random circuit of 3 distinct nodes with the help of the node registry
    const getallNodes = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
    const allNodesData:any = await getallNodes.json();

    const allNodes: GetNodeRegistryBody = allNodesData;

    let shuffledNodes: Node[] = allNodes.nodes.slice(); // Make a copy of the array

    shuffledNodes.sort(() => Math.random() - 0.5); // Shuffle the array
    const randomNodes: Node[] = shuffledNodes.slice(0, 3);

    const first_node = randomNodes[0].nodeId;

    let all_finals :string = "";

    //create each layer of encryption FOR EACH NODE
    for (let i = 0; i < randomNodes.length; i++) {
      //error(`Index ${i}:`, randomNodes[i]);

      //on créé une unique symétrique 'key' for each node
      const symki = await Crypto.createRandomSymmetricKey();

      //get the string of 10 characters
      const number = BASE_USER_PORT + destinationUserId ;
      const value = "000000" + number ;

      //concatenated et encrypted the text and the message with the symki
      const message_final_before_encryption = value + message ;
      const message_final_after_encryption = await Crypto.symEncrypt(symki,message_final_before_encryption);
      //error(message_final_after_encryption);

      //encrypt symKI with the node's RSA
      const base64_symKI = await Crypto.exportSymKey(symki); //on convertit la symki en base64
      const encrypt_symKI_rsa = await Crypto.rsaEncrypt(base64_symKI,randomNodes[i].pubKey);

      //concat encrypt_symki with message_final
      const final = encrypt_symKI_rsa + message_final_after_encryption ;
      all_finals = all_finals + final ; //on récupère les finals
    }

    //error("final " + all_finals);

    //on envoie

    await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + first_node}/message`,{
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({message: all_finals})
    });

    lastSentMessage = message;

    return res.send("success");
  });


  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

class Server {
    private static final int bitSize = 1024;

    private static final String PUBLIC_KEY_FILE = "Public.key";
    private static final String PRIVATE_KEY_FILE = "Private.key";
    private static RSAPublicKeySpec rsaPublicKeySpec;
    private static RSAPrivateKeySpec rsaPrivateKeySpec;
    private static Server rsaObj = new Server();
    private static String decryptedData = new String();

    public static void main(String[] args){
        BigInteger modulus;
        BigInteger exponent;
        String kStr = new String();
        RC4 rc4 = new RC4();
        GFG gfg = new GFG();
        Scanner scanner = new Scanner(System.in);
        String failStr = "Failed!";
        String successStr = "Successfully! Welcome back Client!";

        byte[] buffer = new byte[100];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        String clientName = new String();

        try{
            File myObj = new File("C:\\Users\\Nicoleta\\Desktop\\uni\\UDP-Server-Client-Encryption\\src\\com\\company\\users.txt");
            Scanner myReader = new Scanner(myObj);

            //Verifying username and password from txt file
            String userData = "";
            String userPsw = "";
            int z = 0;
            while (myReader.hasNextLine()) {

                if(z == 0){
                    clientName = myReader.nextLine();
                    z++;
                }else if(z == 1){
                    userPsw = myReader.nextLine();
                    z++;
                }

            }


            System.out.println("Server is connecting ...");
            //Generate Private and Public keys
            generateKeys();
            saveToFiles();

            System.out.println("Done!");
            System.out.println("--------------------");
            System.out.println("Server connected. Welcome Back!");
            System.out.println("Waiting for Client Response...");

            //Get client username
            DatagramSocket socket = new DatagramSocket((5000));
            socket.receive(packet);
            String identity = new String(buffer, 0, packet.getLength());
            if(identity.equalsIgnoreCase(clientName)){
                modulus = rsaPublicKeySpec.getModulus();
                exponent = rsaPublicKeySpec.getPublicExponent();
                String modStr = modulus.toString();
                String expStr = exponent.toString();
                String pubKey = modStr + "," + expStr;
                //System.out.println(pubKey);

                System.out.println("Sending Public key to client...");
                byte[] bfr3 = pubKey.getBytes();
                rsaObj.sendMsg(bfr3, socket, packet);
                System.out.println("Done!");
                System.out.println("--------------------");

            }else{
                //System.out.println(identity + " Length: " + identity.length());
                String str = "Invalid Username!";
                System.out.println(str);
                System.exit(-1);
            }

            //Get K from Bob
            System.out.println("Waiting for Key...");
            byte[] byteK = new byte[128];
            DatagramPacket packetK = new DatagramPacket(byteK, byteK.length);
            socket.receive(packetK);
            System.out.println("Received Key from Client");
            byte[] encodedK = Base64.getEncoder().encode(packetK.getData());
            System.out.println("CipherText: " + new String(encodedK, 0, 15) + "...");
            //Decrypt k
            rsaObj.decryptRSAData(packetK.getData());
            kStr = decryptedData;
            System.out.println("--------------------");
            //System.out.println(kStr);
            System.out.println("Waiting for " + identity + "'s Password...");

            //Receive username and password from Bob
            byte[] byteUP = new byte[128];
            DatagramPacket packetUP = new DatagramPacket(byteUP, byteUP.length);
            socket.receive(packetUP);
            System.out.println("Ciphertext: " + new String(byteUP, 0, packetUP.getLength()));

            //Decrypt username and password
            String encryStr = new String(byteUP, 0, packetUP.getLength());
            String decryStr = rc4.decryRC4(encryStr, kStr, "UTF-8");
            System.out.println("Plaintext: " + decryStr);

            //Quit the program if the psw doesn't match
            myReader.close();
            if(decryStr.substring(clientName.length()).equals(userPsw)){
                System.out.println("--------------------");
                System.out.println("identity verified");
                byte[] btrSuccess = successStr.getBytes();
                rsaObj.sendMsg(btrSuccess, socket, packet);
            }else{
                byte[] bfrFailed = failStr.getBytes();
                rsaObj.sendMsg(bfrFailed, socket, packet);
                System.out.println("Error, invalid Login!");
                System.exit(-1);
            }
            System.out.println("Client has connected!");
            System.out.println("--------------------");

            //Generate session key
            System.out.println("HashCode Generated by SHA-1 for ssk: ");
            String s1 = kStr + userPsw;
            String ssk = gfg.encryptThisString(s1);
            System.out.println("SSK (Plaintext): " + s1);
            System.out.println("SSK (CipherText): " + ssk);
            System.out.println("--------------------");



            while(true){
                byte[] buffer3 = new byte[200];
                DatagramPacket packet2 = new DatagramPacket(buffer3, buffer3.length);
                socket.receive(packet2);

                String cipherRC4Str = new String(buffer3,0,packet2.getLength());
                if(cipherRC4Str.equalsIgnoreCase("exit")){
                    System.out.println("Client has disconnected!");
                    System.out.println("Shutting Down the Program...");
                    System.exit(-1);
                }
                System.out.println("Client Sent:");
                System.out.println("CipherText: " + cipherRC4Str.substring(0, 20) + "...");
                String plaintRC4Str = rc4.decryRC4(cipherRC4Str, ssk, "UTF-8");
                System.out.println("h:  " + plaintRC4Str.substring(plaintRC4Str.length()-40));


                String msg = plaintRC4Str.substring(0, plaintRC4Str.length()-40);

                //computes h^ = H(ssk||m||ssk) and verifies if h = h^
                String hCheckStr = ssk + msg + ssk;
                String hCheck = gfg.encryptThisString(hCheckStr);
                System.out.println("h': " + hCheck);

                if(hCheck.equals(plaintRC4Str.substring(plaintRC4Str.length()-40))){
                    System.out.println("Authenticate Successfully");
                    System.out.println("");
                    System.out.println("Message: " + msg);
                    System.out.println("--------------------");
                    if(msg.equalsIgnoreCase("exit")){
                        System.out.println("Client has disconnected!");
                        System.out.println("Shutting Down Program...");
                        String quitStr = "exit";
                        byte[] buffer5 = quitStr.getBytes();
                        rsaObj.sendMsg(buffer5, socket, packet2);
                        System.exit(-1);
                    }
                }else{
                    String errorStr = "Communication Error!";
                    byte[] bufferErr = errorStr.getBytes();
                    rsaObj.sendMsg(bufferErr, socket, packet2);
                }


                System.out.print("Enter your message: ");
                String echoString = scanner.nextLine();
                if(echoString.equalsIgnoreCase("exit")){
                    System.out.println("You has disconnected!");
                    System.out.println("Shutting Down the Program...");
                    String quitStr = "exit";
                    byte[] buffer5 = quitStr.getBytes();
                    rsaObj.sendMsg(buffer5, socket, packet2);
                    System.exit(-1);
                }


                //Integrity check h = H(ssk||m||ssk)
                String hashStr = ssk + echoString + ssk;
                String h = gfg.encryptThisString(hashStr);

                //C = SKEssk(m||h)
                String c = echoString + h;

                System.out.println("Plaintext: " + c);
                String encryRC4Str = rc4.encryRC4String(c, ssk,"UTF-8");
                System.out.println("CipherText: " + encryRC4Str.substring(0,20) + "...");
                byte[] encryBuffer = encryRC4Str.getBytes();



                rsaObj.sendMsg(encryBuffer, socket, packet2);

                System.out.println("--------------------");
            }


        } catch (SocketException s) {
            System.out.println("SocketException: " + s.getMessage());
        } catch (IOException e){
            System.out.println("IOException: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }


    }



    public static void generateKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("Generating " + bitSize + " bits Public and Private Key...");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(bitSize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        //System.out.println("Done");

        System.out.println("Pulling out Parameters which makes keypair...");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        rsaPublicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
        rsaPrivateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
        //System.out.println("Done");
    }

    private static void saveToFiles() throws IOException {
        System.out.println("Saving public key and private key to files...");
        rsaObj.saveKeys(PUBLIC_KEY_FILE, rsaPublicKeySpec.getModulus(), rsaPublicKeySpec.getPublicExponent());
        rsaObj.saveKeys(PRIVATE_KEY_FILE, rsaPrivateKeySpec.getModulus(), rsaPrivateKeySpec.getPrivateExponent());
    }

    public void sendMsg(byte[] buffer, DatagramSocket socket, DatagramPacket packet){
        try{
            InetAddress address = packet.getAddress();
            int port = packet.getPort();
            packet = new DatagramPacket(buffer, buffer.length, address, port);
            socket.send(packet);
        } catch (SocketException s) {
            System.out.println("SocketException: " + s.getMessage());
        } catch (IOException e){
            System.out.println("IOException: " + e.getMessage());
        }
    }

    private void saveKeys(String fileName, BigInteger mod, BigInteger exp) throws IOException{
        FileOutputStream fos = null;
        ObjectOutputStream oos = null;
        try{
            System.out.println("Generating " + fileName + "...");
            fos = new FileOutputStream(fileName);
            oos = new ObjectOutputStream(new BufferedOutputStream(fos));
            oos.writeObject(mod);
            oos.writeObject(exp);
            //System.out.println("Done");
        }catch (IOException e){
            e.printStackTrace();
        } finally {
            if(oos != null){
                oos.close();
                if(fos != null){
                    fos.close();
                }
            }
        }
    }


    private void decryptRSAData(byte[] data) throws IOException {
        decryptedData = "";
        byte[] decryptedData = null;
        try {
            PrivateKey privateKey = readPrivateKeyFromFile(this.PRIVATE_KEY_FILE);


            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decryptedData = cipher.doFinal(data);
            System.out.println("PlainText: " + new String(decryptedData));
            this.decryptedData = new String(decryptedData);


        } catch (NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

    }

    public PrivateKey readPrivateKeyFromFile(String fileName) throws IOException{
        FileInputStream fis = null;
        ObjectInputStream ois = null;
        try {
            fis = new FileInputStream(new File(fileName));
            ois = new ObjectInputStream(fis);
            BigInteger modulus = (BigInteger) ois.readObject();
            BigInteger exponent = (BigInteger) ois.readObject();
            //Get private Key
            RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, exponent);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = factory.generatePrivate(rsaPrivateKeySpec);
            return  privateKey;

        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }
    private  byte[] encryptData(String data) throws IOException{
        System.out.println("------ Encryption Started --------");
        System.out.println("Data before encryption: " + data);
        byte [] dataToEncrypt = data.getBytes();
        byte [] encryptedData = null;
        try{
            PublicKey publicKey = readPublicKeyFromFile(this.PUBLIC_KEY_FILE);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptedData = cipher.doFinal(dataToEncrypt);
            System.out.println("Encrypted Data: " + encryptedData);

        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        System.out.println("--------- Encryption completed! ----------");
        return encryptedData;
    }

    public PublicKey readPublicKeyFromFile(String fileName) throws IOException{
        FileInputStream fis = null;
        ObjectInputStream ois = null;
        try{
            fis = new FileInputStream(new File(fileName));
            ois = new ObjectInputStream(fis);
            BigInteger modulus = (BigInteger) ois.readObject();
            BigInteger exponent = (BigInteger) ois.readObject();

            //Get public key
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = factory.generatePublic(rsaPublicKeySpec);
            return  publicKey;


        } catch (ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        } finally {
            if(ois != null){
                ois.close();
                if(fis != null){
                    fis.close();
                }
            }
        }
        return null;
    }

}

class RC4 {

    public static String encryRC4String(String data, String key, String chartSet) throws UnsupportedEncodingException {
        if (data == null || key == null) {
            return null;
        }
        return bytesToHex(encryRC4Byte(data, key, chartSet));
    }


    public static byte[] encryRC4Byte(String data, String key, String chartSet) throws UnsupportedEncodingException {
        if (data == null || key == null) {
            return null;
        }
        if (chartSet == null || chartSet.isEmpty()) {
            byte bData[] = data.getBytes();
            return RC4Base(bData, key);
        } else {
            byte bData[] = data.getBytes(chartSet);
            return RC4Base(bData, key);
        }
    }


    public static String decryRC4(String data, String key, String chartSet) throws UnsupportedEncodingException {
        if (data == null || key == null) {
            return null;
        }
        return new String(RC4Base(hexToByte(data), key), chartSet);
    }


    private static byte[] initKey(String aKey) {
        byte[] bkey = aKey.getBytes();
        byte state[] = new byte[256];

        for (int i = 0; i < 256; i++) {
            state[i] = (byte) i;
        }
        int index1 = 0;
        int index2 = 0;
        if (bkey.length == 0) {
            return null;
        }
        for (int i = 0; i < 256; i++) {
            index2 = ((bkey[index1] & 0xff) + (state[i] & 0xff) + index2) & 0xff;
            byte tmp = state[i];
            state[i] = state[index2];
            state[index2] = tmp;
            index1 = (index1 + 1) % bkey.length;
        }
        return state;
    }


    public static String bytesToHex(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if (hex.length() < 2) {
                sb.append(0);
            }
            sb.append(hex);
        }
        return sb.toString();
    }


    public static byte[] hexToByte(String inHex) {
        int hexlen = inHex.length();
        byte[] result;
        if (hexlen % 2 == 1) {
            hexlen++;
            result = new byte[(hexlen / 2)];
            inHex = "0" + inHex;
        } else {
            result = new byte[(hexlen / 2)];
        }
        int j = 0;
        for (int i = 0; i < hexlen; i += 2) {
            result[j] = (byte) Integer.parseInt(inHex.substring(i, i + 2), 16);
            j++;
        }
        return result;
    }


    private static byte[] RC4Base(byte[] input, String mKkey) {
        int x = 0;
        int y = 0;
        byte key[] = initKey(mKkey);
        int xorIndex;
        byte[] result = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            x = (x + 1) & 0xff;
            y = ((key[x] & 0xff) + y) & 0xff;
            byte tmp = key[x];
            key[x] = key[y];
            key[y] = tmp;
            xorIndex = ((key[x] & 0xff) + (key[y] & 0xff)) & 0xff;
            result[i] = (byte) (input[i] ^ key[xorIndex]);
        }
        return result;
    }
}

class GFG {
    public static String encryptThisString(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] messageDigest = md.digest(input.getBytes());

            BigInteger no = new BigInteger(1, messageDigest);
            String hashtext = no.toString(16);

            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }

            return hashtext;
        }


        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}

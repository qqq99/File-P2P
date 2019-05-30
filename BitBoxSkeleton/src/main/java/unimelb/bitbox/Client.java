package unimelb.bitbox;

import unimelb.bitbox.util.Document;

import java.io.*;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

// client to operate peer
public class Client {
    // logger
    private static Logger log = Logger.getLogger(Client.class.getName());

    // secret key
    private static String secretKey;

    public static void main(String[] args) throws IOException {
        // parse args
        Map<String, String> arg = new HashMap<>();
        if (args.length < 4) {
            argWrong();
        }
        if (!args[0].equals("-c") || !args[2].equals("-s")) {
            argWrong();
        }

        arg.put("command", args[1]);
        arg.put("server", args[3]);
        if (args.length > 4) {
            if (args.length < 6) {
                argWrong();
            }
            if(args[4].equals("-i")){
                arg.put("key", args[5]);
            }
            else{
                arg.put("peer", args[5]);
            }
        }

        if(args.length > 6){
            if (args.length != 8 || !args[6].equals("-i")) {
                argWrong();
            }
            arg.put("key", args[7]);
        }
        //
        //parse command
        parse(arg);
    }

    // to report arg wrong and exit
    private static void argWrong() {
        log.severe("Usage: java -cp bitbox.jar unimelb.bitbox.Client " +
                "-c connect_peer " +
                "-s server.com:3000" +
                "[-p bigdata.cis.unimelb.edu.au:8500]");
        //System.exit(-1);
        throw new RuntimeException("123");
    }

    // parse command line args
    private static void parse(Map<String, String> args) throws IOException {
        String[] addr = args.get("server").split(":");
        String id = "";
        // read id from private file
        if(args.containsKey("key")){
            id = args.get("key");
        }
        else {
            try {
                File file = new File("bitboxclient_rsa");
                FileReader reader = new FileReader(file);
                BufferedReader bufferedReader = new BufferedReader(reader);
                id = bufferedReader.readLine();
            } catch (FileNotFoundException e) {
                log.severe("public key file not found");
            } catch (IOException e) {
                log.severe("read public key failed");
            }
        }
        //
        Socket socket = new Socket(addr[0], Integer.parseInt(addr[1]));

        // connection request
        Document request = new Document();
        request.append("command", "AUTH_REQUEST");
        request.append("identity", id);
        writeOut(socket, request.toJson());

        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF8"));
        String res = in.readLine();
        log.info("receive message " + res);
        Document response = Document.parse(res);
        // if we are rejected by server
        if (!response.getBoolean("status")) {
            log.severe("we are not in servers public id");
            System.exit(-1);
        }
        secretKey = response.getString("AES128");
        log.info("connected to " + args.get("server"));
        //

        switch (args.get("command")) {
            case "list_peers":
                request = new Document();
                request.append("command", "LIST_PEERS_REQUEST");
                writeOut(socket, encrypt(request));

                printResult(in.readLine());
                break;
            case "connect_peer":
                if (!args.containsKey("peer")) {
                    argWrong();
                }
                String[] targetAddr = args.get("peer").split(":");
                request = new Document();
                request.append("command", "CONNECT_PEER_REQUEST");
                request.append("host", targetAddr[0]);
                request.append("port", Integer.parseInt(targetAddr[1]));
                writeOut(socket, encrypt(request));

                printResult(in.readLine());
                break;
            case "disconnect_peer":
                if (!args.containsKey("peer")) {
                    argWrong();
                }

                String[] targetAddr2 = args.get("peer").split(":");
                request = new Document();
                request.append("command", "DISCONNECT_PEER_REQUEST");
                request.append("host", targetAddr2[0]);
                request.append("port", Integer.parseInt(targetAddr2[1]));
                writeOut(socket, encrypt(request));

                printResult(in.readLine());
                break;
            default:
                log.severe("unknown command, valid are list_peers, connect_peer, disconnect_peer");
        }
    }

    // decrypt and print the response
    private static void printResult(String response) {
        Document data = Document.parse(response);
        try {
            String docStr = AES128.Decrypt(data.getString("payload"), secretKey);
            log.info(docStr);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // encrypt a document
    private static String encrypt(Document d) {
        Document result = new Document();
        try {
            result.append("payload", AES128.Encrypt(d.toJson(), secretKey));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return result.toJson();
    }

    // write to socket
    private static void writeOut(Socket socket, String s) throws IOException {
        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF8"));
        out.write(s);
        out.newLine();
        out.flush();
    }
}

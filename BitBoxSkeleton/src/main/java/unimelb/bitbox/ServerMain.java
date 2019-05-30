package unimelb.bitbox;

import unimelb.bitbox.util.*;
import unimelb.bitbox.util.FileSystemManager.FileSystemEvent;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Logger;

public class ServerMain implements FileSystemObserver {
    private static Logger log = Logger.getLogger(ServerMain.class.getName());
    protected FileSystemManager fileSystemManager;
    int REV_SIZE = 65536;
    private List<Socket> peers;
    // in order to mark max peer
    private int initPeersCount;//0
    // for udp
    private List<HostPort> udpPeers;
    // is udp
    private boolean isUdp = false;
    // udp socket
    private DatagramSocket serverSocket;
    // public ids
    private String[] publicIds;
    // private key for encrypt
    private String privateKey = "aqwoeisjdhxndjsa";

    public ServerMain() throws NumberFormatException, IOException, NoSuchAlgorithmException {
        peers = new ArrayList<>(); 
        // server thread
        String mod = Configuration.getConfigurationValue("mod");
        isUdp = !mod.equals("tcp");

        // start client socket
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    int serverPort = Integer.valueOf(Configuration.getConfigurationValue("clientPort"));
                    ServerSocket listenSocket = new ServerSocket(serverPort);
                    while (true) {
                        Socket clientSocket = listenSocket.accept();
                        log.info("accept client socket: " + clientSocket);
                        // start connection thread
                        new Connection(clientSocket, null);
                    }
                } catch (IOException e) {
                    System.out.println("Listen socket:" + e.getMessage());
                }
            }
        }).start();


        // if we use tcp
        if (!isUdp) {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        int serverPort = Integer.valueOf(Configuration.getConfigurationValue("port"));
                        ServerSocket listenSocket = new ServerSocket(serverPort);
                        while (true) {
                            Socket clientSocket = listenSocket.accept();
                            log.info("accept socket: " + clientSocket);
                            // start connection thread
                            new Connection(clientSocket, null);
                        }
                    } catch (IOException e) {
                        System.out.println("Listen socket:" + e.getMessage());
                    }
                }
            }).start();
            // init peer connection
            initPeerConnection();
        }
        // if we use udp
        else {
            serverSocket = new DatagramSocket(Integer.valueOf(Configuration.getConfigurationValue("udpPort")));
            udpPeers = new ArrayList<>();

            // init peer connection
            initPeerConnection();

            // start connection thread
            new Connection(null, serverSocket);
        }


        fileSystemManager = new FileSystemManager(Configuration.getConfigurationValue("path"), this);

        // time thread
        new Thread(new Runnable() {
            @Override
            public void run() {
                int sleepTime = Integer.parseInt(Configuration.getConfigurationValue("syncInterval"));
                while (true) {
                    // sleep interval which in configuration
                    try {
                        Thread.sleep(sleepTime * 1000);
                    } catch (InterruptedException e) {
                        log.severe("Sleep interrupted: " + e.getMessage());
                    }

                    // begin sync events
                    log.info("sync events begin!");
                    for (FileSystemEvent pathevent : fileSystemManager.generateSyncEvents()) {
                        log.info(pathevent.toString());
                        processFileSystemEvent(pathevent);
                    }
                    log.info("sync events end!");
                }
            }
        }).start();
    }

    @Override
    public void processFileSystemEvent(FileSystemEvent fileSystemEvent) {
        
        if (Objects.equals(fileSystemEvent.name, ".DS_Store")) {
            return;
        }

        if (fileSystemEvent.event == FileSystemManager.EVENT.FILE_CREATE) {
            buildFIleRequest(fileSystemEvent, "FILE_CREATE_REQUEST");
        } else if (fileSystemEvent.event == FileSystemManager.EVENT.FILE_MODIFY) {
            buildFIleRequest(fileSystemEvent, "FILE_MODIFY_REQUEST");
        } else if (fileSystemEvent.event == FileSystemManager.EVENT.FILE_DELETE) {
            buildFIleRequest(fileSystemEvent, "FILE_DELETE_REQUEST");
        } else if (fileSystemEvent.event == FileSystemManager.EVENT.DIRECTORY_CREATE) {
            buildDirectoryRequest(fileSystemEvent, "DIRECTORY_CREATE_REQUEST");
        } else if (fileSystemEvent.event == FileSystemManager.EVENT.DIRECTORY_DELETE) {
            buildDirectoryRequest(fileSystemEvent, "DIRECTORY_DELETE_REQUEST");
        } else {
            log.severe("Unsupported file event: " + fileSystemEvent.event.toString());
        }
    }

    // build and send basic directory request which contains file descriptor and pathname
    private void buildDirectoryRequest(FileSystemEvent fileSystemEvent, String commandType) {
        // build request
        Document request = new Document();
        request.append("command", commandType);
        request.append("pathName", fileSystemEvent.pathName);

        // send request to all peers
        sendDocumentToPeer(commandType, request);
    }

    // build and send basic file request which contains file descriptor and pathname
    private void buildFIleRequest(FileSystemEvent fileSystemEvent, String commandType) {
        // build request
        Document request = new Document();
        request.append("command", commandType);
        Document descriptor = new Document();
        descriptor.append("md5", fileSystemEvent.fileDescriptor.md5);
        descriptor.append("lastModified", fileSystemEvent.fileDescriptor.lastModified);
        descriptor.append("fileSize", fileSystemEvent.fileDescriptor.fileSize);
        request.append("fileDescriptor", descriptor);
        request.append("pathName", fileSystemEvent.pathName);

        System.out.println(request.toJson());

        // send request to all peers
        sendDocumentToPeer(commandType, request);
    }

    // send a request document to all peers
    private void sendDocumentToPeer(String commandType, Document request) {
        // tcp
        if (!isUdp) {
            for (Socket peer : peers) {
                try {
                    BufferedWriter out = new BufferedWriter(new OutputStreamWriter(peer.getOutputStream(), "UTF8"));
                    out.write(request.toJson());
                    out.newLine();
                    out.flush();
                    log.info("send request to peer: "
                            + peer.getInetAddress().getHostName() + ": " + peer.getPort() + " " + request.toJson());
                } catch (IOException e) {
                    log.severe("can't write socket in " + commandType);
                }
            }
        }
        // udp
        else {
            for (HostPort hostPort : udpPeers) {
                try {
                    String strSend = request.toJson();
                    InetAddress inetAddress = InetAddress.getByName(hostPort.host);
                    DatagramPacket data_send = new DatagramPacket(strSend.getBytes(), strSend.length(), inetAddress, hostPort.port);
                    serverSocket.send(data_send);
                } catch (UnknownHostException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    // read public ids
    private void readPublicIds() {
        publicIds = Configuration.getConfigurationValue("authorized_keys").split(",");
    }

    // use to init peer connection
    @SuppressWarnings("unchecked")
    private void initPeerConnection() {
        // read public key
        readPublicIds();
        // if no peers to connect 
        if (Configuration.getConfigurationValue("peers").equals("none")) {
            return;
        }
        // build handShake request
        Document handShake = buildHandShakeRequest();

        String[] peersAddr = Configuration.getConfigurationValue("peers").split(",");
        for (String peerAddr : peersAddr) {
            initPeersCount++;
            peerAddr = peerAddr.trim();
            String[] addr = peerAddr.split(":");
            // perform a bfs
            Queue<String[]> next = new LinkedList<>();
            next.add(addr);
            System.out.println(Arrays.toString(addr));
            while (!next.isEmpty()) {
                addr = next.poll();
                try {
                    if (!isUdp) {
                        Socket socket = new Socket(addr[0], Integer.parseInt(addr[1]));
                        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF8"));
                        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF8"));
                        out.write(handShake.toJson());
                        out.newLine();
                        out.flush();
                        Document response = Document.parse(in.readLine());
                        // connection failed
                        log.info("receive response: " + response.toJson());
                        if (response.getString("command").equals("CONNECTION_REFUSED")) {
                            for (Document next_peer : (ArrayList<Document>) response.get("peers")) {
                                String[] nextAddr = {next_peer.getString("host"), String.valueOf(next_peer.getInteger("port"))};
                                next.add(nextAddr);
                            }
                            socket.close();
                        }
                        //
                        else if (response.getString("command").equals("INVALID_PROTOCOL")) {
                            log.severe("socket connect failed! Our request isn't correct: " + response.get("message"));
                        }
                        // connection success!
                        else {
                            peers.add(socket);
                            new Connection(socket, null);
                            System.out.println(peers);
                            log.info("Successfully connect to " + Arrays.toString(addr));
                            break;
                        }
                    } else {
                        String strSend = handShake.toJson();
                        InetAddress inetAddress = InetAddress.getByName(addr[0]);
                        DatagramPacket data_send = new DatagramPacket(strSend.getBytes(), strSend.length(), inetAddress, Integer.parseInt(addr[1]));
                        // handle timeout
                        int timeout = Integer.parseInt(Configuration.getConfigurationValue("timeout"));
                        serverSocket.setSoTimeout(timeout * 1000);
                        // handle retry
                        int retry = Integer.parseInt(Configuration.getConfigurationValue("retry"));
                        boolean revResponse = false;
                        int send_count = 0;
                        byte[] buf_rev = new byte[REV_SIZE];
                        DatagramPacket data_rev = new DatagramPacket(buf_rev, REV_SIZE);
                        System.out.println("here");

                        while (!revResponse && send_count < retry) {
                            try {
                                serverSocket.send(data_send);
                                serverSocket.receive(data_rev);
                                revResponse = true;
                            } catch (InterruptedIOException e) {
                                // if time out, reduce retry
                                send_count += 1;
                                log.info("Time out," + (retry - send_count)
                                        + " more tries...");
                            }
                        }
                        if (revResponse) {
                            // if we get the response
                            String str_receive = new String(data_rev.getData(), 0, data_rev.getLength());
                            Document response = Document.parse(str_receive);
                            log.info("receive response: " + response.toJson());
                            if (response.getString("command").equals("CONNECTION_REFUSED")) {
                                for (Document next_peer : (ArrayList<Document>) response.get("peers")) {
                                    String[] nextAddr = {next_peer.getString("host"), String.valueOf(next_peer.getInteger("port"))};
                                    next.add(nextAddr);
                                }
                            }
                            //
                            else if (response.getString("command").equals("INVALID_PROTOCOL")) {
                                log.severe("udp socket connect failed! Our request isn't correct: " + response.get("message"));
                            }
                            // connection success!
                            else {
                                Document targetHostPort = (Document) response.get("hostPort");
                                HostPort newPeer = new HostPort(targetHostPort.getString("host"), (int) targetHostPort.getLong("port"));
                                udpPeers.add(newPeer);
                                log.info("Successfully connect to " + Arrays.toString(addr));
                                System.out.println("set to 0");
                                serverSocket.setSoTimeout(0);
                                break;
                            }
                            data_rev.setLength(REV_SIZE);
                        } else {
                            log.info("No response -- give up to connect to " + addr[0] + ":" + addr[1]);
                        }


                    }
                } catch (IOException e) {
                    log.severe("socket connect failed!" + e.getMessage());
                }
            }
        }
    }

    // handle handshake request
    // because we will change the number of peer sockets, this method must be synchronized
    private synchronized Document handleHandShake(String host, int port) throws IOException {
        Document result = new Document();
        int size = 0;
        if (!isUdp) {
            size = peers.size();
        } else {
            size = udpPeers.size();
        }

        if (size >= Integer.parseInt(Configuration.getConfigurationValue("maximumIncommingConnections")) + initPeersCount) {
            result.append("command", "CONNECTION_REFUSED");
            result.append("message", "connection limit reached");
            ArrayList<Document> peerList = new ArrayList<>();
            listPeers(result, peerList);
            return result;
        }

        if (!isUdp) {
            for (Socket s : peers) {
                if (s.getInetAddress().getHostName().equals(host) && s.getPort() == port) {
                    result.append("command", "INVALID_PROTOCOL");
                    result.append("message", "Connection already established");
                    return result;
                }
            }
            Socket persistentSocket = new Socket(host, port);
            System.out.println(persistentSocket);
            new Connection(persistentSocket, null);
            System.out.println(result.toJson());
            peers.add(persistentSocket);
        } else {
            for (HostPort hostPort : udpPeers) {
                if (hostPort.host.equals(host) && hostPort.port == port) {
                    result.append("command", "INVALID_PROTOCOL");
                    result.append("message", "Connection already established");
                    return result;
                }
            }
            udpPeers.add(new HostPort(host, port));
        }

        result.append("command", "HANDSHAKE_RESPONSE");
        Document hostPort = new Document();
        hostPort.append("host", Configuration.getConfigurationValue("advertisedName"));
        if (!isUdp) {
            hostPort.append("port", Integer.parseInt(Configuration.getConfigurationValue("port")));
        } else {
            hostPort.append("port", Integer.parseInt(Configuration.getConfigurationValue("udpPort")));
        }
        result.append("hostPort", hostPort);

        return result;
    }

    // for list peer
    private Document handleListPeer() {
        Document result = new Document();
        result.append("command", "LIST_PEERS_RESPONSE");
        ArrayList<Document> peerList = new ArrayList<>();
        listPeers(result, peerList);

        return result;
    }

    // handle connect to peer
    private Document handleConnectToPeer(String host, int port) {
        // build result
        Document result = new Document();
        result.append("command", "CONNECT_PEER_RESPONSE");
        result.append("host", host);
        result.append("port", port);
        // build handShake request
        Document handShake = buildHandShakeRequest();

        // find if the connection already established
        if(!isUdp){
            for (Socket s : peers) {
                if (s.getInetAddress().getHostName().equals(host) && s.getPort() == port) {
                    result.append("status", false);
                    result.append("message", "connection already established");
                    return result;
                }
            }
        }
        else{
            for (HostPort hostPort : udpPeers) {
                if (hostPort.host.equals(host) && hostPort.port == port) {
                    result.append("status", false);
                    result.append("message", "connection already established");
                    return result;
                }
            }
        }

        try {
            if (!isUdp) {
                Socket socket = new Socket(host, port);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF8"));
                BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF8"));
                out.write(handShake.toJson());
                out.newLine();
                out.flush();
                Document response = Document.parse(in.readLine());
                // connection failed
                log.info("receive response: " + response.toJson());
                if (!response.getString("command").equals("HANDSHAKE_RESPONSE")) {
                    result.append("status", false);
                    result.append("message", "connection failed");
                    socket.close();
                }
                // connection success!
                else {
                    peers.add(socket);
                    new Connection(socket, null);
                    result.append("status", true);
                    result.append("message", "connect to peer");//connected
                    log.info("Successfully connect to " + host + ":" + port);
                }
            } else {
                String strSend = handShake.toJson();
                InetAddress inetAddress = InetAddress.getByName(host);
                DatagramPacket data_send = new DatagramPacket(strSend.getBytes(), strSend.length(), inetAddress, port);

                try {
                    serverSocket.send(data_send);
                } catch (IOException ex) {
                    ex.printStackTrace();
                }

                // connection success!
                HostPort newPeer = new HostPort(host, port);
                udpPeers.add(newPeer);
                result.append("status", true);
                result.append("message", "connect to peer");
            }
        } catch (IOException e) {
            result.append("status", false);
            result.append("message", "connection failed");
            log.severe("socket connect failed!" + e.getMessage());
        }

        return result;
    }

    // for udp to disconnect from peer(update peers/udpPeers)
    private void disconnectPeer(String host, int port){
        // handle tcp
        if(!isUdp){
            for (int i = 0; i < peers.size(); i++){
                Socket s = peers.get(i);
                if(s.getInetAddress().getHostName().equals(host) && s.getPort() == port){
                    log.info("disconnect from peer " + host + ":" + port);
                    peers.remove(i);
                    break;
                }
            }
        }
        // handle udp
        else{
            for (int i = 0; i < udpPeers.size(); i++){
                HostPort hostPort = udpPeers.get(i);
                if(hostPort.host.equals(host) && hostPort.port == port){
                    log.info("disconnect from peer " + host + ":" + port);
                    udpPeers.remove(i);
                    break;
                }
            }
        }
    }

    // handle disconnect from peer request
    private Document handleDisconectionPeer(String host, int port){
        // build result
        Document result = new Document();
        result.append("command", "DISCONNECT_PEER_RESPONSE");
        result.append("host", host);
        result.append("port", port);

        if (!isUdp) {
            for (int i = 0; i < peers.size(); i++) {
                Socket s = peers.get(i);
                if (s.getInetAddress().getHostName().equals(host) && s.getPort() == port) {
                    result.append("status", true);
                    result.append("message", "disconnected from peer");

                    Document disconnectRequest = new Document();
                    disconnectRequest.append("command", "DISCONNECT");

                    disconnectRequest.append("host", Configuration.getConfigurationValue("advertisedName"));
                    disconnectRequest.append("port", Integer.parseInt(
                            Configuration.getConfigurationValue("port")));
                    try {
                        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(s.getOutputStream(), "UTF8"));
                        out.write(disconnectRequest.toJson());
                        out.newLine();
                        out.flush();
                        s.close();
                    } catch (IOException e) {
                        log.severe("can't close socket");
                    }
                    peers.remove(i);
                    return result;
                }
            }
        } else {
            for (int i = 0; i < udpPeers.size(); i++) {
                HostPort hostPort = udpPeers.get(i);
                if (hostPort.host.equals(host) && hostPort.port == port) {
                    result.append("status", true);
                    result.append("message", "disconnected from peer");
                    // tell peer to disconect
                    Document disconnectRequest = new Document();
                    disconnectRequest.append("command", "DISCONNECT");
                    disconnectRequest.append("host", Configuration.getConfigurationValue("advertisedName"));
                    disconnectRequest.append("port", Integer.parseInt(
                            Configuration.getConfigurationValue("udpPort")));
                    String strSend = disconnectRequest.toJson();
                    try {
                        InetAddress inetAddress = InetAddress.getByName(host);
                        DatagramPacket dataSend = new DatagramPacket(strSend.getBytes(), strSend.length(), inetAddress, port);
                        serverSocket.send(dataSend);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    // remove connection
                    udpPeers.remove(i);
                    return result;
                }
            }
        }

        // we can't find peer
        result.append("status", false);
        result.append("message", "connection not active");
        return result;
    }

    // build handshake request
    private Document buildHandShakeRequest() {
        Document handShake = new Document();
        handShake.append("command", "HANDSHAKE_REQUEST");
        Document hostPort = new Document();
        hostPort.append("host", Configuration.getConfigurationValue("advertisedName"));
        if (!isUdp) {
            hostPort.append("port", Integer.parseInt(Configuration.getConfigurationValue("port")));
        } else {
            hostPort.append("port", Integer.parseInt(Configuration.getConfigurationValue("udpPort")));
        }
        handShake.append("hostPort", hostPort);
        return handShake;
    }

    // list all peers and add to result
    private void listPeers(Document result, ArrayList<Document> peerList) {
        if (!isUdp) {
            for (Socket s : peers) {
                Document peer = new Document();
                peer.append("host", s.getInetAddress().getHostName());
                peer.append("port", s.getPort());
                peerList.add(peer);
            }
            result.append("peers", peerList);
        } else {
            for (HostPort hostPort : udpPeers) {
                Document peer = new Document();
                peer.append("host", hostPort.host);
                peer.append("port", hostPort.port);
                peerList.add(peer);
            }
            result.append("peers", peerList);
        }
    }

    //###############################
    //#   TCP server accept thread  #
    //###############################
    class Connection extends Thread {
        DatagramSocket datagramSocket;
        BufferedReader in;
        BufferedWriter out;
        Socket clientSocket;
        int port;
        String host;
        int REV_SIZE = 65536;
        int targetPort;
        String targetHost;
        byte[] buf_rev;
        private HashSet<String> loadingFileName;
        private HashMap<String, String> loadingFileNameInUdp;
        private long blockSize = Long.parseLong(Configuration.getConfigurationValue("blockSize"));
        private Logger log = Logger.getLogger(Connection.class.getName());

        public Connection(Socket aClientSocket, DatagramSocket datagramSocket) {
            // accept a socket
            loadingFileName = new HashSet<>();
            loadingFileNameInUdp = new HashMap<>();
            if (aClientSocket != null) {
                try {
                    clientSocket = aClientSocket;
                    in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream(), "UTF8"));
                    out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream(), "UTF8"));
                    this.start();
                } catch (IOException e) {
                    System.out.println("Connection:" + e.getMessage());
                }
            }
            // accept udp socket
            else {
                this.datagramSocket = datagramSocket;
                buf_rev = new byte[REV_SIZE];
                this.start();
            }
        }

        // accept request
        public void run() {
            // because we use persistent tcp connections, we should wait for next request
            try {
                while (true) {
                    // read a line of data from the stream
                    Document data = new Document();
                    // tcp accept
                    if (clientSocket != null) {
                        String dataStr = in.readLine();
                        log.info("get message: " + dataStr);
                        log.info(clientSocket.toString());
                        if (dataStr == null) {
                            clean();
                            break;
                        }
                        data = Document.parse(dataStr);
                    }
                    // udp accept
                    else {
                        DatagramPacket data_rev = new DatagramPacket(buf_rev, REV_SIZE);
                        datagramSocket.receive(data_rev);
                        targetPort = data_rev.getPort();
                        targetHost = data_rev.getAddress().getHostName();
                        String dataStr = new String(data_rev.getData(), 0, data_rev.getLength());
                        data = Document.parse(dataStr);
                        log.info("get message: " + dataStr);
                    }
                    log.info(Configuration.getConfigurationValue("advertisedName") + " receive a request");
                    // check for client request
                    if (data.containsKey("payload")) {
                        Document document = new Document();
                        String secretKey = "";
                        // want to find first key to decrypt request
                        for (String publicId : publicIds) {
                            try {
                                secretKey = AES128.Encrypt(publicId, privateKey).substring(0, 16);
                                String docStr = AES128.Decrypt(data.getString("payload"), secretKey);
                                System.out.println(docStr);
                                document = Document.parse(docStr);
                                if (document.containsKey("command")) {
                                    break;
                                }
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }

                        // analyze request
                        Document result = new Document();
                        if (document.containsKey("command")) {
                            switch (document.getString("command")) {
                                case "LIST_PEERS_REQUEST":
                                    result = ServerMain.this.handleListPeer();
                                    writeToOut(encrypt(result, secretKey));
                                    break;
                                case "CONNECT_PEER_REQUEST":
                                    result = ServerMain.this.handleConnectToPeer(
                                            document.getString("host"),
                                            document.getInteger("port"));
                                    writeToOut(encrypt(result, secretKey));
                                    break;
                                case "DISCONNECT_PEER_REQUEST":
                                    result = ServerMain.this.handleDisconectionPeer(
                                            document.getString("host"),
                                            document.getInteger("port"));
                                    writeToOut(encrypt(result, secretKey));
                                    break;
                            }
                        } else {
                            log.severe("we can't decrypt playload");
                        }
                    }
                    // normal request
                    else if (checkField(data, "command", "", String.class)) {
                        switch (data.getString("command")) {
                            case "HANDSHAKE_REQUEST":
                                // a flag to test connection is build successfully
                                boolean connectionBuild = false;
                                // first we check the input data and then we handle the request
                                if (checkField(data, "hostPort", "", Document.class)) {
                                    Document document = (Document) data.get("hostPort");
                                    if (checkField(document, "host", "hostPort", String.class) && checkField(document, "port", "hostPort", Long.class)) {
                                        //handle request
                                        String host = document.getString("host");
                                        int port = document.getInteger("port");
                                        System.out.println(port);
                                        Document response = ServerMain.this.handleHandShake(host, port);
                                        System.out.println(response.toJson());
                                        writeToOut(response.toJson());
                                        if (response.getString("command").equals("HANDSHAKE_RESPONSE")) {
                                            connectionBuild = true;
                                            this.port = port;
                                            this.host = host;
                                        }
                                    }
                                }
                                // not build connection we should close socket
                                if (!connectionBuild) {
                                    clientSocket.close();
                                    return;
                                }
                                break;
                            case "FILE_CREATE_REQUEST":
                                // first we check the input data and then we handle the request
                                if (checkFileRequest(data)) {
                                    data.put("command", "FILE_CREATE_RESPONSE");
                                    Document descriptor = (Document) data.get("fileDescriptor");

                                    // check if a safe path name
                                    if (!fileSystemManager.isSafePathName(data.getString("pathName"))) {
                                        data.append("message", "unsafe pathname given");
                                        data.append("status", false);
                                        writeToOut(data.toJson());
                                        break;
                                    }
                                    // check if the path exist
                                    if (fileSystemManager.fileNameExists(data.getString("pathName"))) {
                                        data.append("message", "pathname already exists");
                                        data.append("status", false);
                                        writeToOut(data.toJson());
                                        break;
                                    }

                                    // check if create file is success
                                    if (!fileSystemManager.createFileLoader(data.getString("pathName"),
                                            descriptor.getString("md5"),
                                            descriptor.getLong("fileSize"),
                                            descriptor.getLong("lastModified"))) {
                                        //not success
                                        data.append("message", "there was a problem creating the file");
                                        data.append("status", false);
                                        writeToOut(data.toJson());
                                        break;
                                    } else {
                                        // success! we should request file content
                                        long size = descriptor.getLong("fileSize");
                                        loadingFileName.add(data.getString("pathName"));
                                        loadingFileNameInUdp.put(targetHost + ":" + targetPort, data.getString("pathName"));
                                        // if file size is 0, we just complete
                                        if (size == 0) {
                                            fileSystemManager.checkWriteComplete(data.getString("pathName"));
                                            loadingFileName.remove(data.getString("pathName"));
                                            data.append("message", "empty file create complete");
                                            data.append("status", true);
                                            writeToOut(data.toJson());
                                        }
                                        // if we can use short cut
                                        else if (fileSystemManager.checkShortcut(data.getString("pathName"))) {
                                            loadingFileName.remove(data.getString("pathName"));
                                            data.append("message", "use short cut to create file");
                                            data.append("status", true);
                                            writeToOut(data.toJson());
                                        }
                                        // request file content
                                        else {
                                            System.out.println(data.toJson());
                                            data.append("message", "file loader ready");
                                            data.append("status", true);
                                            writeToOut(data.toJson());

                                            // send byte request
                                            buildByteRequest(data, 0, Math.min(blockSize, descriptor.getLong("fileSize")));
                                        }
                                    }
                                }
                                break;
                            case "FILE_CREATE_RESPONSE":
                                // we just do nothing
                                break;
                            case "FILE_BYTES_REQUEST":
                                // read file
                                if (checkFileRequest(data)) {
                                    if (checkField(data, "position", "", Long.class) && checkField(data, "length", "", Long.class)) {
                                        data.put("command", "FILE_BYTES_RESPONSE");
                                        Document fileDescriptor = (Document) data.get("fileDescriptor");
                                        ByteBuffer byteBuffer = fileSystemManager.readFile(fileDescriptor.getString("md5"), data.getLong("position"), data.getLong("length"));
                                        if (byteBuffer == null) {
                                            // read failed
                                            data.append("content", "");
                                            data.append("message", "read failed!");
                                            data.append("status", false);
                                            writeToOut(data.toJson());
                                        } else {
                                            // read success
                                            data.append("content", Base64.getEncoder().encodeToString(byteBuffer.array()));
                                            data.append("message", "read success!");
                                            data.append("status", true);
                                            writeToOut(data.toJson());
                                        }
                                    }
                                }
                                break;
                            case "FILE_BYTES_RESPONSE":
                                // write file
                                if (checkFileRequest(data)) {
                                    if (checkField(data, "position", "", Long.class)
                                            && checkField(data, "length", "", Long.class)
                                            && checkField(data, "content", "", String.class)
                                            && checkField(data, "status", "", Boolean.class)
                                            && checkField(data, "message", "", String.class)) {
                                        if (data.getBoolean("status")) {
                                            Document fileDescriptor = (Document) data.get("fileDescriptor");
                                            long size = fileDescriptor.getLong("fileSize");
                                            long position = data.getLong("position");
                                            long length = data.getLong("length");
                                            ByteBuffer byteBuffer = ByteBuffer.allocate((int) length);
                                            byteBuffer.put(Base64.getDecoder().decode(data.getString("content")));
                                            // use this to allow channel to write
                                            byteBuffer.position(0);
                                            if (!fileSystemManager.writeFile(data.getString("pathName"), byteBuffer, position)) {
                                                // write failed
                                                log.severe("write file failed!");
                                            } else {
                                                // write success
                                                if (position + length == size) {
                                                    // write complete
                                                    if (!fileSystemManager.checkWriteComplete(data.getString("pathName"))) {
                                                        log.severe("write not complete!");
                                                    }
                                                    // cancel loading file name
                                                    loadingFileName.remove(data.getString("pathName"));
                                                } else {
                                                    buildByteRequest(data, position + length, Math.min(blockSize, size - position - length));
                                                }
                                            }
                                        } else {
                                            // request is failed
                                            log.severe("read request failed: " + data.getString("message"));
                                        }
                                    }
                                }
                                break;
                            case "FILE_DELETE_REQUEST":
                                // first we check the input data and then we handle the request
                                if (checkFileRequest(data)) {
                                    data.put("command", "FILE_DELETE_RESPONSE");
                                    Document descriptor = (Document) data.get("fileDescriptor");

                                    // check if a safe path name
                                    if (!fileSystemManager.isSafePathName(data.getString("pathName"))) {
                                        data.append("message", "unsafe pathname given");
                                        data.append("status", false);
                                        writeToOut(data.toJson());
                                        break;
                                    }

                                    // check if the path exist
                                    if (!fileSystemManager.fileNameExists(data.getString("pathName"))) {
                                        data.append("message", "pathname not exists");
                                        data.append("status", false);
                                        writeToOut(data.toJson());
                                        break;
                                    }

                                    // check if we can delete
                                    if (!fileSystemManager.deleteFile(data.getString("pathName"),
                                            descriptor.getLong("lastModified"),
                                            descriptor.getString("md5"))) {
                                        data.append("message", "there was a problem deleting the file");
                                        data.append("status", false);
                                        writeToOut(data.toJson());
                                        break;
                                    } else {
                                        // delete complete
                                        data.append("message", "file deleted");
                                        data.append("status", true);
                                        writeToOut(data.toJson());
                                    }
                                }
                                break;
                            case "FILE_DELETE_RESPONSE":
                                // we just do nothing
                                break;
                            case "FILE_MODIFY_REQUEST":
                                // first we check the input data and then we handle the request
                                if (checkFileRequest(data)) {
                                    data.put("command", "FILE_MODIFY_RESPONSE");
                                    Document descriptor = (Document) data.get("fileDescriptor");

                                    // check if a safe path name
                                    if (!fileSystemManager.isSafePathName(data.getString("pathName"))) {
                                        data.append("message", "unsafe pathname given");
                                        data.append("status", false);
                                        writeToOut(data.toJson());
                                        break;
                                    }
                                    // check if the path exist
                                    if (!fileSystemManager.fileNameExists(data.getString("pathName"))) {
                                        data.append("message", "pathname not exists");
                                        data.append("status", false);
                                        writeToOut(data.toJson());
                                        break;
                                    }

                                    // check if create file is success
                                    if (!fileSystemManager.modifyFileLoader(data.getString("pathName"),
                                            descriptor.getString("md5"),
                                            descriptor.getLong("lastModified"))) {
                                        //not success
                                        data.append("message", "there was a problem modifying the file");
                                        data.append("status", false);
                                        writeToOut(data.toJson());
                                        break;
                                    } else {
                                        // success! we should request file content
                                        long size = descriptor.getLong("fileSize");
                                        loadingFileName.add(data.getString("pathName"));
                                        // if file size is 0, we just complete

                                        if (size == 0) {
                                            fileSystemManager.checkWriteComplete(data.getString("pathName"));
                                            loadingFileName.remove(data.getString("pathName"));
                                            data.append("message", "empty file modify complete");
                                            data.append("status", true);
                                            writeToOut(data.toJson());
                                        }
                                        // if data already exist
                                        else if (fileSystemManager.checkShortcut(data.getString("pathName"))) {
                                            loadingFileName.remove(data.getString("pathName"));
                                            data.append("message", "file already exists with matching content");
                                            data.append("status", true);
                                            writeToOut(data.toJson());
                                        }
                                        // request file content
                                        else {
                                            System.out.println(data.toJson());
                                            data.append("message", "file loader ready");
                                            data.append("status", true);
                                            writeToOut(data.toJson());

                                            // send byte request
                                            buildByteRequest(data, 0, Math.min(blockSize, descriptor.getLong("fileSize")));
                                        }
                                    }
                                }
                                break;
                            case "FILE_MODIFY_RESPONSE":
                                // we just do nothing
                                break;
                            case "DIRECTORY_CREATE_REQUEST":
                                // first we check the input data and then we handle the request
                                if (checkField(data, "pathName", "", String.class)) {
                                    data.put("command", "DIRECTORY_CREATE_RESPONSE");

                                    // check if a safe path name
                                    if (!fileSystemManager.isSafePathName(data.getString("pathName"))) {
                                        data.append("message", "unsafe pathname given");
                                        data.append("status", false);
                                        writeToOut(data.toJson());
                                        break;
                                    }

                                    // check if the path exist
                                    if (fileSystemManager.dirNameExists(data.getString("pathName"))) {
                                        data.append("message", "pathname already exists");
                                        data.append("status", false);
                                        writeToOut(data.toJson());
                                        break;
                                    }

                                    if (!fileSystemManager.makeDirectory(data.getString("pathName"))) {
                                        // failed
                                        data.append("message", "there was a problem creating the directory");
                                        data.append("status", false);
                                        writeToOut(data.toJson());
                                        break;
                                    } else {
                                        // create complete
                                        data.append("message", "directory created");
                                        data.append("status", true);
                                        writeToOut(data.toJson());
                                    }
                                }
                                break;
                            case "DIRECTORY_CREATE_RESPONSE":
                                // we just do nothing
                                break;
                            case "DIRECTORY_DELETE_REQUEST":
                                // first we check the input data and then we handle the request
                                if (checkField(data, "pathName", "", String.class)) {
                                    data.put("command", "DIRECTORY_DELETE_RESPONSE");

                                    // check if a safe path name
                                    if (!fileSystemManager.isSafePathName(data.getString("pathName"))) {
                                        data.append("message", "unsafe pathname given");
                                        data.append("status", false);
                                        writeToOut(data.toJson());
                                        break;
                                    }

                                    // check if the path exist
                                    if (!fileSystemManager.dirNameExists(data.getString("pathName"))) {
                                        data.append("message", "pathname not exists");
                                        data.append("status", false);
                                        writeToOut(data.toJson());
                                        break;
                                    }

                                    // check if we can delete
                                    if (!fileSystemManager.deleteDirectory(data.getString("pathName"))) {
                                        data.append("message", "there was a problem deleting the directory");
                                        data.append("status", false);
                                        writeToOut(data.toJson());
                                        break;
                                    } else {
                                        // delete complete
                                        data.append("message", "directory deleted");
                                        data.append("status", true);
                                        writeToOut(data.toJson());
                                    }
                                }
                                break;
                            case "DIRECTORY_DELETE_RESPONSE":
                                // we just do nothing
                                break;
                            case "AUTH_REQUEST":
                                if (checkField(data, "identity", "", String.class)) {
                                    String id = data.getString("identity");
                                    boolean found = false;
                                    for (String publicId : publicIds) {
                                        if (id.equals(publicId)) {
                                            Document invalidResponse = new Document();
                                            invalidResponse.append("command", "AUTH_RESPONSE");
                                            invalidResponse.append("status", true);
                                            invalidResponse.append("message", "public key found");
                                            try {
                                                invalidResponse.append("AES128", AES128.Encrypt(id, privateKey).substring(0, 16));
                                            } catch (Exception e) {
                                                log.severe("encrypt fail " + e.getMessage());
                                            }
                                            writeToOut(invalidResponse.toJson());
                                            found = true;
                                            break;
                                        }
                                    }

                                    // if we not found id
                                    if (!found) {
                                        Document invalidResponse = new Document();
                                        invalidResponse.append("command", "AUTH_RESPONSE");
                                        invalidResponse.append("status", false);
                                        invalidResponse.append("message", "public key not found");
                                        writeToOut(invalidResponse.toJson());
                                    }
                                    break;
                                }
                            case "INVALID_PROTOCOL":
                                log.severe("our request is invalid");
                                break;
                            case "DISCONNECT":
                                disconnectPeer(data.getString("host"), data.getInteger("port"));
                                break;
                            default:
                                writeToOut(buildInvalidResponse("unknown command: " + data.getString("command")));
                        }
                    }
                }
            } catch (EOFException e) {
                log.severe("EOF:" + e.getMessage());
                clean();
            } catch (IOException e) {
                log.severe("readline:" + e.getMessage());
                clean();
            } catch (NoSuchAlgorithmException e) {
                log.severe("No such algorithm! " + e.getMessage());
                clean();
            }
        }

        // encrypt a document
        private  String encrypt(Document d, String key){
            Document result = new Document();
            try {
                result.append("payload", AES128.Encrypt(d.toJson(), key));
            } catch (Exception e) {
                e.printStackTrace();
            }

            return result.toJson();
        }

        // do some clean work
        private void clean() {
            // close socket
            for (int i = 0; i < peers.size(); i++) {
                Socket s = peers.get(i);
                if (s.getInetAddress().getHostName().equals(host) && s.getPort() == port) {
                    try {
                        s.close();
                        clientSocket.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    log.info("socket remove : " + s);
                    peers.remove(i);
                    break;
                }
            }
            // clean file
            for (String pathName : loadingFileName) {
                try {
                    fileSystemManager.cancelFileLoader(pathName);
                } catch (IOException e) {
                    log.severe(e.getMessage());
                }
            }

            if (clientSocket != null) {
                log.info("connection lost " + clientSocket.toString() + " socket has closed and loading file canceled");
            }
        }

        // build and send byte request
        private void buildByteRequest(Document fileBasic, long position, long length) throws IOException {
            Document request = new Document();
            request.append("command", "FILE_BYTES_REQUEST");
            request.append("fileDescriptor", (Document) fileBasic.get("fileDescriptor"));
            request.append("pathName", fileBasic.getString("pathName"));
            request.append("position", position);
            request.append("length", length);

            writeToOut(request.toJson());
        }

        // write response to out
        private void writeToOut(String result) throws IOException {
            if (clientSocket != null) {
                log.info("write out: " + result);
                out.write(result);
                out.newLine();
                out.flush();
            } else {
                InetAddress inetAddress = InetAddress.getByName(targetHost);
                DatagramPacket dataSend = new DatagramPacket(result.getBytes(),
                        result.length(), inetAddress, targetPort);
                datagramSocket.send(dataSend);
                System.out.println("send!" + result);
            }
        }

        // build invalid response with message
        private String buildInvalidResponse(String message) {
            Document response = new Document();
            response.append("command", "INVALID_PROTOCOL");
            response.append("message", message);
            return response.toJson();
        }

        // check file request is correct
        private boolean checkFileRequest(Document data) throws IOException {
            if (checkField(data, "pathName", "", String.class) && checkField(data, "fileDescriptor", "", Document.class)) {
                Document descriptor = (Document) data.get("fileDescriptor");
                return checkField(descriptor, "md5", "", String.class) && checkField(descriptor, "lastModified", "", Long.class) && checkField(descriptor, "fileSize", "", Long.class);
            }

            return false;
        }

        // check list field and type
        private boolean checkList(Document document, String key, String prifix, Class c) throws IOException {
            if (!document.containsKey(key)) {
                writeToOut(buildInvalidResponse("message must contain a field called: " + prifix + "." + key));

                return false;
            }
            List l = new ArrayList();
            try {
                l = (ArrayList) document.get(key);
            } catch (ClassCastException e) {
                writeToOut(buildInvalidResponse("message must contain a list field called: " + prifix + "." + key));
                return false;
            }

            if (!l.isEmpty()) {
                try {
                    c.cast(l.get(0));
                } catch (ClassCastException e) {
                    writeToOut(buildInvalidResponse("message must contain a list field contains" + c.getName() + " called: " + prifix + "." + key));
                    return false;
                }
            }

            return true;
        }

        // check the field exist and type
        private boolean checkField(Document document, String key, String prifix, Class c) throws IOException {
            if (!document.containsKey(key)) {
                writeToOut(buildInvalidResponse("message must contain a field called: " + prifix + "." + key));

                return false;
            }
            try {
                c.cast(document.get(key));
            } catch (ClassCastException e) {
                writeToOut(buildInvalidResponse("message must contain a " + c.getName() + " field called: " + prifix + "." + key));
                return false;
            }

            return true;
        }
    }
}

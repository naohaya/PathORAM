package com.client;

/*
 * client connects to the server
 * initializes server
 * gets path from the server, finds the block he wants
 * writes back path to the server
 */
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.pathoram.*;

/* Cipher */
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class Client implements ClientInterface {
	
	public static int requestID = 0;
	
	protected InetSocketAddress serverAddress;
	protected AsynchronousChannelGroup mThreadGroup;
	protected AsynchronousSocketChannel mChannel;

	/* Cipher */
//	String pass = "P@55W0rd";
//	CriptoKeyGenerator keygen = new CriptoKeyGenerator(pass);
	CriptoKeyGenerator keygen = new CriptoKeyGenerator();
	SecretKey seckey =  keygen.getKey();
	GCMParameterSpec param = keygen.getParam();
	byte[] nonce = keygen.getNonce();

	
	int[] position_map;
	Stash stash;
	RandomForORAM rand;
	ByteSerializable seria;
	
	@SuppressWarnings("rawtypes")
	public Client(){
		this.position_map = new int[Configs.BLOCK_COUNT];
		this.stash = new Stash();
		this.rand = new RandomForORAM();
		this.seria = new ByteSerializable();
		//give each block a initialize random path
		for(int i=0;i<Configs.BLOCK_COUNT;i++){
			position_map[i] = rand.getRandomLeaf() + Configs.LEAF_START;
		}
		//connect to server
		try {
			serverAddress = new InetSocketAddress(Configs.SERVER_HOSTNAME,Configs.SERVER_PORT);
			mThreadGroup = AsynchronousChannelGroup.withFixedThreadPool(Configs.THREAD_FIXED, Executors.defaultThreadFactory());
			mChannel = AsynchronousSocketChannel.open(mThreadGroup);
			Future connection = mChannel.connect(serverAddress);
			connection.get();
			System.out.println("client connect to server successful!!");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	@Override
	public void initServer() {
		// TODO Auto-generated method stub
		ByteBuffer header = MessageUtility.createMessageHeaderBuffer(MessageUtility.ORAM_INIT, 0);
		byte[] responseBytes = sendAndGetMessage(header, MessageUtility.ORAM_INIT);
		System.out.println("client INIT server successful!" + responseBytes[0]);
		responseBytes = null;
	}

	public byte[] obliviousAccess(int blockIndex, byte[] newData, Operation op){
		System.out.println("process request "+requestID);
		requestID++;
		
		byte[] returndata;// return data
		
		//get path id
		int position = position_map[blockIndex];
		//sign the block to a new random path
		position_map[blockIndex] = rand.getRandomLeaf() + Configs.LEAF_START;
		
		//read path
		readPath(position);
		
		//get request block from stash
		Block b = stash.find_by_index(blockIndex);
		
		//write request
		if(op == Operation.WRITE){
			/* Encryption */
			byte[] ciphertext = DataCripto.encrypt(newData, seckey, nonce);
			System.out.println(ciphertext + " by write operation."); // for debug
			
			b = new Block(position_map[blockIndex],blockIndex,ciphertext); // put the chipher text into the block
			stash.add(b);//update block path id and data
			returndata = newData;
		}
		//read request
		else{
			if(b == null){//didn't find block in stash, return 0
				returndata = new byte[Configs.BLOCK_DATA_LEN];
			}else{
				returndata = b.getData();
				/* Decryption */
				param = keygen.generateGCMParameter(nonce);
				byte[] deciphertext = DataCripto.decrypt(returndata, seckey, nonce);
				returndata = deciphertext;
				System.out.println(returndata + "by read operation."); // for debug
				b = new Block(position_map[blockIndex],blockIndex,deciphertext);
				stash.updataBlock(b);//update block path id
			}
		}
		// get blocks from client stash to proper bucket
		Bucket[] bucket_list = new Bucket[Configs.HEIGHT];
		int countPtr = 0;
		for (int pos_run = position; pos_run >= 0; pos_run = (pos_run - 1) >> 1) {
			Block[] block_list = stash.remove_by_bucket(pos_run);
			ArrayList<Block> blocks = new ArrayList<Block>(Configs.Z);
			for(int i=0;i<Configs.Z;i++){
				blocks.add(block_list[i]);
			}
			bucket_list[countPtr] = new Bucket(blocks);
			countPtr++;
			if (pos_run == 0)
				break;
		}
		
		//write path
		writePath(position, bucket_list);
		bucket_list = null;
		
		System.out.println();
		
		return returndata;
	}
	
	@Override
	public void readPath(int pathID) {
		// TODO Auto-generated method stub
		byte[] pathIdBytes = Ints.toByteArray(pathID);
		byte[] header = MessageUtility.createMessageHeaderBytes(MessageUtility.ORAM_READPATH,
				pathIdBytes.length);
		ByteBuffer requestBuffer = ByteBuffer.wrap(Bytes.concat(header, pathIdBytes));
		byte[] responseBytes = sendAndGetMessage(requestBuffer, MessageUtility.ORAM_READPATH);
		int startIndex = 0;
		int bucket_bytes_len = (4+4+Configs.BLOCK_DATA_LEN)*Configs.Z;
		for(int i=0;i<Configs.HEIGHT;i++){
			//recovery bucket from the response byte array
			byte[] bucket_bytes = Arrays.copyOfRange(
					responseBytes, startIndex, startIndex+bucket_bytes_len);
			startIndex += bucket_bytes_len;
			Bucket bucket = seria.bucketFromSerializable(bucket_bytes);
			ArrayList<Block> blocks = bucket.getBlocks();
			for(Block blk:blocks){
				//add real block to the stash
				if(blk.getIndex() != -1){
					stash.add(blk);
				}
			}
		}
		System.out.println("client READPATH "+pathID+" successful!");
		pathIdBytes = null;
		header = null;
		requestBuffer = null;
		responseBytes = null;
	}

	@Override
	public void writePath(int pathID, Bucket[] bucket_list) {
		// TODO Auto-generated method stub
		byte[] pathIdBytes = Ints.toByteArray(pathID);
		byte[][] pathBytes = new byte[Configs.HEIGHT][];
		for(int i=0;i<Configs.HEIGHT;i++){
			pathBytes[i] = seria.bucketSerializable(bucket_list[i]);
		}
		//join all bucket bytes
		byte[] pathBytesWrap = pathBytes[0];
		for(int i =1;i<Configs.HEIGHT;i++){
			pathBytesWrap = Bytes.concat(pathBytesWrap,pathBytes[i]);
		}
		pathBytesWrap = Bytes.concat(pathIdBytes,pathBytesWrap);
		byte[] header = MessageUtility.createMessageHeaderBytes(MessageUtility.ORAM_WRITEPATH,
				pathBytesWrap.length);
		ByteBuffer requestBuffer = ByteBuffer.wrap(Bytes.concat(header, pathBytesWrap));
		//send write path message
		byte[] responseBytes = sendAndGetMessage(requestBuffer, MessageUtility.ORAM_WRITEPATH);
		System.out.println("client WRITEPATH "+pathID+" successful!"+responseBytes[0]);
		
		pathIdBytes = null;
		pathBytes = null;
		pathBytesWrap = null;
		header = null;
		requestBuffer = null;
		responseBytes = null;
	}
	
	@Override
	public void close() {
		// TODO Auto-generated method stub
		try {
			mChannel.close();
			mThreadGroup.shutdown();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@SuppressWarnings("rawtypes")
	public byte[] sendAndGetMessage(ByteBuffer requestBuffer, int messageType) {
		byte[] responseBytes = null;
		//send request to server
		try {
			while (requestBuffer.remaining() > 0) {
				Future requestBufferRead = mChannel.write(requestBuffer);
				try {
					requestBufferRead.get();
				} catch (InterruptedException | ExecutionException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}

			// get response from server
			ByteBuffer typeAndSize = ByteBuffer.allocate(4 + 4);
			Future typeAndSizeRead = mChannel.read(typeAndSize);
			try {
				typeAndSizeRead.get();
			} catch (InterruptedException | ExecutionException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			typeAndSize.flip();
			int[] typeAndSizeInt = MessageUtility.parseTypeAndLength(typeAndSize);
			int type = typeAndSizeInt[0];//message type
			int size = typeAndSizeInt[1];//data size
			typeAndSize = null;

			ByteBuffer responseBuffer = ByteBuffer.allocate(size);
			while (responseBuffer.remaining() > 0) {
				Future responseBufferRead = mChannel.read(responseBuffer);
				responseBufferRead.get();
			}
			responseBuffer.flip();
			//check if it is current request corresponding response
			if (type == messageType) {
				responseBytes = new byte[size];
				responseBuffer.get(responseBytes);//read data into byte array
			} else {
				System.out.println("client get wrong when resieve response from server!");
			}
			responseBuffer = null;
		} catch (Exception e) {
			try {
				mChannel.close();
			} catch (IOException e1) {
			}
		}
		return responseBytes;
	}
	
	public static void main(String[] args) {
		int warmup = 5;
		int rloop = 1, wloop = 1;
		if (args.length < 1) {
			rloop = wloop = 10;
		} else if (args.length == 2) {
			rloop = Integer.parseInt(args[0]);
			wloop = Integer.parseInt(args[1]);
		} else {
			System.out.println("Invalid arguments!");
			System.exit(1);
		}
		// TODO Auto-generated method stub
		Client client = new Client();
		client.initServer();
		/*** 
		 * Warmup loops
		 ***/
		for(int i=0;i<warmup;i++){
			byte[] data = new byte[Configs.BLOCK_DATA_LEN];
			Arrays.fill(data, (byte)i);
			client.obliviousAccess(i, data, Operation.WRITE);
		}

		/* write loop */
		for(int i=0;i<wloop;i++){
			byte[] data = new byte[Configs.BLOCK_DATA_LEN];
			Arrays.fill(data, (byte)i);
			client.obliviousAccess(i, data, Operation.WRITE);
		}

		/* read loop */
		for(int i=0;i<rloop;i++){
			byte[] data = new byte[Configs.BLOCK_DATA_LEN];
			byte[] returndata = client.obliviousAccess(i, data, Operation.READ);
			for(int j = 0;j<Configs.BLOCK_DATA_LEN;j++){
				System.out.print(returndata[i]);
			}
			System.out.println();
		}
		client.close();
	}

}

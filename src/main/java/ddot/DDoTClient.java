package ddot;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollSocketChannel;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import org.xbill.DNS.*;
import org.xbill.DNS.Record;

public class DDoTClient {
	
	public static String ZONE = "";
	public static String SERVER_IP = "";
	public static int SERVER_PORT = 853;
	public static String TEST_TARGET = "example.com.";
	
	public static void main(String[] args) throws Exception {
 		
        OpenSsl.ensureAvailability();

        SslContext sslCtx = SslContextBuilder.forClient()
                .protocols("TLSv1.3", "TLSv1.2")
                .ciphers(Arrays.asList(
                        "TLS_AES_256_GCM_SHA384",
                        "TLS_AES_128_GCM_SHA256",
                        "TLS_CHACHA20_POLY1305_SHA256",
                        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"))
                .sslProvider(SslProvider.OPENSSL)
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();

        EventLoopGroup group = new NioEventLoopGroup();

        Bootstrap bootstrap = new Bootstrap()
                .group(group)
                .channelFactory(() -> {
                    if (Epoll.isAvailable()) {
                        return new EpollSocketChannel();
                    } else {
                        return new NioSocketChannel();
                    }
                })
                .handler(new DoTClientInitializer(sslCtx));

        Channel channel = bootstrap.connect(SERVER_IP, SERVER_PORT).sync().channel();

        //createTestCNAME(channel, ZONE, "test202203192307", randomString(6)+"."+TEST_TARGET);
        //deleteTestCNAME(channel, ZONE, "test202203192307");
        updateTestCNAME(channel, ZONE, "test202203192307", randomString(6)+"."+TEST_TARGET);
        
    }
	
	private static byte[] getMessageByte(Message message) {
		byte[] data = new byte[2];
        data[1] = (byte) (message.toWire().length & 0xFF);
        data[0] = (byte) ((message.toWire().length >> 8) & 0xFF);
        return data;
	}
	
	private static void createTestCNAME(Channel channel, String zonename, String ownername,
			String target) throws Exception {
		List<String> rdataList = new LinkedList<>();
        rdataList.add(target);
        
        Message message = getCreateRRSetMessage(zonename, ownername, "CNAME", 300, rdataList);
        byte[] data = getMessageByte(message);
        channel.write(Unpooled.wrappedBuffer(data));
        System.out.println(message);
        channel.writeAndFlush(Unpooled.wrappedBuffer(message.toWire())).sync();
	}
	
	private static void deleteTestCNAME(Channel channel, String zonename, String ownername) 
			throws Exception {
        
        Message message = getDeleteRRSetMessage(zonename, ownername, "CNAME");
        byte[] data = getMessageByte(message);
        channel.write(Unpooled.wrappedBuffer(data));
        System.out.println(message);
        channel.writeAndFlush(Unpooled.wrappedBuffer(message.toWire())).sync();
	}
	
	private static void updateTestCNAME(Channel channel, String zonename, String ownername,
			String target) throws Exception {
		List<String> rdataList = new LinkedList<>();
        rdataList.add(target);
        
        Message message = getUpdateEntireRRSetMessage(zonename, ownername, "CNAME", 300, rdataList);
        byte[] data = getMessageByte(message);
        channel.write(Unpooled.wrappedBuffer(data));
        System.out.println(message);
        channel.writeAndFlush(Unpooled.wrappedBuffer(message.toWire())).sync();
	}
	
	private static Message getCreateRRSetMessage(String zonename, String ownername, String rrType, 
			int ttl, List<String> rdataList) throws Exception {
        Name zone = Name.fromString(zonename);
        Update update = new Update(zone);
        update.absent(Name.fromString(ownername, zone), Type.value(rrType));
        org.xbill.DNS.RRset rrset = generateRRSet(zonename, rrType, ownername, 
        		Long.valueOf(ttl).longValue(), rdataList);
        update.add(rrset);
        return update;
    }
	
	private static Message getUpdateEntireRRSetMessage(String zonename, String ownername, String rrType, 
			int ttl, List<String> rdataList) throws Exception {
		Name zone = Name.fromString(zonename);
		Update update = new Update(zone);
		update.present(Name.fromString(ownername, zone), Type.value(rrType));
		org.xbill.DNS.RRset rrset = generateRRSet(zonename, rrType, ownername, 
				Long.valueOf(ttl).longValue(), rdataList);
		update.replace(rrset);
        return update;
    }
	
	private static Message getDeleteRRSetMessage(String zonename, String ownername, String rrType) 
			throws Exception {
        Name zone = Name.fromString(zonename);
        Update update = new Update(zone);
        update.present(Name.fromString(ownername, zone), Type.value(rrType));
        update.delete(Name.fromString(ownername, zone), Type.value(rrType));
        return update;
    }
	
	private static org.xbill.DNS.RRset generateRRSet(String zonename, String rrType,
            String ownername, long ttl, List<String> rdata) throws IOException {
        
        org.xbill.DNS.RRset rrset = new org.xbill.DNS.RRset();
        Name zone = Name.fromString(zonename);
        
        /*
         * the TXT record is special, if Record.fromString is used as space is not treated as expected
         * For example, if the rrset is "this  is  a test   ", then "this", "is", "a" "test" are added 
         */
        if (Type.value(rrType) == Type.TXT) {
            for(String answer: rdata) {
                TXTRecord record = null;
                if (answer.length() <= 255) {
                    record = new TXTRecord(Name.fromString(ownername, zone), DClass.IN, 
                            ttl, answer);
                } else {
                    // Long answer, e.g., Mail 2048bit DKIM
                    List<String> longAnswers = new LinkedList<String>();
                    for(int startOffset = 0; startOffset < answer.length();) {
                        String partialAnswer = answer.substring(startOffset, Math.min(startOffset+255, answer.length()));
                        startOffset += 255;
                        longAnswers.add(partialAnswer);
                    }
                    record = new TXTRecord(Name.fromString(ownername, zone), DClass.IN, 
                          ttl, longAnswers);
                }
                rrset.addRR(record);
            }
        } else if ((Type.value(rrType) == Type.A)
                || Type.value(rrType) == Type.AAAA
                || Type.value(rrType) == Type.SRV
                || Type.value(rrType) == Type.CAA) {
            for(String answer: rdata) {
                Record record = Record.fromString(Name.fromString(ownername, zone), Type.value(rrType), DClass.IN, 
                        ttl, answer, zone);
                rrset.addRR(record);
            }
        } else if ((Type.value(rrType) == Type.CNAME)
                || Type.value(rrType) == Type.PTR
                || (Type.value(rrType) == Type.MX)
                || (Type.value(rrType) == Type.NS)){
            for(String answer: rdata) {
                // If the rdata does not have trailling period, Saber is going to add zone after it
                Record record = Record.fromString(Name.fromString(ownername, zone), Type.value(rrType), DClass.IN, 
                        ttl, answer, zone);
                rrset.addRR(record);
            }
        }
        return rrset;
    }
	
	private static String randomString(int len) {
        int leftLimit = 97; // letter 'a'
        int rightLimit = 122; // letter 'z'
        Random random = new Random();
        StringBuilder buffer = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            int randomLimitedInt = leftLimit + (int) 
              (random.nextFloat() * (rightLimit - leftLimit + 1));
            buffer.append((char) randomLimitedInt);
        }
        String generatedString = buffer.toString();
        return generatedString;
    }
}

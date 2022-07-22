package cic.cs.unb.ca.jnetpcap;


import org.pcap4j.core.*;

import org.pcap4j.packet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.io.EOFException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.concurrent.TimeoutException;

public class PacketReader {

	private static final Logger logger = LoggerFactory.getLogger(PacketReader.class);
	private final IdGenerator  generator = new IdGenerator();
	private PcapHandle pcapHandle;
	
	private long firstPacketTimestamp;
	private long lastPacketTimestamp;
	private final Mode mode;
	
	public PacketReader(String filename, Mode mode) {
		super();
		this.config(filename);
		this.mode = mode;
	}

	public PacketReader(Mode mode){
		this.mode = mode;
	}
	
	private void config(String filename) {
		try {
			pcapHandle = Pcaps.openOffline(filename);
		} catch(Exception e) {
			System.out.println(e.getMessage());
			System.out.println(Arrays.toString(e.getStackTrace()));
		}
		this.firstPacketTimestamp = 0L;
		this.lastPacketTimestamp = 0L;
	}
	
	public BasicPacketInfo nextPacket() throws EOFException, NotOpenException, PcapNativeException, TimeoutException {
			 Packet packet = pcapHandle.getNextPacketEx();
			 return getIpInfo(packet);
	}

	public BasicPacketInfo getPacketInfo(Packet packet) {
		return getIpInfo(packet);
	}

	private BasicPacketInfo getIpInfo(Packet packet) {
		BasicPacketInfo packetInfo = new BasicPacketInfo(this.generator);
		//todo look at this link
		// basically, from the packet needs to be sort of reconstructed.
		// https://stackoverflow.com/questions/64507511/cannot-read-tcppacket-in-pcap4j
		// https://github.com/kaitoy/pcap4j/issues/67
		Timestamp timestamp = pcapHandle.getTimestamp();
		packetInfo.setTimeStamp(timestamp.getTime());
		if(this.firstPacketTimestamp == 0L)
			this.firstPacketTimestamp = timestamp.getTime();
		this.lastPacketTimestamp = timestamp.getTime();
		try {
			if (packet.contains(TcpPacket.class)) {
				TcpPacket tcpPacket = packet.get(TcpPacket.class);
				packetInfo.setTCPWindow(tcpPacket.getHeader().getWindowAsInt());
				packetInfo.setSrcPort(tcpPacket.getHeader().getSrcPort().valueAsInt());
				packetInfo.setDstPort(tcpPacket.getHeader().getDstPort().valueAsInt());
				packetInfo.setProtocol(6);
				packetInfo.setFlagACK(tcpPacket.getHeader().getAck());
				packetInfo.setFlagFIN(tcpPacket.getHeader().getFin());
				packetInfo.setFlagPSH(tcpPacket.getHeader().getPsh());
				packetInfo.setFlagRST(tcpPacket.getHeader().getRst());
				packetInfo.setFlagSYN(tcpPacket.getHeader().getSyn());
				packetInfo.setFlagURG(tcpPacket.getHeader().getUrg());
				packetInfo.setPayloadBytes(tcpPacket.getPayload().length());
				packetInfo.setHeaderBytes(tcpPacket.getHeader().length());

			} else if (packet.contains(UdpPacket.class)) {
				UdpPacket udpPacket = packet.get(UdpPacket.class);
				packetInfo.setSrcPort(udpPacket.getHeader().getSrcPort().valueAsInt());
				packetInfo.setDstPort(udpPacket.getHeader().getDstPort().valueAsInt());
				packetInfo.setPayloadBytes(udpPacket.getPayload().length());
				packetInfo.setHeaderBytes(udpPacket.getHeader().getLength());
				packetInfo.setProtocol(17);
			} else {
				return null;
			}

			if (packet.contains(IpV6Packet.class)) {
				IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
				packetInfo.setSrc(ipV6Packet.getHeader().getSrcAddr().getAddress());
				packetInfo.setDst(ipV6Packet.getHeader().getDstAddr().getAddress());
			} else if (packet.contains(IpV4Packet.class)) {
				IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
				packetInfo.setSrc(ipV4Packet.getHeader().getSrcAddr().getAddress());
				packetInfo.setDst(ipV4Packet.getHeader().getDstAddr().getAddress());
			}
		} catch (Exception e) {
			String errormsg = "";
			errormsg+=e.getMessage()+"\n";
			errormsg+="********************************************************************************"+"\n";
			errormsg+= Arrays.toString(packet.getRawData()) +"\n";
			logger.debug(errormsg);
			return null;
		}

		return packetInfo;
	}

	public long getFirstPacketTimestamp() {
		return firstPacketTimestamp;
	}

	public long getLastPacketTimestamp() {
		return lastPacketTimestamp;
	}

}

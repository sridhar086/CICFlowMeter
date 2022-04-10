package cic.cs.unb.ca.jnetpcap.worker;

import cic.cs.unb.ca.jnetpcap.BasicFlow;
import cic.cs.unb.ca.jnetpcap.FlowGenerator;
import cic.cs.unb.ca.jnetpcap.Mode;
import cic.cs.unb.ca.jnetpcap.PacketReader;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.util.List;

import static org.pcap4j.core.Pcaps.getDevByName;

public class TrafficFlowWorker extends SwingWorker<String,String> implements FlowGenListener{

	public static final Logger logger = LoggerFactory.getLogger(TrafficFlowWorker.class);
    public static final String PROPERTY_FLOW = "flow";
	private String device;
	private PacketReader packetReader;


    public TrafficFlowWorker(String device) {
		super();
		packetReader = new PacketReader(Mode.LIVE);
		this.device = device;
	}

	@Override
	protected String doInBackground() throws PcapNativeException, NotOpenException, InterruptedException {
		FlowGenerator   flowGen = new FlowGenerator(true,120000000L, 5000000L);
		flowGen.addFlowListener(this);
		int snaplen = 64 * 1024;//2048; // Truncate packet at this size
		int timeout = 60 * 1000; // In milliseconds
		StringBuilder errbuf = new StringBuilder();
		PcapNetworkInterface pcapNetworkInterface = Pcaps.getDevByName(device);
		PcapHandle pcap = pcapNetworkInterface.openLive(snaplen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);
		if (pcap == null) {
			logger.info("open {} fail -> {}",device,errbuf.toString());
			return String.format("open %s fail ->",device)+errbuf.toString();
		}

		PacketListener packetListener = new PacketListener() {

			/*
			 * BufferUnderflowException while decoding header
			 * that is because:
			 * 1.PCAP library is not multi-threaded
			 * 2.jNetPcap library is not multi-threaded
			 * 3.Care must be taken how packets or the data they referenced is used in multi-threaded environment
			 *
			 * typical rule:
			 * make new packet objects and perform deep copies of the data in PCAP buffers they point to
			 *
			 * but it seems not work
			 */
			@Override
			public void gotPacket(Packet packet) {
				flowGen.addPacket(packetReader.getPacketInfo(packet));

				if(isCancelled()) {
					try {
						pcap.breakLoop();
					} catch (NotOpenException e) {
						e.printStackTrace();
					}
					logger.debug("break Packet loop");
				}
			}
		};

        //FlowMgr.getInstance().setListenFlag(true);
        logger.info("Pcap is listening...");
        firePropertyChange("progress","open successfully","listening: "+device);
        pcap.loop(-1, packetListener);
		System.out.println(pcap.getStats().getNumPacketsCaptured());
		System.out.println(pcap.getStats().getNumPacketsReceived());
		String str;
		if(pcap.isOpen()) {
			return "listening: " + device + " finished";
		} else {
			return "stop listening: " + device;
		}
	}

	@Override
	protected void process(List<String> chunks) {
		super.process(chunks);
	}

	@Override
	protected void done() {
		super.done();
	}

	@Override
	public void onFlowGenerated(BasicFlow flow) {
        firePropertyChange(PROPERTY_FLOW,null,flow);
	}
}

package cic.cs.unb.ca.jnetpcap.worker;

import java.util.List;

import javax.swing.SwingWorker;

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class LoadPcapInterfaceWorker extends SwingWorker<List<PcapNetworkInterface>,String>{

	public static final Logger logger = LoggerFactory.getLogger(LoadPcapInterfaceWorker.class);
	
	public LoadPcapInterfaceWorker() {
		super();
	}

	@Override
	protected List<PcapNetworkInterface> doInBackground() throws Exception {
		
		StringBuilder errbuf = new StringBuilder();
		List<PcapNetworkInterface> ifs = Pcaps.findAllDevs();

		if(ifs.size() == 0) {
			logger.error("Error occured: " + errbuf.toString());
			throw new Exception(errbuf.toString());
		}
		return ifs;
	}

	@Override
	protected void done() {
		super.done();
	}
}

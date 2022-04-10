package cic.cs.unb.ca.jnetpcap;


import org.pcap4j.core.PcapNetworkInterface;

import java.util.ArrayList;
import java.util.List;

public class PcapIfWrapper {

    private PcapNetworkInterface pcapIf;
    private String prompt;

    public PcapIfWrapper(PcapNetworkInterface pcapIf) {
        this.pcapIf = pcapIf;
    }

    public PcapIfWrapper(String prompt) {
        this.prompt = prompt;
    }

    public static List<PcapIfWrapper> fromPcapIf(List<PcapNetworkInterface> ifs) {
        List<PcapIfWrapper> ifWrappers = new ArrayList<>();
        for(PcapNetworkInterface pcapif:ifs){
            ifWrappers.add(new PcapIfWrapper(pcapif));
        }
        return ifWrappers;
    }

    public String name(){
        return pcapIf.getName();
    }

    @Override
    public String toString() {
        if(pcapIf == null){
            return prompt;
        }else{
            return String.format("%s (%s)",pcapIf.getName(),pcapIf.getDescription());
        }
    }
}

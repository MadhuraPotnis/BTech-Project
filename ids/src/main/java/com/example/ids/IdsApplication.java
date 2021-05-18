package com.example.ids;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.util.List;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.NifSelector;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;

import com.example.ids.db.Login;
import com.example.ids.db.LoginRepository;

@SpringBootApplication
public class IdsApplication implements CommandLineRunner {

	@Autowired	
	LoginRepository loginRepository;

	public static void main(String[] args) {
		SpringApplication.run(IdsApplication.class, args);


	}

	@Override
	public void run(String... args) throws Exception {
		// For test purpose
		System.out.println("Good Afternoon");

		InetAddress addr = InetAddress.getByName("192.168.0.183");    
		PcapNetworkInterface device = Pcaps.getDevByAddress(addr);

		//		 PcapNetworkInterface device = null;

		//	        // Pcap4j comes with a convenient method for listing
		//	        // and choosing a network interface from the terminal
		//	        try {
		//	            // List the network devices available with a prompt
		//	            device = new NifSelector().selectNetworkInterface();
		//	        } catch (IOException e) {
		//	            e.printStackTrace();
		//	        }
		//		
		//        System.out.println("You chose: " + device);

		// Open the device and get a handle
		int snapshotLength = 65536; // in bytes   
		int readTimeout = 40; // in milliseconds                   
		final PcapHandle handle;
		handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);
		PcapDumper dumper = handle.dumpOpen("out.pcap");

		// Set a filter to only listen for tcp packets on port 80 (HTTP)
		String filter = "tcp port 80";
		handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

		// Create a listener that defines what to do with the received packets
		PacketListener listener = new PacketListener() {
			@Override
			public void gotPacket(Packet packet) {
				// Print packet information to screen
				System.out.println(handle.getTimestamp());
				System.out.println(packet);

				// Dump packets to file
				try {
					dumper.dump(packet, handle.getTimestamp());
				} catch (NotOpenException e) {
					e.printStackTrace();
				}
			}
		};

		// Tell the handle to loop using the listener we created
		try {
			int maxPackets = 2;
			handle.loop(maxPackets, listener);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		//		Packet pkt;
		//		try {
		//			pkt = handle.getNextPacket();
		//			System.out.println(pkt.getHeader().toString().substring(30, 39));
		//		} catch (NotOpenException e1) {
		//			// TODO Auto-generated catch block
		//			e1.printStackTrace();
		//		}

		// Cleanup when complete
		dumper.close();
		handle.close();

		parsePacket();
	}

	public void parsePacket() throws PcapNativeException {

		PcapHandle handle;

		handle = Pcaps.openOffline("out.pcap");

		for(int i = 0; i<2; i++)
		{
			Packet packet;
			try {
				packet = handle.getNextPacket();
				
				IpV4Packet ipv4_packet = packet.get(IpV4Packet.class);
				IpV4Packet.IpV4Header ipV4Packet_header = ipv4_packet.getHeader();
				
				System.out.println("Protocol:"+ipV4Packet_header.getProtocol());

			} catch (NotOpenException e) {
				e.printStackTrace();
			}

		}

	}
}

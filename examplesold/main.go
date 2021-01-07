/*
*
 */
package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/songgao/water"
)

func main() {
	// Create interface 1
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.Fatal(err)
	}

	// create interface 2
	ifce2, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Interface Name: %s\n", ifce.Name())
	log.Printf("Interface Name: %s\n", ifce2.Name())

	// Assign IP.
	cmd := exec.Command("/sbin/ifconfig", "utun2", "10.0.0.1", "10.0.0.2", "up")
	if err := cmd.Run(); err != nil {
		log.Fatalf("error %s", err)
	}

	cmd = exec.Command("/sbin/ifconfig", "utun3", "10.2.0.1", "10.2.0.2", "up")
	if err := cmd.Run(); err != nil {
		log.Fatalf("error %s", err)
	}

	packet := make([]byte, 2000)

	// Read and discard packets from utun3
	go func() {
		packet2 := make([]byte, 2000)
		for {
			_, err := ifce2.Read(packet2)
			if err != nil {
				log.Fatal(err)
			}
			writeResp(packet2, ifce)
		}
	}()

	// REad packets from utun2 and send packet over eth for routing.
	for {
		n, err := ifce.Read(packet)
		if err != nil {
			log.Fatal(err)
		}

		//	fmt.Println("Size read", n)
		createPkt(packet, n)
	}
}

func writeResp(pkt []byte, intf *water.Interface) {
	fmt.Println("Packet written to utun2xo")
	fmt.Println(gopacket.NewPacket(
		pkt,
		layers.LayerTypeIPv4,
		gopacket.Default,
	))

	packet := gopacket.NewPacket(pkt, layers.LayerTypeIPv4, gopacket.Default)
	ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

	ipl := &layers.IPv4{
		SrcIP:      net.IP{10, 0, 0, 2},
		DstIP:      net.IP{10, 0, 0, 1},
		Protocol:   ip.Protocol,
		Version:    ip.Version,
		IHL:        ip.IHL,
		TOS:        ip.TOS,
		Id:         ip.Id,
		Flags:      ip.Flags,
		FragOffset: ip.FragOffset,
		TTL:        ip.TTL,
		Options:    ip.Options,
		Padding:    ip.Padding,
	}
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	buffer := gopacket.NewSerializeBuffer()

	switch ip.NextLayerType() {
	case layers.LayerTypeUDP:
		trans := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if err := trans.SetNetworkLayerForChecksum(ipl); err != nil {
			log.Fatalf("error udp checksum %s", err)
		}
		if err := gopacket.SerializeLayers(buffer, opts, ipl, trans, gopacket.Payload(trans.Payload)); err != nil {
			log.Fatalf("Error Serializelayer %s", err)
		}

	case layers.LayerTypeTCP:
		trans := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if err := trans.SetNetworkLayerForChecksum(ipl); err != nil {
			log.Fatalf("error udp checksum %s", err)
		}
		if err := gopacket.SerializeLayers(buffer, opts, ipl, trans, gopacket.Payload(trans.Payload)); err != nil {
			log.Fatalf("Error Serializelayer %s", err)
		}

	case layers.LayerTypeICMPv4:
		trans := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		if err := gopacket.SerializeLayers(buffer, opts, ipl, trans, gopacket.Payload(trans.Payload)); err != nil {
			log.Fatalf("Error Serializelayer %s", err)
		}

	}

	if _, err := intf.Write(buffer.Bytes()); err != nil {
		log.Fatalf("Unable to write to utun3")
	}

}

func createPkt(pkt []byte, sz int) {
	packet := gopacket.NewPacket(pkt, layers.LayerTypeIPv4, gopacket.Default)

	ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	//	udp, _ := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	ethl := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0x80, 0xE6, 0x50, 0x18, 0x9B, 0xBA},
		//DstMAC: net.HardwareAddr{0x80, 0xE6, 0x50, 0x18, 0x9B, 0xBA},
		DstMAC:       net.HardwareAddr{0x18, 0x3D, 0xA2, 0x42, 0xE4, 0x4C}, // Dummy value.
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipl := &layers.IPv4{
		SrcIP: net.IP{10, 2, 0, 2},
		//SrcIP:      net.IP{192, 168, 1, 111},
		DstIP:      net.IP{192, 168, 1, 112},
		Protocol:   ip.Protocol,
		Version:    ip.Version,
		IHL:        ip.IHL,
		TOS:        ip.TOS,
		Id:         ip.Id,
		Flags:      ip.Flags,
		FragOffset: ip.FragOffset,
		TTL:        ip.TTL,
		Options:    ip.Options,
		Padding:    ip.Padding,
	}

	buffer := gopacket.NewSerializeBuffer()

	switch ip.NextLayerType() {
	case layers.LayerTypeUDP:
		trans := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if err := trans.SetNetworkLayerForChecksum(ipl); err != nil {
			log.Fatalf("error udp checksum %s", err)
		}
		if err := gopacket.SerializeLayers(buffer, opts, ethl, ipl, trans, gopacket.Payload(trans.Payload)); err != nil {
			log.Fatalf("Error Serializelayer %s", err)
		}

	case layers.LayerTypeTCP:
		trans := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if err := trans.SetNetworkLayerForChecksum(ipl); err != nil {
			log.Fatalf("error udp checksum %s", err)
		}

		trans.SetNetworkLayerForChecksum(ipl)
		if err := gopacket.SerializeLayers(buffer, opts, ethl, ipl, trans, gopacket.Payload(trans.Payload)); err != nil {
			log.Fatalf("Error Serializelayer %s", err)
		}

	case layers.LayerTypeICMPv4:
		trans := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		if err := gopacket.SerializeLayers(buffer, opts, ethl, ipl, trans, gopacket.Payload(trans.Payload)); err != nil {
			log.Fatalf("Error Serializelayer %s", err)
		}

	}

	fmt.Println("Packet written to eno")
	fmt.Println(gopacket.NewPacket(
		buffer.Bytes(),
		//pkt,
		layers.LayerTypeEthernet,
		gopacket.Default,
	))

	handle, err := pcap.OpenLive("en0", 1024, false, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		//if err := handle.WritePacketData(pkt); err != nil {
		log.Fatal("error send", err)
	}
}

func printPacket(pkt []byte) {
	// Decode a packet
	packet := gopacket.NewPacket(pkt, layers.LayerTypeIPv4, gopacket.Default)
	// Get the TCP layer from this packet
	if tcpLayer := packet.Layer(layers.LayerTypeIPv4); tcpLayer != nil {
		fmt.Println("This is a TCP packet!")
		// Get actual TCP data from this layer
		//tcp, _ := tcpLayer.(*layers.TCP)
		//fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
		ip, _ := tcpLayer.(*layers.IPv4)
		fmt.Println("IP", ip.SrcIP, ip.DstIP)
	}
}

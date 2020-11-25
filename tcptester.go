package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	ethl := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x80, 0xE6, 0x50, 0x18, 0x9B, 0xBA},
		DstMAC:       net.HardwareAddr{0xDD, 0xDD, 0xA2, 0x42, 0xE4, 0x4C}, // Dummy value.
		EthernetType: layers.EthernetTypeIPv4,
	}
	_ = ethl

	ipl := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 111},
		DstIP:    net.IP{192, 168, 1, 112},
		Protocol: layers.IPProtocolTCP,
	}

	trans := &layers.TCP{
		SrcPort: layers.TCPPort(6266),
		DstPort: layers.TCPPort(8811),
		SYN:     true,
		Seq:     1105024978,
		Window:  14600,
	}
	trans.SetNetworkLayerForChecksum(ipl)

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, opts, ipl, trans); err != nil {
		log.Fatalf("Error Serializelayer %s", err)
	}

	fmt.Println(gopacket.NewPacket(
		buffer.Bytes(),
		layers.LayerTypeEthernet,
		gopacket.Default,
	))

	handle, err := pcap.OpenLive("utun1", 1024, false, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Fatal("error send", err)
	}

}

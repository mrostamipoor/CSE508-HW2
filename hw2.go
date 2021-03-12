package main

import (
   	"flag"
   	"fmt"
	"os"
	"log"
	"time"
	"strings"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"encoding/hex"
	"strconv"
)
//creating a packet structure for printing it

type packetstrc struct {
     timesta string
	 srcMACAdress string
	 dstMACAdress string
	 ethtype string
	 packetlength int
	 srcIP string
	 dstIP string
	 protocoltype string
	 srcPort string
	 dstPort string
	 payload string
	 fin, syn, rst, psh, ack, urg, ece, cwr, ns bool
}	
 
var handle *pcap.Handle
var err error



func main() {
	// the bellowing lines give the inputs from CLI or find an active interface if the user doese not enter a file name or interface name
  //	
  
	loc, err := time.LoadLocation("America/New_York")
   	if err != nil {
			log.Fatal(err)
		}
   	 time.Local = loc
    founded := flag.String("s", "", "whatever that you want to find in payloads")
    interfaces := flag.String("i", "", "Network interface name")
    filename := flag.String("r", "", "Offline captured file's name")
    flag.Parse()
	
//if the user enter both of option, file name and interface name, encounters with an error

	if *interfaces != "" && *filename != ""  {
       fmt.Printf("You can only use one option online or offline capture!\n")
	   flag.PrintDefaults()
	    os.Exit(1)
    }
	
//find an active interface 
	if *interfaces == "" {	    
	  tmp:=livedevice()
		if len(tmp)==1 {
		 *interfaces=tmp[0]
		} else if len(tmp) == 0 {
		 fmt.Println("There is not an active interface on your system !! Please enable one interface and excute the program again :)")
		 log.Fatal(err)
		} else if len(tmp)>2 {
		fmt.Println("There is more than one active interface please choose one and give the program with -i option or disable them except your desired one :)")	
		log.Fatal(err)
		}
	}
// gives bpfFilter from CLI 
	bpfFilter:=flag.Args()

//The following code can be used to read in data from an interface
	if *interfaces != ""{
		var (
		 snaplen int32 = 65535
		 promisc bool = false
		 timeout time.Duration = -1 * time.Second
		)
		handle, err = pcap.OpenLive(*interfaces, snaplen, promisc, timeout)
		if err != nil {
			log.Fatal(err)
		}
		
	}

//The following code can be used to read in data from the pcap file
	
	if *filename != "" {
		handle, err = pcap.OpenOffline(*filename)
		if err != nil {
			log.Fatal(err)
		}
	}
	filter := strings.Join(bpfFilter, " ")
	err = handle.SetBPFFilter(filter)
		
	if err != nil {
		log.Fatal(err)
	}
//gives packets from the source

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		var newp packetstrc
		newp.timesta=packet.Metadata().Timestamp.String()
		newp.packetlength=	int(packet.Metadata().CaptureLength)
		
		if packet == nil {
			continue
		}
//set payload of the packet
		app := packet.ApplicationLayer()
		if  app == nil && *founded !=""  {
			continue
		}else if app != nil && *founded !="" {
//check whether the user wanted to find a string in payloads or not, if the packet does not contain the string then continue.
		   	if strings.Contains(string(app.Payload()), *founded) {
				newp.payload =hex.Dump(app.Payload())
				} else {
			    	continue
				}

			
		}
//if the user did not want to find a string in payloads, the payload would be added to the structure.
			if *founded =="" && app != nil{
				newp.payload =hex.Dump(app.Payload())
				}

			
		
//the following lines set ethernet layer attributes would be set, such as source MAC and destination MAC , ...
		if packet.LinkLayer != nil {
			ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethernetLayer != nil {
				ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
				newp.srcMACAdress =ethernetPacket.SrcMAC.String()
				newp.dstMACAdress  =ethernetPacket.DstMAC.String()
//I used the followint code to conver EthernetType to Hexadecimal
				tmpVar1:=fmt.Sprintf("%d",ethernetPacket.EthernetType)
	   			 i, err := strconv.Atoi(tmpVar1) //convert string to int
    			 if err != nil {
      			 fmt.Println(err)
       				 os.Exit(2)
				}
			 	newp.ethtype=fmt.Sprintf("0x%x", i)
				}
			}
		
		
//the following lines set network layer (IPv4 only) attributes, such as source and destination IP , ...
		if packet.NetworkLayer()!= nil  {
			if packet.Layer(layers.LayerTypeIPv4)!= nil {
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				ip, _ := ipLayer.(*layers.IPv4)
				newp.srcIP =ip.SrcIP.String()
				newp.dstIP =ip.DstIP.String()
				newp.protocoltype =ip.Protocol.String()
				}
		}
		
		
//In the following lines, tcp layer attributes would be set, such as source and destination port, and its flags , ...

		if packet.TransportLayer() != nil {
			var isTcp bool= false
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				isTcp=true
				tcp, _ := tcpLayer.(*layers.TCP)
				newp.srcPort=strings.Split(tcp.SrcPort.String(), "(")[0]
				newp.dstPort =strings.Split(tcp.DstPort.String(), "(")[0]
				newp.fin=tcp.FIN
				newp.syn=tcp.SYN
				newp.rst=tcp.RST
				newp.psh=tcp.PSH
				newp.ack=tcp.ACK
				newp.urg=tcp.URG
				newp.ece=tcp.ECE
				newp.cwr=tcp.CWR
				newp.ns=tcp.NS
			}
			
//the following lines udp layer attributes would be set, such as source and destination port, and its flags , ...
			if !isTcp {
			   if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					udp, _ := udpLayer .(*layers.UDP)
					newp.srcPort=strings.Split(udp.SrcPort.String(), "(")[0]
					newp.dstPort =strings.Split(udp.DstPort.String(), "(")[0]
				}
			}
		}
		
	    printPacket(newp)
		
						
	}
		

}
// a method for finding active interface in the state a user doese not enter an interface name or a captured file name
func livedevice() []string {
    devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	var live []string
	for _, i := range devs {
		devfind := false
		var addrs []string
		for _, addr := range i.Addresses {
			if addr.IP.IsLoopback() || addr.IP.IsMulticast() || addr.IP.IsUnspecified() || addr.IP.IsLinkLocalUnicast() {
				continue
			}
			devfind = true
			addrs = append(addrs, addr.IP.String())
		}
		if devfind {
			live = append(live, i.Name)
		}
	}
		return live
	

}
// we use this function for printing each packet based on packetstrc structure
func printPacket (newp packetstrc){
	   if newp.timesta !="" {
    		fmt.Printf(newp.timesta+" ")
		}
		if newp.srcMACAdress !="" {
			fmt.Printf(newp.srcMACAdress+"->")
		}
		if newp.dstMACAdress !="" {
			fmt.Printf(newp.dstMACAdress+" ")
		}
		if newp.ethtype !="" {
			fmt.Printf("type "+newp.ethtype+" ")
		}
		if newp.packetlength !=0 {
		   fmt.Printf("len ")
		   fmt.Printf("%d",newp.packetlength)
           fmt.Printf(" ")
		}
		if newp.srcIP  !="" {
			fmt.Printf(newp.srcIP)
		}
		if newp.srcPort !="" {
			fmt.Printf(":"+newp.srcPort+"->")
		}else if newp.srcIP !="" {
		    fmt.Printf("->")
		}
		if newp.dstIP !="" {
			fmt.Printf(newp.dstIP+"")
		}
		if newp.dstPort !="" {
			fmt.Printf(":"+newp.dstPort+" ")
		}else{
		    fmt.Printf(" ")
		}
		if newp.protocoltype !="" {
			var set bool=false
			if newp.protocoltype =="TCP" {
	    		fmt.Printf(newp.protocoltype+" ")
				set=true
			}
			if newp.protocoltype =="UDP" {
				fmt.Printf(newp.protocoltype+" ")
				set=true
			}
			if newp.protocoltype =="ICMPv4" {
				fmt.Printf(newp.protocoltype+" ")
				set=true
			}
			if !set{
	     		fmt.Printf("OTHERS ")
			}
		}
		if newp.fin==true{
			fmt.Printf("FIN ")
		}
		if newp.syn==true{
			fmt.Printf("SYN ")
		}
		if newp.rst==true{
		  fmt.Printf("RST ")
		}
		if newp.psh==true{
			fmt.Printf("PSH ")
		}
		if newp.ack==true{
     		fmt.Printf("ACK ")
		}
		if newp.urg==true{
	    	fmt.Printf("URG ")
		}
		if newp.ece==true{
		   fmt.Printf("ECE ")
		}
		if newp.cwr==true{
	    	fmt.Printf("CWR ")
		}
		if newp.ns==true{
		   fmt.Printf("NS ")
		}					
		fmt.Println()
	  if newp.payload !="" {
		 fmt.Printf(newp.payload+" ")
	   }
}

	 
	 
	 

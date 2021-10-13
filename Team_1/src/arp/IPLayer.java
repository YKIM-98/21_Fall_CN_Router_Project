package arp;

import arp.BaseLayer;
import java.util.ArrayList;


public class IPLayer implements BaseLayer{
    public int nUpperLayerCount = 0;
    public int nUnderLayerCount = 0;
    public ArrayList<BaseLayer> p_aUnderLayer = new ArrayList<BaseLayer>();
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();    
	public String pLayerName = null;
	private _IP_Header ip_header = new _IP_Header();
	
	
	// Layer 이름 설정
	public IPLayer(String pName){
		pLayerName = pName;
	}
	
	// ip header에 필요한 정보를 담아 송신
	public boolean Send(byte[] input, int length){
		
		return true;
	}
	
	// ip header 추가
	private byte[] ObjToByte21(_IP_Header ip_header, byte[] input, int length) { // 헤더 추가부분
		byte[] buf = new byte[length + 21];
		return buf;
	}
	
	// 수신된 패킷을 검사하여 버리거나 TCP Layer로 전달
	public synchronized boolean Receive(byte[] input) {

		return false;
	}

	@Override
	public String GetLayerName() {
		return pLayerName;
	}

	@Override
	public BaseLayer GetUnderLayer() {
		return null;
	}

	@Override
	public BaseLayer GetUpperLayer(int nindex) {
        if (nindex < 0 || nindex > nUnderLayerCount || nUnderLayerCount < 0)
            return null;
        return p_aUnderLayer.get(nindex);
	}

	@Override
	public void SetUnderLayer(BaseLayer pUnderLayer) {
        if (pUnderLayer == null)
            return;
        this.p_aUnderLayer.add(nUnderLayerCount++, pUnderLayer);
	}

	@Override
	public void SetUpperLayer(BaseLayer pUpperLayer) {
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
	}

	@Override
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);		
	}
	
    // src IP address set
    public void SetIpSrcAddress(byte[] srcAddress) {
        ip_header.ip_srcaddr.addr = srcAddress;
    }

    // dst IP address set
    public void SetIpDstAddress(byte[] dstAddress) {
        ip_header.ip_dstaddr.addr = dstAddress;

    }
	
    private class _IP_Header {
        byte is_checked; // ARP-0x06, data-0x08  	(index 0)
        byte ip_verlen; // ip version 				(1byte, index 1)
        byte ip_tos; // type of service 			(1byte, index 2)
        short ip_len; // total packet length 		(2byte, index 3~4)
        short ip_id; // datagram id					(2byte, index 5~6)
        short ip_fragoff;// fragment offset 		(2byte, index 7~8)
        byte ip_ttl; // time to live in gateway hops(1byte, index 9)
        byte ip_proto; // IP protocol 				(1byte, index 10, TCP-6, UDP-17)
        short ip_cksum; // header checksum 			(2byte, index 11~12)

        _IP_ADDR ip_srcaddr;// src IP address		(4byte, 13~16 index)
        _IP_ADDR ip_dstaddr;// dst IP address		(4byte, 17~20 index)
        
        private _IP_Header() {
            this.is_checked = 0x08;
            this.ip_verlen = 0x04; 	// IPV4 - 0x04
            this.ip_tos = 0x00;
            this.ip_len = 0;
            this.ip_id = 0;
            this.ip_fragoff = 0;
            this.ip_ttl = 0x00;
            this.ip_proto = 0x06;	// ARP - 0x06
            this.ip_cksum = 0;
            this.ip_srcaddr = new _IP_ADDR();
            this.ip_dstaddr = new _IP_ADDR();
        }

        // 헤더의 IP주소 자료구조
        private class _IP_ADDR {
            private byte[] addr = new byte[4];

            public _IP_ADDR() {
                this.addr[0] = 0x00;
                this.addr[1] = 0x00;
                this.addr[2] = 0x00;
                this.addr[3] = 0x00;
            }
        }
    }
}

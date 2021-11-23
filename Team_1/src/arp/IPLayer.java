package arp;

import arp.BaseLayer;

import java.util.ArrayList;

import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

public class IPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public int nUnderLayerCount = 0;
	public ArrayList<BaseLayer> p_aUnderLayer = new ArrayList<BaseLayer>();
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	public String pLayerName = null;
	private _IP_Header ip_header = new _IP_Header();
	private boolean isRouting = false;
	RoutingDlg dlg;

	public IPLayer(String pName) {
		pLayerName = pName;
	}

	private class _IP_Header {
		byte ip_verlen; // ip version (1byte)
		byte ip_tos; // type of service (1byte)
		short ip_len; // total packet length (2byte)
		short ip_id; // datagram id (2byte)
		short ip_fragoff;// fragment offset (2byte)
		byte ip_ttl; // time to live in gateway hops(1byte)
		byte ip_proto; // IP protocol (1byte)
		short ip_cksum; // header checksum (2byte)

		_IP_ADDR ip_srcaddr;// src IP address (4byte)
		_IP_ADDR ip_dstaddr;// dst IP address (4byte)

		private _IP_Header() {
			this.ip_verlen = 0x04; // IPV4 - 0x04
			this.ip_tos = 0x00;
			this.ip_len = 0;
			this.ip_id = 0;
			this.ip_fragoff = 0;
			this.ip_ttl = 0x00;
			this.ip_proto = 0x06;
			this.ip_cksum = 0;
			this.ip_srcaddr = new _IP_ADDR();
			this.ip_dstaddr = new _IP_ADDR();
		}

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

	public boolean Send(byte[] input, int length) {
		int resultLength = input.length;

		//확인할 것
		dlg = ((RoutingDlg) this.GetUpperLayer(0));
		NILayer ni = (NILayer) this.GetUnderLayer().GetUnderLayer().GetUnderLayer();
		
		if (isRouting) {// Routing
			this.GetUnderLayer(0).Send(input, length);

			isRouting = false;
			
		} else if (dlg.ARPorChat.equals("ARP")) {
			this.ip_header.ip_dstaddr.addr = new byte[4];
			this.ip_header.ip_srcaddr.addr = new byte[4];
			SetIpSrcAddress(ip2Byte(ni.getMyIpAddr()));
			
			String InputARPIP = dlg.getInputARPIP();
			byte[] dstAddressToByte = new byte[4];
			String[] byte_dst = InputARPIP.split("\\.");

			for (int i = 0; i < 4; i++) {
				dstAddressToByte[i] = (byte) Integer.parseInt(byte_dst[i], 16);
			}

			SetIpDstAddress(dstAddressToByte);
		}

		byte[] temp = ObjToByte20(this.ip_header, input, resultLength);

		return this.GetUnderLayer(1).Send(temp, resultLength + 20);
	}

	private byte[] ObjToByte20(_IP_Header ip_header, byte[] input, int length) { // 헤더 추가부분
		byte[] buf = new byte[length + 20];
		buf[0] = ip_header.ip_verlen;
		buf[1] = ip_header.ip_tos;
		buf[2] = (byte) (((length + 20) >> 8) & 0xFF);
		buf[3] = (byte) ((length + 20) & 0xFF);
		buf[4] = (byte) ((ip_header.ip_id >> 8) & 0xFF);
		buf[5] = (byte) (ip_header.ip_id & 0xFF);
		buf[6] = (byte) ((ip_header.ip_fragoff >> 8) & 0xFF);
		buf[7] = (byte) (ip_header.ip_fragoff & 0xFF);
		buf[8] = ip_header.ip_ttl;
		buf[9] = ip_header.ip_proto;
		buf[10] = (byte) ((ip_header.ip_cksum >> 8) & 0xFF);
		buf[11] = (byte) (ip_header.ip_cksum & 0xFF);
		System.arraycopy(ip_header.ip_srcaddr.addr, 0, buf, 12, 4);
		System.arraycopy(ip_header.ip_dstaddr.addr, 0, buf, 16, 4);
		System.arraycopy(input, 0, buf, 20, length);
		return buf;
	}

	public void routing(byte[] input, int length) {
		DefaultTableModel dtm_routing = ((RoutingDlg) this.GetUpperLayer(0)).dtm_Routing;
		byte[] dstIp = new byte[] { input[16], input[17], input[18], input[19] };

		for (int i = 0; i < dtm_routing.getRowCount(); ++i) {
			String subnetting_dst_addr = subnetting(ip2String(dstIp), (String) dtm_routing.getValueAt(i, 1));

			if ((String) dtm_routing.getValueAt(i, 0) == subnetting_dst_addr) {
				String flag = (String) dtm_routing.getValueAt(i, 3);
				RoutingDlg dlg = (RoutingDlg) this.GetUpperLayer(0);

				if (flag.equals("UH")) {
					isRouting = true;
					dlg.ipLayer[dlg.findInterface((int) dtm_routing.getValueAt(i, 4))].Send(input, length);
				}
			}
		}
	}

	public synchronized boolean Receive(byte[] input) {
		if (((input[6] == 0) && (input[7] == 0))) {
			byte[] temp = new byte[input.length - 28];
			System.arraycopy(input, 28, temp, 0, input.length - 28);
			return this.GetUpperLayer(0).Receive(removeIpHeader(temp));
		}
		// IP 타입 체크 ip_verlen : ip version : IPv4 ip_header.ip_tos : type of service
		// 0x00
		if (this.ip_header.ip_verlen != input[0] || this.ip_header.ip_tos != input[1]) {
			return false;
		}

		int packet_tot_len = ((input[2] << 8) & 0xFF00) + input[3] & 0xFF;
		byte[] my_ip_address = ((RoutingDlg) this.GetUpperLayer(0).GetUpperLayer(0).GetUpperLayer(0)).getMyIPAddress()
				.getAddress();
		for (int addr_index_count = 0; addr_index_count < 4; addr_index_count++) {
			if (my_ip_address[addr_index_count] != input[16 + addr_index_count]) {
				return this.GetUnderLayer(0).Send(input, packet_tot_len);
			}
		} // PARP

		if (input[9] == 0x06) {// IP Protocol이 0x06 TCP Layer 인지 판별
			return this.GetUpperLayer(0).Receive(removeIpHeader(input));
		}

		return false;
	}

	private byte[] removeIpHeader(byte[] input) {

		byte[] temp = new byte[input.length - 20];
		System.arraycopy(input, 20, temp, 0, temp.length);
		return temp;
	}

	@Override
	public String GetLayerName() {
		return pLayerName;
	}

	@Override
	public BaseLayer GetUnderLayer() {
		return null;
	}

	public BaseLayer GetUnderLayer(int nindex) {
		if (nindex < 0 || nindex > nUnderLayerCount || nUnderLayerCount < 0)
			return null;
		return p_aUnderLayer.get(nindex);
	}

	@Override
	public BaseLayer GetUpperLayer(int nindex) {
		if (nindex < 0 || nindex > nUnderLayerCount || nUnderLayerCount < 0)
			return null;
		return p_aUpperLayer.get(nindex);
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

	public void SetIpSrcAddress(byte[] srcAddress) {
		ip_header.ip_srcaddr.addr = srcAddress;
	}

	public void SetIpDstAddress(byte[] dstAddress) {
		ip_header.ip_dstaddr.addr = dstAddress;

	}

	public static String subnetting(String input, String mask) {
		byte[] inputByte = ip2Byte(input);
		byte[] maskByte = ip2Byte(mask);
		byte[] masking = new byte[4];
		for (int idx = 0; idx < 4; idx++) {
			masking[idx] = (byte) (inputByte[idx] & maskByte[idx]);
		}
		return ip2String(masking);
	}

	public static byte[] ip2Byte(String ip) {
		String[] ipBuf = ip.split("\\.");
		byte[] buf = new byte[4];
		for (int i = 0; i < 4; i++) {
			buf[i] = (byte) Integer.parseInt(ipBuf[i]);
		}
		return buf;
	}

	public static String ip2String(byte[] ip) {
		String ipAddress = "";
		for (byte b : ip) {
			ipAddress += Integer.toString(b & 0xFF) + ".";
		}
		return ipAddress.substring(0, ipAddress.length() - 1);
	}
}

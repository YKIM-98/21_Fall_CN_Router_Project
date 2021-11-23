package arp;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.ArrayList;

public class EthernetLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

	private class _ETHERNET_ADDR {
		private byte[] addr = new byte[6];

		public _ETHERNET_ADDR() {
			this.addr[0] = (byte) 0x00;
			this.addr[1] = (byte) 0x00;
			this.addr[2] = (byte) 0x00;
			this.addr[3] = (byte) 0x00;
			this.addr[4] = (byte) 0x00;
			this.addr[5] = (byte) 0x00;
		}
	}

	private class _ETHERNET_HEADER {
		_ETHERNET_ADDR enet_dstaddr;
		_ETHERNET_ADDR enet_srcaddr;
		byte[] enet_type;

		public _ETHERNET_HEADER() {
			this.enet_dstaddr = new _ETHERNET_ADDR();
			this.enet_srcaddr = new _ETHERNET_ADDR();
			this.enet_type = new byte[2];
		}
	}

	_ETHERNET_HEADER m_sHeader = new _ETHERNET_HEADER();

	public EthernetLayer(String pName) {
		this.pLayerName = pName;
	}

	public byte[] ObjToByte(_ETHERNET_HEADER Header, byte[] input, int length) {
		byte[] buf = new byte[length + 14];
		for (int i = 0; i < 6; i++) {
			buf[i] = Header.enet_dstaddr.addr[i];
			buf[i + 6] = Header.enet_srcaddr.addr[i];
		}
		buf[12] = Header.enet_type[0];
		buf[13] = Header.enet_type[1];
		for (int i = 0; i < length; i++)
			buf[14 + i] = input[i];

		return buf;
	}

	public boolean Send(byte[] input, int length) {
		int opCode = byte2ToInt(input[6], input[7]);
		RoutingDlg dlg = ((RoutingDlg) this.GetUpperLayer(0).GetUpperLayer(0).GetUpperLayer(0).GetUpperLayer(0));
		
				
		if (opCode == 1) {// ARP request
			SetEnetDstAddress(new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff});
			SetEnetSrcAddress(new byte[] { input[8], input[9], input[10], input[11], input[12], input[13] });
			SetEnetType(new byte[] { 0x08, 0x06 });
		} 
		
		else if (opCode == 2) {// ARP reply
			SetEnetDstAddress(new byte[] { input[18], input[19], input[20], input[21], input[22], input[23] });
			SetEnetSrcAddress(new byte[] { input[8], input[9], input[10], input[11], input[12], input[13] });
			SetEnetType(new byte[] { 0x08, 0x06 });
		}
		else if (opCode == 3){//routing
			SetEnetDstAddress(new byte[] { input[18], input[19], input[20], input[21], input[22], input[23] });
			SetEnetSrcAddress(new byte[] { input[8], input[9], input[10], input[11], input[12], input[13] });
			SetEnetType(new byte[] { 0x08, 0x00 });			
		}
		m_sHeader.enet_srcaddr.addr = dlg.myMacByte;
		
		byte[] bytes = ObjToByte(m_sHeader, input, length);
		this.GetUnderLayer().Send(bytes, length + 14);

		return true;
	}

	// not complete
	public synchronized boolean Receive(byte[] input) {
	      int frameType = byte2ToInt(input[12], input[13]);
	      if((isBroadcast(input) || isMyAddr(input)) && !isMyFrame(input)){
	            if (frameType == 0x0806) {//상위 ARP로 전송
	                input = RemoveEthernetHeader(input, input.length);
	                GetUpperLayer(1).Receive(input);
	                return true;
	             } else if (frameType == 0x0800) {//상위 IP로 전송
	                input = RemoveEthernetHeader(input, input.length);
	                GetUpperLayer(0).Receive(input);
	                return true;
	             }
	         }	      
	      return false;
	   }

	public byte[] RemoveEthernetHeader(byte[] input, int length) {
		byte[] cpyInput = new byte[length - 14];
		System.arraycopy(input, 14, cpyInput, 0, length - 14);
		input = cpyInput;
		return input;
	}

	public void SetEnetSrcAddress(byte[] srcAddress) {
		// TODO Auto-generated method stub
		m_sHeader.enet_srcaddr.addr = srcAddress;
	}

	public void SetEnetDstAddress(byte[] dstAddress) {
		// TODO Auto-generated method stub
		m_sHeader.enet_dstaddr.addr = dstAddress;
	}

	public void SetEnetType(byte[] enet_type) {
		m_sHeader.enet_type = enet_type;
	}

	@Override
	public void SetUnderLayer(BaseLayer pUnderLayer) {
		if (pUnderLayer == null)
			return;
		this.p_UnderLayer = pUnderLayer;
	}

	@Override
	public void SetUpperLayer(BaseLayer pUpperLayer) {
		if (pUpperLayer == null)
			return;
		this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
	}

	@Override
	public String GetLayerName() {
		// TODO Auto-generated method stub
		return pLayerName;
	}

	@Override
	public BaseLayer GetUnderLayer() {
		if (p_UnderLayer == null)
			return null;
		return p_UnderLayer;
	}

	@Override
	public BaseLayer GetUpperLayer(int nindex) {
		if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
			return null;
		return p_aUpperLayer.get(nindex);
	}

	@Override
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
		this.SetUpperLayer(pUULayer);
		pUULayer.SetUnderLayer(this);
	}
	
	private boolean isBroadcast(byte[] bytes) {//dstMac이 ffff~~~일 때
	      for (int i = 0; i < 6; i++)
	         if (bytes[i] != (byte) 0xff)
	            return false;
	      return true;
	   }
	
	private boolean isMyFrame(byte[] input) {
		for (int i = 0; i < 6; i++)
			if (m_sHeader.enet_srcaddr.addr[i] != input[6 + i])
				return false;
		return true;
	}
	
	private boolean isMyAddr(byte[] input) {
		for (int i = 0; i < 6; i++)
			if (m_sHeader.enet_srcaddr.addr[i] != input[i])
				return false;
		return true;
	}

	private int byte2ToInt(byte value1, byte value2) {
		return (int) ((value1 << 8) | (value2));
	}
}
